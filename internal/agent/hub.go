package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
	"github.com/KazuhaHub/infra-hub/internal/logx"
)

// Limits of what the agent asks of a hub.
const (
	// HTTPTimeout bounds a whole request, the transfer of a bundle included.
	HTTPTimeout = 60 * time.Second
	// MaxResponse bounds a bundle response (the contract allows a 64 MiB tarball plus the age overhead).
	MaxResponse = 70 << 20
	maxSmall    = 64 << 10
)

// responseLimit is MaxResponse (a variable so that a test can lower it).
var responseLimit int64 = MaxResponse

// Hub is one hub, reached only through its pinned key.
type Hub struct {
	URL    string
	client *http.Client
}

// NewHub builds the client of one hub: TLS 1.3, the pins decide trust, no proxy, no redirects.
func NewHub(rawURL string, pins []string) (*Hub, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig:       hubtrust.Verifier{Pins: pins, Host: u.Hostname()}.TLSConfig(),
		Proxy:                 nil,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: HTTPTimeout,
		ForceAttemptHTTP2:     true,
	}
	return &Hub{URL: rawURL, client: &http.Client{
		Transport:     tr,
		Timeout:       HTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// HubError is an answer that is not the one that was asked for: the status and the hub's error code.
type HubError struct {
	Status int
	Code   string
}

func (e *HubError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("hub answered %d %s", e.Status, e.Code)
	}
	return fmt.Sprintf("hub answered %d", e.Status)
}

// do sends a request and reads at most limit bytes of the answer (more is an error). The body is returned for any
// status; a status other than want becomes a HubError.
func (h *Hub) do(ctx context.Context, method, path string, hdr map[string]string, body []byte, limit int64, want ...int) (int, http.Header, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.URL+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "infra-agent")
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if int64(len(data)) > limit {
		return 0, nil, nil, fmt.Errorf("the response is larger than %d bytes", limit)
	}
	for _, w := range want {
		if resp.StatusCode == w {
			return resp.StatusCode, resp.Header, data, nil
		}
	}
	he := &HubError{Status: resp.StatusCode}
	var doc struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &doc) == nil {
		he.Code = doc.Error.Code
	}
	return resp.StatusCode, resp.Header, nil, he
}

// Health calls /v1/healthz.
func (h *Hub) Health(ctx context.Context) (string, error) {
	_, _, data, err := h.do(ctx, http.MethodGet, "/v1/healthz", nil, nil, maxSmall, http.StatusOK)
	if err != nil {
		return "", err
	}
	var doc struct {
		APIVersion string `json:"apiVersion"`
		Status     string `json:"status"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.APIVersion != "v1" {
		return "", errors.New("the hub's health answer is not apiVersion v1")
	}
	return doc.Status, nil
}

// Bundle fetches the encrypted bundle for host. etag is the commit last verified ("" for none). On a 200 the body is
// handed to consume as a stream capped at MaxResponse bytes: nothing buffers the whole ciphertext. A failure of the
// connection while consume reads is a hub error even if consume reports it as a bad bundle. notModified is true for a
// 304, which is only believable when an If-None-Match was sent and the hub's ETag names the commit that was sent.
func (h *Hub) Bundle(ctx context.Context, host, etag string, consume func(io.Reader) error) (notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL+"/v1/bundle/"+url.PathEscape(host), nil)
	if err != nil {
		return false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", `"`+etag+`"`)
	}
	req.Header.Set("User-Agent", "infra-agent")
	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		if etag == "" {
			return false, errors.New("hub answered 304 to a request without If-None-Match")
		}
		if got := strings.TrimPrefix(resp.Header.Get("ETag"), "W/"); got != `"`+etag+`"` {
			return false, errors.New("hub answered 304 with an ETag that is not the one sent")
		}
		return true, nil
	case http.StatusOK:
		body := &trackReader{r: &limitReader{r: resp.Body, left: responseLimit}}
		if err := consume(body); err != nil {
			if body.err != nil {
				return false, fmt.Errorf("read the response: %w", body.err)
			}
			return false, err
		}
		return false, nil
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxSmall))
	he := &HubError{Status: resp.StatusCode}
	var doc struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &doc) == nil {
		he.Code = doc.Error.Code
	}
	return false, he
}

// trackReader remembers a read error other than EOF.
type trackReader struct {
	r   io.Reader
	err error
}

func (t *trackReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

// limitReader fails (rather than stopping silently) when more than left bytes would be read.
type limitReader struct {
	r    io.Reader
	left int64
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		var one [1]byte
		if n, _ := l.r.Read(one[:]); n > 0 {
			return 0, fmt.Errorf("the response is larger than %d bytes", responseLimit)
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

// ReportBody is the "report" object of POST /v1/report.
type ReportBody struct {
	AppliedCommit string `json:"appliedCommit"`
	Result        string `json:"result"`
	Message       string `json:"message"`
	Time          string `json:"time"`
}

// Report asks for a challenge, answers it with the nonce decrypted by the host's age key and posts the report.
func (h *Hub) Report(ctx context.Context, host string, id *Identity, rep ReportBody) error {
	reqBody, _ := json.Marshal(map[string]string{"host": host})
	_, _, data, err := h.do(ctx, http.MethodPost, "/v1/challenge", jsonHdr, reqBody, maxSmall, http.StatusOK)
	if err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	var ch struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(data, &ch); err != nil || ch.Challenge == "" {
		return errors.New("challenge: the answer has no challenge")
	}
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(ch.Challenge)), id.ids...)
	if err != nil {
		return errors.New("challenge: cannot decrypt it with this host's age key")
	}
	nonce, err := io.ReadAll(io.LimitReader(r, 64))
	if err != nil || len(nonce) != 32 {
		return errors.New("challenge: the plaintext is not a 32 byte nonce")
	}
	nonceHex := hex.EncodeToString(nonce)
	logx.AddRecent(nonceHex)
	body, err := json.Marshal(map[string]any{"apiVersion": "v1", "host": host, "nonce": nonceHex, "report": rep})
	if err != nil {
		return err
	}
	if _, _, _, err := h.do(ctx, http.MethodPost, "/v1/report", jsonHdr, body, maxSmall, http.StatusOK); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	return nil
}

var jsonHdr = map[string]string{"Content-Type": "application/json"}
