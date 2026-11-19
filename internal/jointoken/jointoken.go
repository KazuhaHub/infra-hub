// Package jointoken is the one-line token that an agent install takes: `ih1.` followed by the unpadded base64url of
// the compact JSON {"v":1,"pins":["sha256//..."],"hubs":["https://host:port",...]}.
//
// A token holds no secret: only the public pins of the hub identity key and the hubs' URLs.
package jointoken

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

const (
	prefix = "ih1."
	// maxLen bounds what Decode will look at.
	maxLen = 16 << 10
)

// Token is the content of a join token.
type Token struct {
	V    int      `json:"v"`
	Pins []string `json:"pins"`
	Hubs []string `json:"hubs"`
}

// Encode returns the token for the pins and hub URLs.
func Encode(pins, hubs []string) (string, error) {
	t := Token{V: 1, Pins: pins, Hubs: hubs}
	if err := t.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode parses and validates a token. It is strict: the token must be exactly what Encode produces (unpadded
// base64url with no white space, compact JSON in canonical form), so duplicate keys, case variants of keys, trailing
// data and padding are all refused.
func Decode(s string) (Token, error) {
	var t Token
	body, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return t, errors.New("not a join token (it starts with ih1.)")
	}
	if len(s) > maxLen {
		return t, errors.New("join token is too long")
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return t, errors.New("join token is not unpadded base64url (no padding, spaces or line breaks)")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return t, errors.New("join token is not valid base64url")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return Token{}, fmt.Errorf("join token content: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Token{}, errors.New("join token content: trailing data")
	}
	if err := t.validate(); err != nil {
		return Token{}, err
	}
	canon, err := json.Marshal(t)
	if err != nil || !bytes.Equal(canon, raw) {
		return Token{}, errors.New("join token content is not in canonical form (duplicate or differently spelled keys?)")
	}
	return t, nil
}

func (t Token) validate() error {
	if t.V != 1 {
		return fmt.Errorf("join token version %d is not supported", t.V)
	}
	if len(t.Pins) == 0 {
		return errors.New("join token has no pin")
	}
	seen := map[string]bool{}
	for _, p := range t.Pins {
		if _, err := hubtrust.ParsePin(p); err != nil {
			return fmt.Errorf("join token pin: %w", err)
		}
		if seen[p] {
			return fmt.Errorf("join token pin %s twice", p)
		}
		seen[p] = true
	}
	if len(t.Hubs) == 0 {
		return errors.New("join token has no hub")
	}
	seen = map[string]bool{}
	for _, h := range t.Hubs {
		if err := ValidateHubURL(h); err != nil {
			return err
		}
		if seen[h] {
			return fmt.Errorf("join token hub %s twice", h)
		}
		seen[h] = true
	}
	return nil
}

// ValidateHubURL accepts only https://host or https://host:port (port 1-65535), with no user, path (not even a
// trailing slash), query or fragment.
func ValidateHubURL(s string) error {
	bad := fmt.Errorf("hub %q must look like https://host:port", s)
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.HasSuffix(u.Host, ":") {
		return bad
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return fmt.Errorf("hub %q has a bad port (1-65535)", s)
		}
	}
	return nil
}
