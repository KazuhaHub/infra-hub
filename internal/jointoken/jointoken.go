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
	"net/url"
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

// Decode parses and validates a token.
func Decode(s string) (Token, error) {
	var t Token
	s = strings.TrimSpace(s)
	body, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return t, errors.New("not a join token (it starts with ih1.)")
	}
	if len(s) > maxLen {
		return t, errors.New("join token is too long")
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
	if dec.More() {
		return Token{}, errors.New("join token content: trailing data")
	}
	if err := t.validate(); err != nil {
		return Token{}, err
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
	for _, p := range t.Pins {
		if _, err := hubtrust.ParsePin(p); err != nil {
			return fmt.Errorf("join token pin: %w", err)
		}
	}
	if len(t.Hubs) == 0 {
		return errors.New("join token has no hub")
	}
	for _, h := range t.Hubs {
		if err := ValidateHubURL(h); err != nil {
			return err
		}
	}
	return nil
}

// ValidateHubURL accepts only https://host or https://host:port, with no user, path, query or fragment.
func ValidateHubURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("hub %q must look like https://host:port", s)
	}
	if p := u.Port(); p != "" && p == "0" {
		return fmt.Errorf("hub %q has port 0", s)
	}
	return nil
}
