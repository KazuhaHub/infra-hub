package hubca

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

// RevocationAPIVersion is the apiVersion of a revocation list document.
const RevocationAPIVersion = "v1"

// maxRevocations bounds a list so a damaged file cannot make the hub allocate without limit.
const maxRevocations = 10000

// Revocation is one revoked hub certificate.
type Revocation struct {
	// Serial is the certificate's serial number in lower-case hex, without leading zeros.
	Serial string `json:"serial"`
	// Time is when it was revoked (RFC 3339 UTC).
	Time string `json:"time"`
	// Reason is free text for people.
	Reason string `json:"reason,omitempty"`
}

// RevocationList is the revocation file: a plain JSON document. It is distributed later inside the signed bundle,
// so the file itself carries no signature; its integrity is the bundle's. Only parsing exists so far; nothing
// enforces the list yet (see docs/ca.md).
type RevocationList struct {
	APIVersion string       `json:"apiVersion"`
	Revoked    []Revocation `json:"revoked"` // sorted by serial
}

// ParseRevocationList reads and validates a document.
func ParseRevocationList(data []byte) (*RevocationList, error) {
	var l RevocationList
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("revocation list: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("revocation list: trailing data")
	}
	if l.APIVersion != RevocationAPIVersion {
		return nil, fmt.Errorf("revocation list: apiVersion %q is not %q", l.APIVersion, RevocationAPIVersion)
	}
	if len(l.Revoked) > maxRevocations {
		return nil, errors.New("revocation list: too many entries")
	}
	seen := map[string]bool{}
	for i := range l.Revoked {
		r := &l.Revoked[i]
		n, ok := new(big.Int).SetString(r.Serial, 16)
		if !ok || n.Sign() <= 0 || r.Serial != strings.ToLower(r.Serial) || r.Serial != n.Text(16) {
			return nil, fmt.Errorf("revocation list: serial %q is not canonical lower-case hex", r.Serial)
		}
		if seen[r.Serial] {
			return nil, fmt.Errorf("revocation list: serial %s twice", r.Serial)
		}
		seen[r.Serial] = true
		if _, err := time.Parse(time.RFC3339, r.Time); err != nil {
			return nil, fmt.Errorf("revocation list: serial %s: time: %w", r.Serial, err)
		}
		if i > 0 && l.Revoked[i-1].Serial >= r.Serial {
			return nil, errors.New("revocation list: entries must be sorted by serial")
		}
	}
	return &l, nil
}

// Contains reports whether the certificate serial is revoked.
func (l *RevocationList) Contains(serial *big.Int) bool {
	if l == nil || serial == nil {
		return false
	}
	s := serial.Text(16)
	for _, r := range l.Revoked {
		if r.Serial == s {
			return true
		}
	}
	return false
}
