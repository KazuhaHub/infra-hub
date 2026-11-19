package httpsapi

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	nonceBytes = 32
	// ChallengeTTL is how long a nonce can be answered.
	ChallengeTTL = 5 * time.Minute
	// maxNonces bounds the memory held for outstanding nonces; maxNoncesPerHost keeps one host from filling it.
	maxNonces        = 8192
	maxNoncesPerHost = 64
)

type nonceEntry struct {
	host    string
	expires time.Time
}

// nonceStore holds the outstanding nonces in memory. A nonce is single use: consume removes it.
type nonceStore struct {
	mu      sync.Mutex
	entries map[[nonceBytes]byte]nonceEntry
	perHost map[string][][nonceBytes]byte // oldest first
}

func newNonceStore() *nonceStore {
	return &nonceStore{entries: map[[nonceBytes]byte]nonceEntry{}, perHost: map[string][][nonceBytes]byte{}}
}

var errStoreFull = errors.New("too many outstanding challenges")

// issue stores a fresh nonce for host. A host that already has maxNoncesPerHost outstanding loses its oldest one.
func (s *nonceStore) issue(host string, nonce [nonceBytes]byte, now time.Time) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= maxNonces {
		s.purgeLocked(now)
		if len(s.entries) >= maxNonces {
			return time.Time{}, errStoreFull
		}
	}
	list := s.perHost[host]
	for len(list) >= maxNoncesPerHost {
		delete(s.entries, list[0])
		list = list[1:]
	}
	exp := now.Add(ChallengeTTL)
	s.entries[nonce] = nonceEntry{host: host, expires: exp}
	s.perHost[host] = append(list, nonce)
	return exp, nil
}

// consume uses the nonce: it succeeds once, for the host it was issued to, before it expires. A nonce presented by
// another host is left alone (its holder may still answer); an expired one is dropped.
func (s *nonceStore) consume(host string, nonce [nonceBytes]byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[nonce]
	if !ok || e.host != host {
		return false
	}
	s.removeLocked(host, nonce)
	return now.Before(e.expires)
}

func (s *nonceStore) removeLocked(host string, nonce [nonceBytes]byte) {
	delete(s.entries, nonce)
	list := s.perHost[host]
	for i, n := range list {
		if n == nonce {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.perHost, host)
	} else {
		s.perHost[host] = list
	}
}

func (s *nonceStore) purgeLocked(now time.Time) {
	for n, e := range s.entries {
		if !now.Before(e.expires) {
			s.removeLocked(e.host, n)
		}
	}
}

func (s *nonceStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// newNonce draws a random nonce from r.
func newNonce(r io.Reader) (n [nonceBytes]byte, err error) {
	_, err = io.ReadFull(r, n[:])
	return
}

func nonceHex(n [nonceBytes]byte) string { return hex.EncodeToString(n[:]) }

func parseNonce(s string) (n [nonceBytes]byte, ok bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != nonceBytes {
		return n, false
	}
	copy(n[:], b)
	return n, true
}

// encryptNonce is the age-armored ciphertext of the nonce for the host's registered key.
func encryptNonce(to age.Recipient, nonce [nonceBytes]byte) (string, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, to)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// remoteKey is the rate-limit key of a peer: the IP address, with IPv6 reduced to its /64 (one subscriber).
func remoteKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}
