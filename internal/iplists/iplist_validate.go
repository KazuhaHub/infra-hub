package iplists

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jmespath/go-jmespath"
)

// IP lists: validation and parsing. The same rules are implemented again in the client script, and
// testdata/iplists/validation-vectors.json is run through both so they cannot drift apart.

const (
	minBitsV4 = 8  // IPv4 prefixes shorter than this are refused (a /7 is a hole, not a CDN)
	minBitsV6 = 16 // likewise for IPv6
	// MaxEntries and MaxV4Space bound a whole list: a list of many wide prefixes that each pass the rules above is
	// still "everyone". MaxV4Space is a quarter of a /1 (about 12% of IPv4); real CDN lists are far below it.
	MaxEntries = 100000
	MaxV4Space = 1 << 29
	// MaxV6Space: total IPv6 addresses (a /32 is 2^96, so this is about 16 of them); 8192 /16s are far above it.
	MaxV6Space = 1 << 100
)

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// reserved: ranges that are never a CDN edge. An entry that overlaps any of them (is inside one, or contains one) is refused:
// this-network, private (RFC 1918), CGNAT, loopback, link-local, IETF and documentation ranges, benchmarking,
// multicast and reserved; for IPv6 unspecified, loopback, IPv4-mapped, NAT64, discard, documentation, ULA,
// link-local and multicast.
var reserved = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

// NormalizeCIDR parses one entry as a CIDR (address and prefix length, nothing else) and returns it with the host
// bits cleared, in canonical text form. It refuses 0.0.0.0/0, ::/0, IPv4 shorter than /8, IPv6 shorter than /16,
// reserved ranges and anything it cannot parse.
func NormalizeCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR", s)
	}
	if p.Addr().Zone() != "" || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q: zones and IPv4-mapped addresses are not accepted", s)
	}
	p = p.Masked()
	if p.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%q matches everything", s)
	}
	if p.Addr().Is4() && p.Bits() < minBitsV4 || p.Addr().Is6() && p.Bits() < minBitsV6 {
		return netip.Prefix{}, fmt.Errorf("%q is too short a prefix", s)
	}
	for _, r := range reserved {
		if r.Addr().Is4() == p.Addr().Is4() && r.Overlaps(p) {
			return netip.Prefix{}, fmt.Errorf("%q is in a private, loopback, link-local or reserved range", s)
		}
	}
	return p, nil
}

// NormalizeAll validates every entry and returns them canonical, without duplicates, in the order IPv4 before IPv6,
// then by address, then by prefix length. Any bad entry is an error (the whole set is refused, so a feed that
// goes wrong is never half-applied), and so is an empty result.
func NormalizeAll(entries []string) ([]string, error) { return normalizeEntries(entries, true) }

// normalizeEntries is NormalizeAll; capTotals false skips the total-coverage caps, which a downloaded provider list is
// not held to (the change guard looks at it) but anything that is served is.
func normalizeEntries(entries []string, capTotals bool) ([]string, error) {
	seen := map[netip.Prefix]bool{}
	var bad []string
	var ps []netip.Prefix
	for _, e := range entries {
		p, err := NormalizeCIDR(e)
		if err != nil {
			if len(bad) < 3 {
				bad = append(bad, err.Error())
			}
			continue
		}
		if !seen[p] {
			seen[p] = true
			ps = append(ps, p)
		}
	}
	if len(bad) > 0 {
		return nil, errors.New("invalid entries: " + strings.Join(bad, "; "))
	}
	if len(ps) == 0 {
		return nil, errors.New("no entries")
	}
	if len(ps) > MaxEntries {
		return nil, fmt.Errorf("more than %d entries", MaxEntries)
	}
	if !capTotals {
		return sortedStrings(ps), nil
	}
	var v4, v6 float64
	for _, p := range ps {
		if p.Addr().Is4() {
			v4 += weight(p)
		} else {
			v6 += weight(p)
		}
	}
	if v4 > MaxV4Space {
		return nil, fmt.Errorf("the IPv4 ranges cover more than %d addresses", MaxV4Space)
	}
	if v6 > MaxV6Space {
		return nil, errors.New("the IPv6 ranges cover more than 2^100 addresses")
	}
	return sortedStrings(ps), nil
}

func sortedStrings(ps []netip.Prefix) []string {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

// weight is the number of addresses of a prefix relative to its family's size (IPv4: addresses; IPv6: units of 2^-32 of a /0 are not needed, a
// float of the host-bit count is enough for comparisons).
func weight(p netip.Prefix) float64 {
	w := 1.0
	for i := p.Bits(); i < p.Addr().BitLen(); i++ {
		w *= 2
	}
	return w
}

// ListVersion is the version of a list: the SHA-256 (hex) of its canonical entries, one per line.
func ListVersion(cidrs []string) string {
	sum := sha256.Sum256([]byte(strings.Join(cidrs, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

// IPSource says where one provider's ranges come from. Providers are data: adding one is an inventory change.
type IPSource struct {
	URL string `json:"url"`
	// Format is "lines" (one CIDR per line, # comments) or "json".
	Format string `json:"format"`
	// Select is, for json, one or more JMESPath expressions that each yield an array of CIDR strings, e.g.
	// "result.ipv4_cidrs" or "prefixes[?service=='CLOUDFRONT'].ip_prefix". Every expression must match something.
	Select []string `json:"select,omitempty"`
	// MaxBytes caps the download (default DefaultMaxBytes).
	MaxBytes int `json:"maxBytes,omitempty"`
}

const (
	DefaultMaxBytes = 2 << 20
	LargestMaxBytes = 16 << 20
)

func (s IPSource) Validate() error {
	if !strings.HasPrefix(s.URL, "https://") {
		return errors.New("url must be https")
	}
	switch s.Format {
	case "lines":
		if len(s.Select) > 0 {
			return errors.New("select is only for format json")
		}
	case "json":
		if len(s.Select) == 0 {
			return errors.New("format json needs select")
		}
		for _, sel := range s.Select {
			if _, err := jmespath.Compile(sel); err != nil {
				return fmt.Errorf("select %q: %v", sel, err)
			}
		}
	default:
		return fmt.Errorf("format %q: must be lines or json", s.Format)
	}
	if s.MaxBytes < 0 || s.MaxBytes > LargestMaxBytes {
		return errors.New("max_bytes out of range")
	}
	return nil
}

func (s IPSource) maxBytes() int {
	if s.MaxBytes == 0 {
		return DefaultMaxBytes
	}
	return s.MaxBytes
}

// ParseSource turns a downloaded body into validated, normalised entries. Nothing is trusted: the body is parsed
// strictly, then every entry goes through NormalizeAll.
func ParseSource(src IPSource, body []byte) ([]string, error) {
	var raw []string
	switch src.Format {
	case "lines":
		if !isText(body) {
			return nil, errors.New("not a text list")
		}
		for _, line := range strings.Split(string(body), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			if line = strings.TrimSpace(line); line != "" {
				raw = append(raw, line)
			}
		}
	case "json":
		var doc any
		dec := json.NewDecoder(bytes.NewReader(body))
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("not JSON: %v", err)
		}
		if dec.More() {
			return nil, errors.New("not JSON: trailing data")
		}
		for _, sel := range src.Select {
			v, err := jmespath.Search(sel, doc)
			if err != nil {
				return nil, fmt.Errorf("select %q: %v", sel, err)
			}
			arr, ok := v.([]any)
			if !ok || len(arr) == 0 {
				return nil, fmt.Errorf("select %q matched no list of entries", sel)
			}
			for _, e := range arr {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("select %q: an entry is not a string", sel)
				}
				raw = append(raw, s)
			}
		}
	default:
		return nil, fmt.Errorf("unknown format %q", src.Format)
	}
	return normalizeEntries(raw, false)
}

func isText(b []byte) bool {
	for _, c := range b {
		if c == 0 || c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}
