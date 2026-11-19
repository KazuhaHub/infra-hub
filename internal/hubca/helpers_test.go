package hubca

import (
	"encoding/pem"
	"net/url"
)

func parseURL(s string) (*url.URL, error) { return url.Parse(s) }

func pemEncodeCSR(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
