package jointoken

import (
	"encoding/base64"
	"strings"
	"testing"
)

var pin = "sha256//" + strings.Repeat("A", 43) + "="

func TestEncodeFormatAndRoundTrip(t *testing.T) {
	tok, err := Encode([]string{pin}, []string{"https://192.0.2.10:8443", "https://hub.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	body, ok := strings.CutPrefix(tok, "ih1.")
	if !ok || strings.ContainsAny(body, "=+/ \n") {
		t.Fatalf("token %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"v":1,"pins":["` + "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" + `"],"hubs":["https://192.0.2.10:8443","https://hub.example.org"]}`
	if string(raw) != want {
		t.Errorf("json %s", raw)
	}
	got, err := Decode(tok)
	if err != nil || got.V != 1 || len(got.Pins) != 1 || got.Pins[0] != pin || len(got.Hubs) != 2 || got.Hubs[1] != "https://hub.example.org" {
		t.Errorf("decode: %+v %v", got, err)
	}
}

// padded is the padded base64url form, which has "=" when the length needs it.
func padded(s string) string { return "ih1." + base64.URLEncoding.EncodeToString([]byte(s)) }

func enc(s string) string { return "ih1." + base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestDecodeRefusals(t *testing.T) {
	good := `"pins":["` + pin + `"],"hubs":["https://h.example.org:8443"]`
	canon := enc(`{"v":1,` + good + `}`)
	hub := func(h string) string { return enc(`{"v":1,"pins":["` + pin + `"],"hubs":["` + h + `"]}`) }
	cases := map[string]string{
		"empty":              "",
		"no prefix":          strings.TrimPrefix(canon, "ih1."),
		"other prefix":       "ih2." + strings.TrimPrefix(canon, "ih1."),
		"unpadded plus =":    canon + "=",
		"newline":            canon + "\n",
		"carriage return":    canon + "\r\n",
		"leading space":      " " + canon,
		"inner newline":      canon[:20] + "\n" + canon[20:],
		"not base64":         "ih1.!!!",
		"not json":           enc("hello"),
		"version 2":          enc(`{"v":2,` + good + `}`),
		"no version":         enc(`{` + good + `}`),
		"unknown field":      enc(`{"v":1,` + good + `,"secret":"x"}`),
		"trailing data":      enc(`{"v":1,` + good + `}{}`),
		"trailing garbage":   enc(`{"v":1,` + good + `}x`),
		"duplicate key":      enc(`{"v":1,"v":1,` + good + `}`),
		"duplicate pins key": enc(`{"v":1,"pins":["` + pin + `"],` + good + `}`),
		"case variant":       enc(`{"V":1,` + good + `}`),
		"case variant 2":     enc(`{"v":1,"Pins":["` + pin + `"],"hubs":["https://h.example.org:8443"]}`),
		"spaces in json":     enc(`{"v":1, ` + good + `}`),
		"reordered":          enc(`{"hubs":["https://h.example.org:8443"],"pins":["` + pin + `"],"v":1}`),
		"no pins":            enc(`{"v":1,"pins":[],"hubs":["https://h:1"]}`),
		"bad pin":            enc(`{"v":1,"pins":["sha256//x"],"hubs":["https://h:1"]}`),
		"duplicate pin":      enc(`{"v":1,"pins":["` + pin + `","` + pin + `"],"hubs":["https://h:1"]}`),
		"no hubs":            enc(`{"v":1,"pins":["` + pin + `"],"hubs":[]}`),
		"duplicate hub":      enc(`{"v":1,"pins":["` + pin + `"],"hubs":["https://h:1","https://h:1"]}`),
		"http hub":           hub("http://h:1"),
		"hub with path":      hub("https://h:1/x"),
		"trailing slash":     hub("https://h:1/"),
		"hub with query":     hub("https://h:1?x=1"),
		"hub with user":      hub("https://u:p@h:1"),
		"hub no host":        hub("https://"),
		"empty port":         hub("https://h:"),
		"port 0":             hub("https://h:0"),
		"port 65536":         hub("https://h:65536"),
		"port text":          hub("https://h:abc"),
		"port leading zero":  hub("https://h:08443"),
		"upper-case host":    hub("https://Hub.Example.org:1"),
		"underscore host":    hub("https://a_b.example.org:1"),
		"wildcard host":      hub("https://*.example.org:1"),
		"zoned IPv6":         hub("https://[fe80::1%25eth0]:1"),
		"empty fragment":     hub("https://h:1#"),
		"fragment":           hub("https://h:1#x"),
		"empty query":        hub("https://h:1?"),
		"at sign":            hub("https://h:1@h2:2"),
		"space":              hub("https://h :1"),
		"too long":           "ih1." + strings.Repeat("A", 20000),
	}
	for name, tok := range cases {
		if _, err := Decode(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, h := range []string{"https://h", "https://h:1", "https://h:65535", "https://[2001:db8::1]:8443", "https://192.0.2.1:8443"} {
		if _, err := Decode(hub(h)); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
}

// A token that is otherwise exactly right is refused when it is in padded base64url.
func TestPaddedBase64IsRefused(t *testing.T) {
	for _, port := range []string{"1", "12", "123"} {
		canon := `{"v":1,"pins":["` + pin + `"],"hubs":["https://h.example.org:` + port + `"]}`
		p := padded(canon)
		if !strings.HasSuffix(p, "=") {
			continue
		}
		if _, err := Decode(enc(canon)); err != nil {
			t.Fatalf("the unpadded form of %s is refused: %v", canon, err)
		}
		if _, err := Decode(p); err == nil {
			t.Errorf("padded form accepted: %s", p)
		}
		return
	}
	t.Fatal("no padded example found")
}

func TestEncodeRefusals(t *testing.T) {
	if _, err := Encode(nil, []string{"https://h:1"}); err == nil {
		t.Error("no pins")
	}
	if _, err := Encode([]string{pin}, nil); err == nil {
		t.Error("no hubs")
	}
	if _, err := Encode([]string{pin}, []string{"hub.example.org:8443"}); err == nil {
		t.Error("hub without scheme")
	}
	if _, err := Encode([]string{"bad"}, []string{"https://h:1"}); err == nil {
		t.Error("bad pin")
	}
}
