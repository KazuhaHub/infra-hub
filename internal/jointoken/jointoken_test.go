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
	got, err := Decode("  " + tok + "\n")
	if err != nil || got.V != 1 || len(got.Pins) != 1 || got.Pins[0] != pin || len(got.Hubs) != 2 || got.Hubs[1] != "https://hub.example.org" {
		t.Errorf("decode: %+v %v", got, err)
	}
}

func enc(s string) string { return "ih1." + base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestDecodeRefusals(t *testing.T) {
	good := `"pins":["` + pin + `"],"hubs":["https://h.example.org:8443"]`
	cases := map[string]string{
		"empty":         "",
		"no prefix":     strings.TrimPrefix(enc(`{"v":1,`+good+`}`), "ih1."),
		"other prefix":  "ih2." + strings.TrimPrefix(enc(`{"v":1,`+good+`}`), "ih1."),
		"padded base64": "ih1." + base64.URLEncoding.EncodeToString([]byte(`{"v":1,`+good+`}x`)),
		"not base64":    "ih1.!!!",
		"not json":      enc("hello"),
		"version 2":     enc(`{"v":2,` + good + `}`),
		"no version":    enc(`{` + good + `}`),
		"unknown field": enc(`{"v":1,` + good + `,"secret":"x"}`),
		"trailing data": enc(`{"v":1,` + good + `}{}`),
		"no pins":       enc(`{"v":1,"pins":[],"hubs":["https://h:1"]}`),
		"bad pin":       enc(`{"v":1,"pins":["sha256//x"],"hubs":["https://h:1"]}`),
		"no hubs":       enc(`{"v":1,"pins":["` + pin + `"],"hubs":[]}`),
		"http hub":      enc(`{"v":1,"pins":["` + pin + `"],"hubs":["http://h:1"]}`),
		"hub with path": enc(`{"v":1,"pins":["` + pin + `"],"hubs":["https://h:1/x"]}`),
		"hub with user": enc(`{"v":1,"pins":["` + pin + `"],"hubs":["https://u:p@h:1"]}`),
		"hub no host":   enc(`{"v":1,"pins":["` + pin + `"],"hubs":["https://"]}`),
		"too long":      "ih1." + strings.Repeat("A", 20000),
	}
	for name, tok := range cases {
		if _, err := Decode(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
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
