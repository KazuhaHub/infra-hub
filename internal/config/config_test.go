package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

func TestConfig(t *testing.T) {
	_, k1 := testutil.NewKey(t)
	_, k2 := testutil.NewKey(t)
	good := func(extra string) string {
		return `{"listen":"192.0.2.10:11882","repo":"/var/lib/infra-hub/infra.git","upstream":"git@git.example.org:example/infra.git",
"host_key":"/var/lib/infra-hub/hk","clients":{"a":"` + k1 + `","b":"` + k2 + `"}` + extra + `}`
	}
	if c, err := ParseConfig([]byte(good(""))); err != nil || c.MirrorIntervalSeconds != 60 || c.State != "/var/lib/infra-hub/state.json" {
		t.Fatalf("good config: %+v %v", c, err)
	}
	bad := map[string]string{
		"unknown field":   good(`,"extra":1`),
		"relative repo":   strings.Replace(good(""), "/var/lib/infra-hub/infra.git", "infra.git", 1),
		"wrong repo name": strings.Replace(good(""), "infra.git", "other.git", 1),
		"no port":         strings.Replace(good(""), "192.0.2.10:11882", "192.0.2.10", 1),
		"same key twice":  strings.Replace(good(""), k2, k1, 1),
		"junk key":        strings.Replace(good(""), k2, "ssh-ed25519 nope", 1),
		"no clients":      `{"listen":"1.2.3.4:1","repo":"/x/infra.git","upstream":"u","host_key":"/k","clients":{}}`,
		"option upstream": strings.Replace(good(""), "git@git.example.org:example/infra.git", "--upload-pack=x", 1),
	}
	for name, cfg := range bad {
		if _, err := ParseConfig([]byte(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// any listen address is fine: the network is configuration
	if _, err := ParseConfig([]byte(strings.Replace(good(""), "192.0.2.10", "0.0.0.0", 1))); err != nil {
		t.Errorf("non-private listen address rejected: %v", err)
	}
}

func TestConfigCerts(t *testing.T) {
	base := `{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","host_key":"/x/k","clients":{"h":"%s"},"certs":%s}`
	_, key := testutil.NewKey(t)
	parse := func(certs string) (Config, error) {
		return ParseConfig([]byte(strings.Replace(strings.Replace(base, "%s", key, 1), "%s", certs, 1)))
	}
	good := func(certs string) error { _, err := parse(certs); return err }
	if err := good(`{"a.example.org":"h"}`); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"a.example.org":"nobody"}`, `{"*.example.org":"h"}`, `{"a/../b.org":"h"}`, `{"single":"h"}`, `{"A.example.org":"h"}`} {
		if good(bad) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	c, _ := parse(`{}`)
	if c.AcmeDirectory != certs.LetsEncryptProduction || c.CertDir != "/x/certs" {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestConfigIPLists(t *testing.T) {
	_, key := testutil.NewKey(t)
	parse := func(extra string) (Config, error) {
		return ParseConfig([]byte(fmt.Sprintf(`{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","host_key":"/x/k","clients":{"h":%q}%s}`, key, extra)))
	}
	good := `,"ip_sources":{"cf":{"url":"https://x/y","format":"lines"}},"ip_lists":{"cloudflare":{"providers":["cf"],"manual":["203.0.114.5/24"],"hosts":["h"]}}`
	c, err := parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if c.IPLists["cloudflare"].Manual[0] != "203.0.114.0/24" || c.IPListDir != "/x/iplists" {
		t.Fatalf("%+v", c)
	}
	for name, extra := range map[string]string{
		"unknown provider":   `,"ip_lists":{"a":{"providers":["nope"],"hosts":["h"]}}`,
		"unknown host":       strings.Replace(good, `"hosts":["h"]`, `"hosts":["z"]`, 1),
		"private manual":     strings.Replace(good, "203.0.114.5/24", "192.168.0.0/16", 1),
		"everything manual":  strings.Replace(good, "203.0.114.5/24", "0.0.0.0/0", 1),
		"empty list":         `,"ip_lists":{"a":{"hosts":["h"]}}`,
		"http source":        strings.Replace(good, "https://x/y", "http://x/y", 1),
		"odd list name":      strings.Replace(good, `"cloudflare"`, `"../x"`, 1),
		"odd provider name":  strings.Replace(strings.Replace(good, `"cf":`, `"C F":`, 1), `["cf"]`, `["C F"]`, 1),
		"relative directory": `,"iplist_dir":"rel"`,
	} {
		if _, err := parse(extra); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConfigRejectsADuplicateProvider(t *testing.T) {
	_, key := testutil.NewKey(t)
	cfg := fmt.Sprintf(`{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","host_key":"/x/k","clients":{"h":%q},
		"ip_sources":{"cf":{"url":"https://x/y","format":"lines"}},"ip_lists":{"a":{"providers":["cf","cf"],"hosts":["h"]}}}`, key)
	if _, err := ParseConfig([]byte(cfg)); err == nil {
		t.Fatal("accepted")
	}
}
