package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/KazuhaHub/infra-hub/internal/certs"
)

// sshKeyLine is a public key line as old configs carry it; it is ignored now, never parsed.
const sshKeyLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dB4w4rTZe"

// httpsBlock is the listener every config needs now.
const httpsBlock = `"httpsAddresses":["192.0.2.1"],"https":{"listen":"192.0.2.1:8443","key":"/x/hub.key"}`

// capture runs f with the default logger writing to a buffer and returns what was logged.
func capture(t *testing.T, f func()) string {
	t.Helper()
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	f()
	return logs.String()
}

func TestConfig(t *testing.T) {
	good := func(extra string) string {
		return `{"repo":"/var/lib/infra-hub/infra.git","upstream":"git@git.example.org:example/infra.git",` + httpsBlock + `,"clients":{"a":{},"b":{}}` + extra + `}`
	}
	if c, err := ParseConfig([]byte(good(""))); err != nil || c.MirrorIntervalSeconds != 60 || c.State != "/var/lib/infra-hub/state.json" {
		t.Fatalf("good config: %+v %v", c, err)
	}
	bad := map[string]string{
		"unknown field":   good(`,"extra":1`),
		"relative repo":   strings.Replace(good(""), "/var/lib/infra-hub/infra.git", "infra.git", 1),
		"wrong repo name": strings.Replace(good(""), "infra.git", "other.git", 1),
		"option upstream": strings.Replace(good(""), "git@git.example.org:example/infra.git", "--upload-pack=x", 1),
	}
	for name, cfg := range bad {
		if _, err := ParseConfig([]byte(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConfigCerts(t *testing.T) {
	base := `{"repo":"/x/infra.git","upstream":"u",` + httpsBlock + `,"clients":{"h":{}},"certs":%s}`
	parse := func(certs string) (Config, error) {
		return ParseConfig([]byte(strings.Replace(base, "%s", certs, 1)))
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
	parse := func(extra string) (Config, error) {
		return ParseConfig([]byte(`{"repo":"/x/infra.git","upstream":"u",` + httpsBlock + `,"clients":{"h":{}}` + extra + `}`))
	}
	good := `,"ipSources":{"cf":{"url":"https://x/y","format":"lines"}},"ipLists":{"cloudflare":{"providers":["cf"],"manual":["203.0.114.5/24"]}}`
	c, err := parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if c.IPLists["cloudflare"].Manual[0] != "203.0.114.0/24" || c.IPListDir != "/x/iplists" {
		t.Fatalf("%+v", c)
	}
	for name, extra := range map[string]string{
		"unknown provider":   `,"ipLists":{"a":{"providers":["nope"]}}`,
		"private manual":     strings.Replace(good, "203.0.114.5/24", "192.168.0.0/16", 1),
		"everything manual":  strings.Replace(good, "203.0.114.5/24", "0.0.0.0/0", 1),
		"empty list":         `,"ipLists":{"a":{}}`,
		"http source":        strings.Replace(good, "https://x/y", "http://x/y", 1),
		"odd list name":      strings.Replace(good, `"cloudflare"`, `"../x"`, 1),
		"odd provider name":  strings.Replace(strings.Replace(good, `"cf":`, `"C F":`, 1), `["cf"]`, `["C F"]`, 1),
		"relative directory": `,"ipListDir":"rel"`,
		"duplicate provider": `,"ipSources":{"cf":{"url":"https://x/y","format":"lines"}},"ipLists":{"a":{"providers":["cf","cf"]}}`,
	} {
		if _, err := parse(extra); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConfigClientsAndHTTPS(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	pub := id.Recipient().String()
	parse := func(clients, extra string) (Config, error) {
		return ParseConfig([]byte(`{"repo":"/x/infra.git","upstream":"u","clients":` + clients + extra + `}`))
	}
	goodHTTPS := `,"httpsAddresses":["192.0.2.10","hub.example.org"],"https":{"listen":"192.0.2.10:8443","key":"/etc/infra-hub/hub.key"}`
	c, err := parse(fmt.Sprintf(`{"a":{"agePublicKey":%q},"b":{}}`, pub), goodHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	if r := c.AgeRecipients(); len(r) != 1 || r["a"] == nil {
		t.Errorf("recipients: %v", r)
	}
	for name, clients := range map[string]string{
		"bad age key":   `{"a":{"agePublicKey":"age1nope"}}`,
		"unknown field": `{"a":{"token":"x"}}`,
		"number":        `{"a":5}`,
		"same age key":  fmt.Sprintf(`{"a":{"agePublicKey":%q},"b":{"agePublicKey":%q}}`, pub, pub),
	} {
		if _, err := parse(clients, goodHTTPS); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	clients := `{"a":{}}`
	c, err = parse(clients, goodHTTPS)
	if err != nil || c.HTTPS.Listen != "192.0.2.10:8443" || c.HTTPS.Key != "/etc/infra-hub/hub.key" || len(c.HTTPSAddresses) != 2 {
		t.Fatalf("good https: %+v %v", c.HTTPS, err)
	}
	for name, extra := range map[string]string{
		"no https":      ``,
		"wildcard name": strings.Replace(goodHTTPS, "hub.example.org", "*.example.org", 1),
		"upper case":    strings.Replace(goodHTTPS, "hub.example.org", "Hub.Example.org", 1),
		"duplicate":     strings.Replace(goodHTTPS, "hub.example.org", "192.0.2.10", 1),
		"zoned":         strings.Replace(goodHTTPS, "hub.example.org", "fe80::1%eth0", 1),
		"no port":       strings.Replace(goodHTTPS, "192.0.2.10:8443", "192.0.2.10", 1),
		"port 0":        strings.Replace(goodHTTPS, "192.0.2.10:8443", "192.0.2.10:0", 1),
		"no key":        strings.Replace(goodHTTPS, `,"key":"/etc/infra-hub/hub.key"`, "", 1),
		"relative key":  strings.Replace(goodHTTPS, "/etc/infra-hub/hub.key", "hub.key", 1),
		"no addresses":  `,"https":{"listen":"192.0.2.10:8443","key":"/etc/infra-hub/hub.key"}`,
		"key no listen": `,"https":{"key":"/etc/infra-hub/hub.key"}`,
		"unknown https": strings.Replace(goodHTTPS, `"listen"`, `"x":1,"listen"`, 1),
	} {
		if _, err := parse(clients, extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The old CA fields are ignored with a warning that names the new one; the rest of the config still applies.
	for _, old := range []string{`"caCert":"/etc/infra-hub/ca.crt"`, `"cert":"/etc/infra-hub/hub.crt"`} {
		var c Config
		out := capture(t, func() {
			c, err = parse(clients, `,"httpsAddresses":["192.0.2.10"],"https":{"listen":"192.0.2.10:8443","key":"/k",`+old+`}`)
		})
		if err != nil || c.HTTPS.Key != "/k" || c.HTTPS.Listen != "192.0.2.10:8443" {
			t.Errorf("%s: %+v %v", old, c.HTTPS, err)
		}
		if !strings.Contains(out, "https.key") || !strings.Contains(out, "removed config key") {
			t.Errorf("%s: no warning naming https.key: %q", old, out)
		}
	}
	// The v0.3.0 shape (a listener, cert and caCert, no key) turns HTTPS off, and a hub without HTTPS is refused.
	out := capture(t, func() {
		_, err = parse(clients, `,"httpsAddresses":["192.0.2.10","hub.example.org"],"https":{"listen":"192.0.2.10:8443","cert":"/etc/infra-hub/hub.crt","caCert":"/etc/infra-hub/ca.crt"}`)
	})
	if err == nil || !strings.Contains(err.Error(), "https.listen") {
		t.Errorf("v0.3.0 https block: %v", err)
	}
	if !strings.Contains(out, "https is off until https.key is set") {
		t.Errorf("warnings: %q", out)
	}
}

// A hub follows the latest release, so a release must accept the config written for the one before it: the keys of the
// removed SSH server are ignored with one warning, never an error.
func TestOldConfigWithSSHKeysLoadsWithOneWarning(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	pub := id.Recipient().String()
	old := fmt.Sprintf(`{"listen":"192.0.2.10:11882","hostKey":"/var/lib/infra-hub/hk","repo":"/x/infra.git","upstream":"u",`+httpsBlock+`,
"clients":{"a":%q,"b":{"sshKey":%q,"agePublicKey":%q}},"certs":{"a.example.org":"a"},
"ipSources":{"c":{"url":"https://e.example/x","format":"lines"}},"ipLists":{"l":{"providers":["c"],"hosts":["a","b"]},"m":{"manual":["8.8.8.0/24"]}}}`, sshKeyLine, sshKeyLine, pub)
	var c Config
	var err error
	out := capture(t, func() { c, err = ParseConfig([]byte(old)) })
	if err != nil {
		t.Fatal(err)
	}
	if c.Clients["b"].AgePublicKey != pub || c.Clients["a"].AgePublicKey != "" || len(c.Clients) != 2 || len(c.IPLists) != 2 || c.Certs["a.example.org"] != "a" {
		t.Errorf("the rest of the config was not kept: %+v", c)
	}
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Fatalf("want one warning, got %d:\n%s", n, out)
	}
	for _, k := range []string{"listen", "hostKey", "clients.*.sshKey", "ipLists.*.hosts"} {
		if !strings.Contains(out, k) {
			t.Errorf("the warning does not name %s:\n%s", k, out)
		}
	}
	// The snake_case host_key of the earlier releases is ignored the same way.
	snake := `{"host_key":"/k","repo":"/x/infra.git","upstream":"u",` + httpsBlock + `}`
	if _, err := ParseConfig([]byte(snake)); err != nil {
		t.Errorf("host_key: %v", err)
	}
	// A config with none of these keys does not warn.
	if out := capture(t, func() { _, err = ParseConfig([]byte(`{"repo":"/x/infra.git","upstream":"u",` + httpsBlock + `}`)) }); err != nil || out != "" {
		t.Errorf("clean config: %v %q", err, out)
	}
}

func TestConfigWithoutHTTPSIsRefused(t *testing.T) {
	for name, cfg := range map[string]string{
		"only ssh":      `{"listen":"192.0.2.10:11882","hostKey":"/k","repo":"/x/infra.git","upstream":"u","clients":{"a":"` + sshKeyLine + `"}}`,
		"nothing":       `{"repo":"/x/infra.git","upstream":"u"}`,
		"empty https":   `{"repo":"/x/infra.git","upstream":"u","https":{}}`,
		"old CA fields": `{"repo":"/x/infra.git","upstream":"u","https":{"caCert":"/a","cert":"/b"}}`,
	} {
		_, err := ParseConfig([]byte(cfg))
		if err == nil || !strings.Contains(err.Error(), "https.listen") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDeprecatedSnakeCaseKeys(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	camel := `{"repo":"/x/infra.git","upstream":"u",` + httpsBlock + `,"clients":{"h":{}},
"mirrorIntervalSeconds":30,"maxStaleSeconds":120,"certDir":"/x/c","acmeDirectory":"https://acme.example.org/dir","acmeEmail":"ops@example.org",
"cloudflareTokenFile":"/x/t","ipListDir":"/x/ip",
"ipSources":{"cf":{"url":"https://x/y","format":"lines","maxBytes":4096}},"ipLists":{"l":{"providers":["cf"]}}}`
	snake := `{"repo":"/x/infra.git","upstream":"u",` + httpsBlock + `,"clients":{"h":{}},
"mirror_interval_seconds":30,"max_stale_seconds":120,"cert_dir":"/x/c","acme_directory":"https://acme.example.org/dir","acme_email":"ops@example.org",
"cloudflare_token_file":"/x/t","iplist_dir":"/x/ip",
"ip_sources":{"cf":{"url":"https://x/y","format":"lines","max_bytes":4096}},"ip_lists":{"l":{"providers":["cf"]}}}`
	a, err := ParseConfig([]byte(camel))
	if err != nil {
		t.Fatal(err)
	}
	if logs.Len() != 0 {
		t.Errorf("the new spelling warned: %s", logs.String())
	}
	b, err := ParseConfig([]byte(snake))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || a.MirrorIntervalSeconds != 30 || a.IPSources["cf"].MaxBytes != 4096 || a.IPListDir != "/x/ip" {
		t.Errorf("the two spellings differ:\n%+v\n%+v", a, b)
	}
	for _, pair := range [][2]string{{"mirror_interval_seconds", "mirrorIntervalSeconds"}, {"ip_sources", "ipSources"}, {"ipSources.cf.max_bytes", "ipSources.cf.maxBytes"}} {
		if !strings.Contains(logs.String(), "key="+pair[0]) || !strings.Contains(logs.String(), "use="+pair[1]) {
			t.Errorf("no warning naming %s -> %s:\n%s", pair[0], pair[1], logs.String())
		}
	}
	// Both spellings of one key is an error, at the top level and inside an ip source.
	both := strings.Replace(camel, `"maxBytes":4096`, `"maxBytes":4096,"max_bytes":4096`, 1)
	if _, err := ParseConfig([]byte(both)); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("conflict in an ip source accepted: %v", err)
	}
	// Unknown keys are still refused, whichever spelling style they have.
	if _, err := ParseConfig([]byte(strings.Replace(camel, `"repo"`, `"host_keys":"x","repo"`, 1))); err == nil {
		t.Error("unknown key accepted")
	}
}
