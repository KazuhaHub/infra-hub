package config

import (
	"bytes"
	"filippo.io/age"
	"fmt"
	"log/slog"
	"reflect"
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
"hostKey":"/var/lib/infra-hub/hk","clients":{"a":"` + k1 + `","b":"` + k2 + `"}` + extra + `}`
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
		"no clients":      `{"listen":"1.2.3.4:1","repo":"/x/infra.git","upstream":"u","hostKey":"/k","clients":{}}`,
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
	base := `{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","hostKey":"/x/k","clients":{"h":"%s"},"certs":%s}`
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
		return ParseConfig([]byte(fmt.Sprintf(`{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","hostKey":"/x/k","clients":{"h":%q}%s}`, key, extra)))
	}
	good := `,"ipSources":{"cf":{"url":"https://x/y","format":"lines"}},"ipLists":{"cloudflare":{"providers":["cf"],"manual":["203.0.114.5/24"],"hosts":["h"]}}`
	c, err := parse(good)
	if err != nil {
		t.Fatal(err)
	}
	if c.IPLists["cloudflare"].Manual[0] != "203.0.114.0/24" || c.IPListDir != "/x/iplists" {
		t.Fatalf("%+v", c)
	}
	for name, extra := range map[string]string{
		"unknown provider":   `,"ipLists":{"a":{"providers":["nope"],"hosts":["h"]}}`,
		"unknown host":       strings.Replace(good, `"hosts":["h"]`, `"hosts":["z"]`, 1),
		"private manual":     strings.Replace(good, "203.0.114.5/24", "192.168.0.0/16", 1),
		"everything manual":  strings.Replace(good, "203.0.114.5/24", "0.0.0.0/0", 1),
		"empty list":         `,"ipLists":{"a":{"hosts":["h"]}}`,
		"http source":        strings.Replace(good, "https://x/y", "http://x/y", 1),
		"odd list name":      strings.Replace(good, `"cloudflare"`, `"../x"`, 1),
		"odd provider name":  strings.Replace(strings.Replace(good, `"cf":`, `"C F":`, 1), `["cf"]`, `["C F"]`, 1),
		"relative directory": `,"ipListDir":"rel"`,
	} {
		if _, err := parse(extra); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestConfigRejectsADuplicateProvider(t *testing.T) {
	_, key := testutil.NewKey(t)
	cfg := fmt.Sprintf(`{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","hostKey":"/x/k","clients":{"h":%q},
		"ipSources":{"cf":{"url":"https://x/y","format":"lines"}},"ipLists":{"a":{"providers":["cf","cf"],"hosts":["h"]}}}`, key)
	if _, err := ParseConfig([]byte(cfg)); err == nil {
		t.Fatal("accepted")
	}
}

func TestConfigClientsAndHTTPS(t *testing.T) {
	_, key := testutil.NewKey(t)
	id, _ := age.GenerateX25519Identity()
	pub := id.Recipient().String()
	parse := func(clients, extra string) (Config, error) {
		return ParseConfig([]byte(`{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","hostKey":"/x/k","clients":` + clients + extra + `}`))
	}
	// The old string form, and the object form with and without an age key.
	c, err := parse(fmt.Sprintf(`{"old":%q,"both":{"sshKey":%q,"agePublicKey":%q},"ssh":{"sshKey":%q}}`, key, mustKey(t), pub, mustKey(t)), "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Clients["old"].SSHKey != key || c.Clients["old"].AgePublicKey != "" || c.Clients["both"].AgePublicKey != pub {
		t.Errorf("clients: %+v", c.Clients)
	}
	if r := c.AgeRecipients(); len(r) != 1 || r["both"] == nil {
		t.Errorf("recipients: %v", r)
	}
	keys, err := c.ClientKeys()
	if err != nil || len(keys) != 3 {
		t.Errorf("ssh keys: %d %v", len(keys), err)
	}
	// An age-only client has no SSH identity.
	if c, err := parse(fmt.Sprintf(`{"a":{"agePublicKey":%q},"b":%q}`, pub, key), ""); err != nil {
		t.Errorf("age-only client: %v", err)
	} else if keys, _ := c.ClientKeys(); len(keys) != 1 {
		t.Errorf("age-only client got an SSH key: %d", len(keys))
	}
	for name, clients := range map[string]string{
		"bad age key":    fmt.Sprintf(`{"a":{"sshKey":%q,"agePublicKey":"age1nope"}}`, key),
		"ssh key as age": fmt.Sprintf(`{"a":{"sshKey":%q,"agePublicKey":%q}}`, key, key),
		"unknown field":  fmt.Sprintf(`{"a":{"sshKey":%q,"token":"x"}}`, key),
		"neither":        `{"a":{}}`,
		"number":         `{"a":5}`,
	} {
		if _, err := parse(clients, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	clients := fmt.Sprintf(`{"a":%q}`, key)
	goodHTTPS := `,"httpsAddresses":["192.0.2.10","hub.example.org"],"https":{"listen":"192.0.2.10:8443","key":"/etc/infra-hub/hub.key"}`
	c, err = parse(clients, goodHTTPS)
	if err != nil || c.HTTPS.Listen != "192.0.2.10:8443" || c.HTTPS.Key != "/etc/infra-hub/hub.key" || len(c.HTTPSAddresses) != 2 {
		t.Fatalf("good https: %+v %v", c.HTTPS, err)
	}
	for name, extra := range map[string]string{
		"wildcard name": strings.Replace(goodHTTPS, "hub.example.org", "*.example.org", 1),
		"upper case":    strings.Replace(goodHTTPS, "hub.example.org", "Hub.Example.org", 1),
		"duplicate":     strings.Replace(goodHTTPS, "hub.example.org", "192.0.2.10", 1),
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
		var logs bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		c, err := parse(clients, `,"httpsAddresses":["192.0.2.10"],"https":{"listen":"192.0.2.10:8443","key":"/k",`+old+`}`)
		slog.SetDefault(prev)
		if err != nil || c.HTTPS.Key != "/k" || c.HTTPS.Listen != "192.0.2.10:8443" {
			t.Errorf("%s: %+v %v", old, c.HTTPS, err)
		}
		if !strings.Contains(logs.String(), "https.key") || !strings.Contains(logs.String(), "removed config key") {
			t.Errorf("%s: no warning naming https.key: %q", old, logs.String())
		}
	}
	// Only the old fields, no key: still starts (HTTPS then needs https.key and is refused as before for listen).
	if _, err := parse(clients, `,"https":{"caCert":"/a","cert":"/b"}`); err != nil {
		t.Errorf("old fields without listen: %v", err)
	}
}

func mustKey(t *testing.T) string {
	_, k := testutil.NewKey(t)
	return k
}

func TestConfigRejectsSharedAgeKeyAndZonedAddress(t *testing.T) {
	_, k1 := testutil.NewKey(t)
	_, k2 := testutil.NewKey(t)
	id, _ := age.GenerateX25519Identity()
	pub := id.Recipient().String()
	base := `{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","hostKey":"/x/k","clients":%s%s}`
	shared := fmt.Sprintf(`{"a":{"sshKey":%q,"agePublicKey":%q},"b":{"sshKey":%q,"agePublicKey":%q}}`, k1, pub, k2, pub)
	if _, err := ParseConfig([]byte(fmt.Sprintf(base, shared, ""))); err == nil {
		t.Error("two clients with the same age key accepted")
	}
	one := fmt.Sprintf(`{"a":%q}`, k1)
	if _, err := ParseConfig([]byte(fmt.Sprintf(base, one, `,"httpsAddresses":["fe80::1%eth0"]`))); err == nil {
		t.Error("zoned address accepted")
	}
}

func TestDeprecatedSnakeCaseKeys(t *testing.T) {
	_, key := testutil.NewKey(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	camel := fmt.Sprintf(`{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","hostKey":"/x/k","clients":{"h":%q},
"mirrorIntervalSeconds":30,"maxStaleSeconds":120,"certDir":"/x/c","acmeDirectory":"https://acme.example.org/dir","acmeEmail":"ops@example.org",
"cloudflareTokenFile":"/x/t","ipListDir":"/x/ip",
"ipSources":{"cf":{"url":"https://x/y","format":"lines","maxBytes":4096}},"ipLists":{"l":{"providers":["cf"],"hosts":["h"]}}}`, key)
	snake := fmt.Sprintf(`{"listen":"127.0.0.1:1","repo":"/x/infra.git","upstream":"u","host_key":"/x/k","clients":{"h":%q},
"mirror_interval_seconds":30,"max_stale_seconds":120,"cert_dir":"/x/c","acme_directory":"https://acme.example.org/dir","acme_email":"ops@example.org",
"cloudflare_token_file":"/x/t","iplist_dir":"/x/ip",
"ip_sources":{"cf":{"url":"https://x/y","format":"lines","max_bytes":4096}},"ip_lists":{"l":{"providers":["cf"],"hosts":["h"]}}}`, key)
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
	if !reflect.DeepEqual(a, b) || a.HostKey != "/x/k" || a.MirrorIntervalSeconds != 30 || a.IPSources["cf"].MaxBytes != 4096 || a.IPListDir != "/x/ip" {
		t.Errorf("the two spellings differ:\n%+v\n%+v", a, b)
	}
	for _, pair := range [][2]string{{"host_key", "hostKey"}, {"mirror_interval_seconds", "mirrorIntervalSeconds"}, {"ip_sources", "ipSources"}, {"ipSources.cf.max_bytes", "ipSources.cf.maxBytes"}} {
		if !strings.Contains(logs.String(), "key="+pair[0]) || !strings.Contains(logs.String(), "use="+pair[1]) {
			t.Errorf("no warning naming %s -> %s:\n%s", pair[0], pair[1], logs.String())
		}
	}
	// Both spellings of one key is an error, at the top level and inside an ip source.
	both := strings.Replace(camel, `"hostKey":"/x/k"`, `"hostKey":"/x/k","host_key":"/x/k"`, 1)
	if _, err := ParseConfig([]byte(both)); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("conflict accepted: %v", err)
	}
	both = strings.Replace(camel, `"maxBytes":4096`, `"maxBytes":4096,"max_bytes":4096`, 1)
	if _, err := ParseConfig([]byte(both)); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Errorf("conflict in an ip source accepted: %v", err)
	}
	// Unknown keys are still refused, whichever spelling style they have.
	if _, err := ParseConfig([]byte(strings.Replace(camel, `"listen"`, `"host_keys":"x","listen"`, 1))); err == nil {
		t.Error("unknown key accepted")
	}
}
