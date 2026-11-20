package config

import "testing"

func TestConfigWaitTimeout(t *testing.T) {
	parse := func(extra string) (Config, error) {
		return ParseConfig([]byte(`{"repo":"/x/infra.git","upstream":"u",` + httpsBlock + `,"clients":{"a":{}}` + extra + `}`))
	}
	if c, err := parse(""); err != nil || c.WaitTimeoutSeconds != 240 {
		t.Fatalf("default: %v %v", c.WaitTimeoutSeconds, err)
	}
	if c, err := parse(`,"waitTimeoutSeconds":60`); err != nil || c.WaitTimeoutSeconds != 60 {
		t.Errorf("set: %v %v", c.WaitTimeoutSeconds, err)
	}
	for _, v := range []string{"5", "301", "-1"} {
		if _, err := parse(`,"waitTimeoutSeconds":` + v); err == nil {
			t.Errorf("accepted %s", v)
		}
	}
}
