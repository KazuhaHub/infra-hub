package sshserver

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

func TestIdentify(t *testing.T) {
	a, _ := testutil.NewKey(t)
	b, _ := testutil.NewKey(t)
	stranger, _ := testutil.NewKey(t)
	id := NewSSHKeyIdentifier(map[string]ssh.PublicKey{"host-a": a.PublicKey(), "host-b": b.PublicKey()})
	cases := []struct {
		name string
		c    ConnInfo
		want string
		fail bool
	}{
		{"allowed a", ConnInfo{User: "infra", Key: a.PublicKey()}, "host-a", false},
		{"allowed b", ConnInfo{User: "infra", Key: b.PublicKey()}, "host-b", false},
		{"unknown key", ConnInfo{User: "infra", Key: stranger.PublicKey()}, "", true},
		{"wrong user", ConnInfo{User: "root", Key: a.PublicKey()}, "", true},
		{"no key", ConnInfo{User: "infra"}, "", true},
	}
	for _, tc := range cases {
		got, err := id.Identify(context.Background(), tc.c)
		if (err != nil) != tc.fail || got != tc.want {
			t.Errorf("%s: got %q, %v", tc.name, got, err)
		}
	}
}

func TestHostKeyIsKeptAcrossRestarts(t *testing.T) {
	path := t.TempDir() + "/hk"
	s1, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LoadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(s1.PublicKey().Marshal()) != string(s2.PublicKey().Marshal()) {
		t.Fatal("host key changed on restart")
	}
}
