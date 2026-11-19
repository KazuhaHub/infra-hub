package sshserver

import (
	"context"
	"errors"
	"net"

	"golang.org/x/crypto/ssh"
)

// ConnInfo is what the server knows about a connection that has proven possession of Key (the SSH library has
// already checked the signature). Nothing here depends on which network the connection came over.
type ConnInfo struct {
	User       string
	RemoteAddr net.Addr
	Key        ssh.PublicKey
}

// Identifier turns a connection into a host name from the configured list, or an error. It is the only gate:
// the server serves a connection if and only if Identify succeeds.
//
// To use another method (a client certificate, a WireGuard or Headscale peer identity, a token), write another
// Identifier and pick it in main. Extra signals such as a network-level peer lookup can be recorded next to the result for
// the status display, but must never be what lets a connection in.
type Identifier interface {
	Identify(ctx context.Context, c ConnInfo) (hostName string, err error)
}

// SSHKeyIdentifier accepts exactly the public keys in the config (host name -> key).
type SSHKeyIdentifier struct {
	byKey map[string]string // marshaled public key -> host name
}

func NewSSHKeyIdentifier(keys map[string]ssh.PublicKey) *SSHKeyIdentifier {
	m := make(map[string]string, len(keys))
	for name, k := range keys {
		m[string(k.Marshal())] = name
	}
	return &SSHKeyIdentifier{byKey: m}
}

func (i *SSHKeyIdentifier) Identify(_ context.Context, c ConnInfo) (string, error) {
	if c.User != sshUser {
		return "", errors.New("unexpected user name")
	}
	if c.Key == nil {
		return "", errors.New("no public key")
	}
	name, ok := i.byKey[string(c.Key.Marshal())]
	if !ok {
		return "", errors.New("unknown public key")
	}
	return name, nil
}

// sshUser is the user name clients connect as. It carries no meaning (identity is the key), but one fixed value
// keeps the URL the same everywhere.
const sshUser = "infra"
