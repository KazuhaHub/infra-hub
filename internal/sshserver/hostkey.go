package sshserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

// LoadOrCreateHostKey returns the hub's host key. The first start generates an ed25519 key and keeps it in
// path (0600), so the key survives restarts; path+".pub" holds the public half in known_hosts/authorized_keys
// format for the host inventory.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		block, merr := ssh.MarshalPrivateKey(priv, "infra-hub host key")
		if merr != nil {
			return nil, merr
		}
		pemBytes = pem.EncodeToMemory(block)
		if werr := atomicfile.Write(path, pemBytes, 0o600); werr != nil {
			return nil, werr
		}
	} else if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("host key %s: %w", path, err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("host key %s is not ed25519", path)
	}
	pub := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if cur, _ := os.ReadFile(path + ".pub"); string(cur) != string(pub) {
		if err := atomicfile.Write(path+".pub", pub, 0o644); err != nil {
			return nil, err
		}
	}
	return signer, nil
}

func SignerFingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }
