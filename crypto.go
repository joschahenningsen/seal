package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Encrypt writes src to dst encrypted to the given SSH public keys.
func Encrypt(dst io.Writer, src io.Reader, keys []Key, armorOut bool) error {
	var recipients []age.Recipient
	for _, k := range keys {
		r, err := agessh.ParseRecipient(k.Line)
		if err != nil {
			return fmt.Errorf("key %s: %w", k.Fingerprint, err)
		}
		recipients = append(recipients, r)
	}

	out := dst
	var armorW io.WriteCloser
	if armorOut {
		armorW = armor.NewWriter(dst)
		out = armorW
	}

	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if armorW != nil {
		// Closing the armor writer emits the footer; without it the file is
		// unterminated and rejected on decrypt.
		return armorW.Close()
	}
	return nil
}

// Decrypt writes src to dst decrypted with the given identities. It transparently
// handles armored input.
func Decrypt(dst io.Writer, src io.Reader, identities []age.Identity) error {
	br := bufio.NewReader(src)
	if peek, _ := br.Peek(len(armor.Header)); bytes.HasPrefix(peek, []byte(armor.Header)) {
		return decrypt(dst, armor.NewReader(br), identities)
	}
	return decrypt(dst, br, identities)
}

func decrypt(dst io.Writer, src io.Reader, identities []age.Identity) error {
	r, err := age.Decrypt(src, identities...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return errors.New("no identity matched this file: it was encrypted to a " +
				"different SSH key, or the right private key was not found (try -i)")
		}
		return err
	}
	_, err = io.Copy(dst, r)
	return err
}

// defaultIdentityPaths are the private keys probed when -i is not given.
var defaultIdentityPaths = []string{"id_ed25519", "id_rsa"}

// LoadIdentities loads SSH private keys, prompting for passphrases as needed.
// With no paths it probes the usual keys in ~/.ssh.
func LoadIdentities(paths []string) ([]age.Identity, error) {
	if len(paths) == 0 {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		for _, name := range defaultIdentityPaths {
			p := filepath.Join(home, ".ssh", name)
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}
		if len(paths) == 0 {
			return nil, fmt.Errorf("no SSH private key found in %s; pass one with -i",
				filepath.Join(home, ".ssh"))
		}
	}

	var ids []age.Identity
	for _, p := range paths {
		id, err := loadIdentity(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func loadIdentity(path string) (age.Identity, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	id, err := agessh.ParseIdentity(pem)
	if err == nil {
		return id, nil
	}

	var needsPass *ssh.PassphraseMissingError
	if !errors.As(err, &needsPass) {
		return nil, err
	}

	// Encrypted key: agessh needs the public key up front so it can defer the
	// passphrase prompt until a stanza actually matches.
	pub := needsPass.PublicKey
	if pub == nil {
		pubBytes, err := os.ReadFile(path + ".pub")
		if err != nil {
			return nil, fmt.Errorf("key is passphrase-protected and %s.pub is missing: %w", path, err)
		}
		pub, _, _, _, err = ssh.ParseAuthorizedKey(pubBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing %s.pub: %w", path, err)
		}
	}

	return agessh.NewEncryptedSSHIdentity(pub, pem, func() ([]byte, error) {
		return readPassphrase(fmt.Sprintf("Enter passphrase for %s: ", path))
	})
}

func readPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("key is passphrase-protected but there is no terminal to ask on")
	}
	defer tty.Close()

	fmt.Fprint(tty, prompt)
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return pass, err
}
