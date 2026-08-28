package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/ssh"
)

const defaultKeysURL = "https://github.com"

// maxKeysBody caps the .keys response
const maxKeysBody = 1 << 20

// Key is one public SSH key published by a GitHub user.
type Key struct {
	Type        string // ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, ...
	Comment     string
	Fingerprint string // SHA256:...
	Line        string // the original authorized_keys line
	Usable      bool   // age can encrypt to it (ssh-rsa or ssh-ed25519)
}

func (k Key) String() string {
	s := fmt.Sprintf("%-16s %s", k.Type, k.Fingerprint)
	if k.Comment != "" {
		s += "  " + k.Comment
	}
	return s
}

// usableTypes are the SSH key types age supports as recipients. ECDSA keys
// cannot be used for encryption, and sk-* (FIDO) keys need the token present.
var usableTypes = map[string]bool{
	ssh.KeyAlgoRSA:     true,
	ssh.KeyAlgoED25519: true,
}

// FetchKeys retrieves the public SSH keys GitHub publishes for user.
func FetchKeys(ctx context.Context, baseURL, user string) ([]Key, error) {
	url := strings.TrimSuffix(baseURL, "/") + "/" + user + ".keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "enc/"+version)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no such GitHub user: %s", user)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysBody))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	return ParseKeys(body)
}

// ParseKeys parses the body of a .keys response into Keys.
func ParseKeys(body []byte) ([]Key, error) {
	var keys []Key
	s := bufio.NewScanner(strings.NewReader(string(body)))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			// Skip anything we can't parse rather than failing the whole fetch.
			continue
		}
		keys = append(keys, Key{
			Type:        pub.Type(),
			Comment:     comment,
			Fingerprint: ssh.FingerprintSHA256(pub),
			Line:        line,
			Usable:      usableTypes[pub.Type()],
		})
	}
	return keys, s.Err()
}
