package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// ecdsaLine is a real ECDSA key: parseable, but not usable as an age recipient.
var ecdsaLine = func() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return authorizedKey(pub, "laptop")
}()

// authorizedKey renders a public key as a single authorized_keys line.
func authorizedKey(pub ssh.PublicKey, comment string) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
}

func encodePEM(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

func testKeyLines(t *testing.T) (ed25519Line, rsaLine string, edPEM, rsaPEM []byte) {
	t.Helper()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshEd, err := ssh.NewPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	edPEM = pemOf(t, edPriv)

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sshRSA, err := ssh.NewPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM = pemOf(t, rsaPriv)

	return authorizedKey(sshEd, "ed-key"), authorizedKey(sshRSA, "rsa-key"), edPEM, rsaPEM
}

func pemOf(t *testing.T, key any) []byte {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return encodePEM(block)
}

func TestFetchKeys(t *testing.T) {
	edLine, rsaLine, _, _ := testKeyLines(t)
	body := edLine + "\n" + rsaLine + "\n" + ecdsaLine + "\n\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/someone.keys" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()

	keys, err := FetchKeys(context.Background(), srv.URL, "someone")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3", len(keys))
	}
	if !keys[0].Usable || !keys[1].Usable {
		t.Errorf("ssh keys should be usable: %v", keys[:2])
	}
	if keys[2].Usable {
		t.Errorf("ecdsa key should not be usable: %v", keys[2])
	}
	if keys[0].Comment != "ed-key" || keys[0].Type != "ssh-ed25519" {
		t.Errorf("unexpected first key: %+v", keys[0])
	}

	if _, err := FetchKeys(context.Background(), srv.URL, "nobody"); err == nil {
		t.Error("expected error for unknown user")
	}
}

func TestRoundTrip(t *testing.T) {
	edLine, rsaLine, edPEM, rsaPEM := testKeyLines(t)
	plaintext := []byte("attack at dawn\n")

	for _, tc := range []struct {
		name      string
		line, pem string
		armor     bool
	}{
		{"ed25519", edLine, string(edPEM), false},
		{"ed25519-armored", edLine, string(edPEM), true},
		{"rsa", rsaLine, string(rsaPEM), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := ParseKeys([]byte(tc.line))
			if err != nil {
				t.Fatal(err)
			}

			var ct bytes.Buffer
			if err := Encrypt(&ct, bytes.NewReader(plaintext), keys, tc.armor); err != nil {
				t.Fatal(err)
			}
			if tc.armor && !bytes.HasPrefix(ct.Bytes(), []byte("-----BEGIN AGE")) {
				t.Fatal("armored output missing header")
			}

			id, err := agessh.ParseIdentity([]byte(tc.pem))
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := Decrypt(&got, bytes.NewReader(ct.Bytes()), []age.Identity{id}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), plaintext) {
				t.Fatalf("got %q, want %q", got.Bytes(), plaintext)
			}
		})
	}
}

func TestDecryptWrongKey(t *testing.T) {
	edLine, _, _, _ := testKeyLines(t)
	_, _, otherPEM, _ := testKeyLines(t)

	keys, _ := ParseKeys([]byte(edLine))
	var ct bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader([]byte("hi")), keys, false); err != nil {
		t.Fatal(err)
	}
	id, err := agessh.ParseIdentity(otherPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(&bytes.Buffer{}, bytes.NewReader(ct.Bytes()), []age.Identity{id}); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestSelectKeys(t *testing.T) {
	edLine, rsaLine, _, _ := testKeyLines(t)
	keys, _ := ParseKeys([]byte(edLine + "\n" + rsaLine + "\n" + ecdsaLine))

	if got, err := selectKeys("u", keys, "", true); err != nil || len(got) != 2 {
		t.Fatalf("--all: got %d keys, err %v", len(got), err)
	}
	if got, err := selectKeys("u", keys, "2", false); err != nil || got[0].Comment != "rsa-key" {
		t.Fatalf("index: got %+v, err %v", got, err)
	}
	if got, err := selectKeys("u", keys, "1,2", false); err != nil || len(got) != 2 {
		t.Fatalf("list: got %d keys, err %v", len(got), err)
	}
	if got, err := selectKeys("u", keys, keys[0].Fingerprint, false); err != nil || got[0].Comment != "ed-key" {
		t.Fatalf("fingerprint: got %+v, err %v", got, err)
	}
	if _, err := selectKeys("u", keys, "9", false); err == nil {
		t.Error("expected out-of-range error")
	}
	if _, err := selectKeys("u", keys, "3", false); err == nil {
		t.Error("ecdsa key should not be selectable")
	}

	only, _ := ParseKeys([]byte(edLine))
	if got, err := selectKeys("u", only, "", false); err != nil || len(got) != 1 {
		t.Fatalf("single key should not prompt: %d, %v", len(got), err)
	}
	ecdsaOnly, _ := ParseKeys([]byte(ecdsaLine))
	if _, err := selectKeys("u", ecdsaOnly, "", false); err == nil {
		t.Error("expected error when no usable keys")
	}
	if _, err := selectKeys("u", nil, "", false); err == nil {
		t.Error("expected error when no keys at all")
	}
}
