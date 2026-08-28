// Command enc encrypts a file to a GitHub user's public SSH key, so they can
// decrypt it with the private key they already have. Output is a standard age
// file, also readable with `age -d -i ~/.ssh/id_ed25519`.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const version = "0.0.1"

const usage = `enc encrypts a file to a GitHub user's public SSH key.

Usage:
  enc encrypt <github-user> [file]   encrypt to a user's SSH key
  enc decrypt [file]                 decrypt with your SSH private key

With no file, or "-", input is read from stdin. Output goes to stdout unless -o
is given. Run "enc encrypt -h" or "enc decrypt -h" for flags.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "enc: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch args[0] {
	case "encrypt", "e":
		return runEncrypt(args[1:])
	case "decrypt", "d":
		return runDecrypt(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	case "version", "--version":
		fmt.Println("enc " + version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try \"enc help\")", args[0])
	}
}

type stringsFlag []string

func (s *stringsFlag) String() string     { return fmt.Sprint(*s) }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func runEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	var (
		out     = fs.String("o", "", "write output to `file` (default stdout)")
		sel     = fs.String("k", "", "select key by index or SHA256 `fingerprint` (no prompt)")
		all     = fs.Bool("a", false, "encrypt to all of the user's usable keys (no prompt)")
		armorOn = fs.Bool("A", false, "PEM-armor the output so it can be pasted as text")
		baseURL = fs.String("keys-url", defaultKeysURL, "base `url` serving <user>.keys")
	)
	fs.StringVar(out, "out", "", "")
	fs.StringVar(sel, "key", "", "")
	fs.BoolVar(all, "all", false, "")
	fs.BoolVar(armorOn, "armor", false, "")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: enc encrypt [flags] <github-user> [file]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("missing github user")
	}
	if fs.NArg() > 2 {
		return fmt.Errorf("too many arguments")
	}
	user := fs.Arg(0)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	keys, err := FetchKeys(ctx, *baseURL, user)
	if err != nil {
		return err
	}
	selected, err := selectKeys(user, keys, *sel, *all)
	if err != nil {
		return err
	}

	src, closeSrc, err := openInput(fs.Arg(1))
	if err != nil {
		return err
	}
	defer closeSrc()

	if (*out == "" || *out == "-") && !*armorOn && isTerminal(os.Stdout) {
		return fmt.Errorf("refusing to write binary ciphertext to the terminal: " +
			"use -o <file>, pipe it somewhere, or add -A for armored text")
	}

	return withOutput(*out, func(w io.Writer) error {
		return Encrypt(w, src, selected, *armorOn)
	})
}

func runDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	var ids stringsFlag
	out := fs.String("o", "", "write output to `file` (default stdout)")
	fs.StringVar(out, "out", "", "")
	fs.Var(&ids, "i", "SSH private key `file` (repeatable; default ~/.ssh/id_ed25519, id_rsa)")
	fs.Var(&ids, "identity", "")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: enc decrypt [flags] [file]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("too many arguments")
	}

	identities, err := LoadIdentities(ids)
	if err != nil {
		return err
	}
	src, closeSrc, err := openInput(fs.Arg(0))
	if err != nil {
		return err
	}
	defer closeSrc()

	return withOutput(*out, func(w io.Writer) error {
		return Decrypt(w, src, identities)
	})
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func openInput(path string) (io.Reader, func(), error) {
	if path == "" || path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// withOutput runs fn against the destination. For a file destination it writes
// to a temp file alongside it and renames on success, so a failure never leaves
// a truncated or partially decrypted file in place.
func withOutput(path string, fn func(io.Writer) error) error {
	if path == "" || path == "-" {
		return fn(os.Stdout)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if err := fn(tmp); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
