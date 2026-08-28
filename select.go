package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// selectKeys narrows the keys published by a user down to the ones to encrypt
// to. With --all or --key it never prompts; otherwise it prompts on the
// terminal, and errors out if there is no terminal to prompt on.
func selectKeys(user string, keys []Key, sel string, all bool) ([]Key, error) {
	var usable []Key
	skipped := 0
	for _, k := range keys {
		if k.Usable {
			usable = append(usable, k)
		} else {
			skipped++
		}
	}

	switch {
	case len(keys) == 0:
		return nil, fmt.Errorf("%s has no public SSH keys on GitHub", user)
	case len(usable) == 0:
		return nil, fmt.Errorf("%s has %d SSH key(s), but none usable for encryption "+
			"(only ssh-rsa and ssh-ed25519 keys can be encrypted to)", user, len(keys))
	}

	if sel != "" {
		return matchSelection(usable, sel)
	}
	if all || len(usable) == 1 {
		return usable, nil
	}

	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		var b strings.Builder
		writeListing(&b, user, usable, skipped)
		return nil, fmt.Errorf("%s has %d usable keys and there is no terminal to ask on; "+
			"re-run with --key <n|fingerprint> or --all\n\n%s", user, len(usable), b.String())
	}
	defer tty.Close()

	writeListing(tty, user, usable, skipped)
	fmt.Fprintf(tty, "Select key(s) [1-%d, comma-separated, or \"a\" for all]: ", len(usable))

	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading selection: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("no key selected")
	}
	return matchSelection(usable, line)
}

func writeListing(w io.Writer, user string, usable []Key, skipped int) {
	fmt.Fprintf(w, "%s has %d usable SSH key(s):\n", user, len(usable))
	for i, k := range usable {
		fmt.Fprintf(w, "  %d) %s\n", i+1, k)
	}
	if skipped > 0 {
		fmt.Fprintf(w, "     (skipped %d key(s) of a type that cannot be encrypted to)\n", skipped)
	}
}

// matchSelection resolves "a", a 1-based index list, or SHA256 fingerprints.
func matchSelection(usable []Key, sel string) ([]Key, error) {
	if s := strings.ToLower(strings.TrimSpace(sel)); s == "a" || s == "all" {
		return usable, nil
	}

	var out []Key
	seen := map[string]bool{}
	for _, part := range strings.Split(sel, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, err := matchOne(usable, part)
		if err != nil {
			return nil, err
		}
		if !seen[k.Fingerprint] {
			seen[k.Fingerprint] = true
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no key selected")
	}
	return out, nil
}

func matchOne(usable []Key, sel string) (Key, error) {
	if n, err := strconv.Atoi(sel); err == nil {
		if n < 1 || n > len(usable) {
			return Key{}, fmt.Errorf("key %d out of range (have %d usable keys)", n, len(usable))
		}
		return usable[n-1], nil
	}

	want := strings.TrimPrefix(sel, "SHA256:")
	var matches []Key
	for _, k := range usable {
		if strings.HasPrefix(strings.TrimPrefix(k.Fingerprint, "SHA256:"), want) {
			matches = append(matches, k)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return Key{}, fmt.Errorf("no usable key matches %q", sel)
	default:
		return Key{}, fmt.Errorf("%q matches %d keys, be more specific", sel, len(matches))
	}
}
