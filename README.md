# seal

Encrypt a file to a GitHub user's public SSH key.

```
seal encrypt <github-user> [file]
seal decrypt [file]                 # uses ~/.ssh/id_ed25519 or ~/.ssh/id_rsa
```

```sh
seal encrypt alice -o secrets.tar.gz.age secrets.tar.gz
seal decrypt secrets.tar.gz.age > secrets.tar.gz
```

If the user has more than one usable key you are asked which to use. Pass
`-k <n|fingerprint>` or `-a` (all keys) to skip the prompt — required when
there's no terminal, e.g. in CI. `-A` armors the output as PEM text so it can be
pasted into a message.

Files are standard [age](https://age-encryption.org) files, so the recipient can
also use the `age` CLI: `age -d -i ~/.ssh/id_ed25519 secrets.tar.gz.age`.

Only `ssh-rsa` and `ssh-ed25519` keys can be encrypted to

This repo basically just wraps some functionallity of [FiloSottile/age](https://github.com/FiloSottile/age)

