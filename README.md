# jwt-scalpel

Offline JWT security scanner. Hand it a token, get back everything wrong
with it, algorithm confusion surface, guessable HMAC secrets, injectable
`kid`, untrusted `jku`/`x5u` key URLs, and lifetime problems. Nothing
leaves the machine.

## Install

```sh
chmod +x jwtscalpel.py
./jwtscalpel.py --help
```

Python 3.8+, standard library only. No dependencies.

## Usage

```sh
# scan a token argument
./jwtscalpel.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# scan from a file or stdin
./jwtscalpel.py -f token.txt
cat token.txt | ./jwtscalpel.py -

# add your own secret candidates
./jwtscalpel.py -f token.txt -w candidates.txt

# machine-readable output
./jwtscalpel.py -f token.txt --json
```

Exit codes: `0` clean, `1` findings, `2` usage or parse error.

## Example

```
$ ./jwtscalpel.py -f weak.txt
[HIGH] weak HMAC secret: signature verifies with secret 'secret'
[MEDIUM] alg confusion surface: a stripped alg=none variant parses cleanly; reject 'none' server-side
[LOW] no exp claim: token never expires; theft is permanent
```

## What it checks

- `alg=none` tokens and none-stripping surface
- HMAC secrets against a built-in weak list plus `--wordlist`
- `kid` path/SQL traversal patterns
- `jku` / `x5u` remote key URLs and embedded `jwk`
- `exp` / `nbf` lifetime claims

## Scope

Authorized testing only. Use against systems you own or are permitted
to test.

## License

MIT, see [LICENSE](LICENSE).
