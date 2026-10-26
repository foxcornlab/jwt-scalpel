# jwt-scalpel — offline JWT security scanner

I kept running into JWTs during engagements and wanted one offline tool
that answers "is this token weak?" in a second. So I built one.

What it checks:
- `alg=none` tokens and none-stripping downgrade surface
- weak HMAC secrets (built-in list plus your own `--wordlist`)
- `kid` path/SQL injection patterns
- untrusted `jku` / `x5u` key URLs and embedded `jwk`
- expired or missing `exp` / `nbf` claims

```
$ ./jwtscalpel.py -f token.txt
[HIGH] weak HMAC secret: signature verifies with secret 'secret'
[MEDIUM] alg confusion surface: a stripped alg=none variant parses cleanly
[LOW] no exp claim: token never expires; theft is permanent
```

Single Python file, zero dependencies, 12 tests green.
Exit codes: 0 clean, 1 findings, 2 errors — pipes straight into CI.

Repo: https://github.com/foxcornlab/jwt-scalpel

#redteam #appsec #jwt #pentesting #offensivesecurity
