# Changelog

## 0.1.5 - 2026-10-13

- Default HTTPS uses ECC-only certificate verification on its first connection. A matching handshake refusal opens one new connection with verify-only RSA-PSS and Certificate Transparency checks scoped to the public root set.
- Caller-supplied TLS configurations stay in force without verifier retries. The library continues to leave crypto provider selection to the host.
