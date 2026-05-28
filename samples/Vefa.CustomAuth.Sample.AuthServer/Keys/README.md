# Sample confidential client keys

`service-client.jwks.json` is the **public** JSON Web Key Set for the sample `service-client`
confidential client, which authenticates with `private_key_jwt`. `DatabaseSeeder` reads this file
and stores it on the client record so the auth server can verify the client's signed assertions.

This file contains **public key material only** — it is safe to commit. The matching private key is
deliberately not shipped; in a real deployment the calling service holds the private key and signs
its client assertions with it. See [`docs/private-key-jwt.md`](../../../docs/private-key-jwt.md) for
the end-to-end flow.

## Regenerating the demo key

Generate a new RSA key pair and replace the `n` (modulus) and `e` (exponent) values, base64url
encoded without padding:

```bash
openssl genrsa -out service-client.key 2048
# Keep service-client.key private (do NOT commit it).
# Derive the public modulus:
openssl rsa -in service-client.key -noout -modulus
# Convert the hex modulus to base64url (n) and use "AQAB" for the standard exponent (e=65537),
# then update service-client.jwks.json. Any JWKS tooling that emits public RSA JWKs also works.
```

RSA (RS256/384/512, PS256), and EC (ES256/384/512) keys are all accepted.
