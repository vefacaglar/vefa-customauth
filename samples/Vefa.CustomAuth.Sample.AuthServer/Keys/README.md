# Sample keys

This folder holds the sample's key material.

## `signing.pfx` (auth server token signing) — git-ignored

If present, the auth server signs its access/ID tokens with this certificate via
`AddSigningCertificate` (see `Program.cs`) instead of the auto-generated key in the database. It is
**git-ignored** because it contains a private key, so a fresh clone falls back to the store-backed key.
The dev password is in `appsettings.Development.json` (`SigningCertificate:Password`).

Generate one (throwaway, dev only):

```bash
openssl req -x509 -newkey rsa:2048 -keyout signing.key.tmp -out signing.crt.tmp -days 3650 -nodes \
  -subj "/CN=Vefa.CustomAuth Sample Signing"
openssl pkcs12 -export -inkey signing.key.tmp -in signing.crt.tmp -out signing.pfx -passout pass:devpassword
rm signing.key.tmp signing.crt.tmp
```

In production, load the certificate from a secret store and use the **same** certificate on every
instance behind a load balancer.

## `service-client.jwks.json` (confidential client) — committed (public only)

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
