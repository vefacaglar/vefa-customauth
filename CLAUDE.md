# AGENTS.md

Project-specific rules for Codex when working on **Vefa.CustomAuth**.

## Current progress (handoff note)

Read this first. The previous session ended here and the user will continue with a fresh model.

### Completed milestones

1. **Solution scaffolding** — sln (`Vefa.CustomAuth.slnx`), 5 src projects, 3 sample projects, 2 test projects all on `net8.0`. `Directory.Build.props` carries shared package metadata; `src/`, `samples/`, `tests/` each override `IsPackable`. Project references and NuGet dependencies are wired. `dotnet build` is 0 warnings / 0 errors.
2. **Domain models, store abstractions, options** — `Vefa.CustomAuth.Core` contains all 5 models (`CustomAuthClient`, `CustomAuthAuthorizationCode`, `CustomAuthRefreshToken`, `CustomAuthSession`, `CustomAuthSigningKey`), 6 store interfaces (`ICustomAuth*Store`), and `CustomAuthOptions`. See `src/Vefa.CustomAuth.Core/`.
3. **JWT signing + token issuance** — `Vefa.CustomAuth.Tokens` has `TokenHasher` (SHA-256 + base64url + opaque token generator), `RsaKeyGenerator`, `RsaSigningCredentialsProvider` (auto-bootstraps an RSA key on first use), and `JwtTokenIssuer` (access + id JWTs, opaque refresh). Registered via `AddJwtTokenSigning()`. Signing/token services are scoped so they can consume scoped EF stores.
4. **Real v0.1 auth endpoints** — `MapVefaCustomAuthEndpoints()` maps working handlers for discovery, JWKS, authorize, token, and login. Endpoint helpers live in `src/Vefa.CustomAuth.AspNetCore/Endpoints/`. Implemented behavior includes exact redirect URI validation, scope subset validation, required PKCE, SSO session cookie lookup, authorization-code creation, authorization-code exchange, refresh-token rotation, and OAuth-style error JSON.
5. **In-memory stores** — full set in `src/Vefa.CustomAuth.AspNetCore/Stores/InMemory/`, registered via `AddInMemoryStores(configure)` with optional client + user seed lists. `InMemoryUserStore` uses `CryptographicOperations.FixedTimeEquals` for password compare. Sample-only, not production.
6. **EF Core stores** — `CustomAuthDbContext`, entity configurations, and all EF-backed store implementations are in `Vefa.CustomAuth.EntityFrameworkCore`. Registration is available via `AddVefaCustomAuthEntityFrameworkCore(optionsAction)` and `AddVefaCustomAuthStores<TContext>()`. `EfCustomAuthSigningKeyStore.GetAllAsync()` orders in memory to avoid SQLite `DateTimeOffset` ordering limitations.
7. **Runnable sample flow** — `scripts/run-samples.sh` builds and starts all three sample apps. `Sample.AuthServer` uses SQLite-backed EF stores for clients, authorization codes, refresh tokens, sessions, and signing keys; only the demo user store remains in-memory because user persistence is host-owned. `Sample.WebApp` uses ASP.NET Core OpenID Connect with code + PKCE and calls `Sample.Api`; `Sample.Api` validates JWT access tokens with `JwtBearer`.
8. **Options validation and hardening** — Added `IValidateOptions<CustomAuthOptions>` with startup validation via `ValidateOnStart()` and comprehensive validation tests. Quieted EF Core commands output in samples by setting the level to `Warning`.
9. **v0.2 Endpoints** — Fully implemented and mapped `/connect/logout`, `/connect/userinfo`, and `/connect/revoke` OIDC endpoints, registered them in DI, updated the discovery configuration, and added comprehensive end-to-end integration tests (all 36 tests pass!).
10. **v0.4 Packaging & CI Automation** — Versioned to `0.1.0` in `Directory.Build.props`, completed XML comments on public models, and created a GitHub Actions CI workflow under `.github/workflows/build-test.yml` running on Node 24 (addressing Node 20 deprecation warnings) that restores, builds, tests, and packs the solution in Release mode.
11. **v0.5-v0.7 Admin UI SPA & Decoupled Persistence** — Implemented the provider-agnostic `Vefa.CustomAuth.AdminUI` class library using Alpine.js and Tailwind CSS. Built full client CRUD Minimal API endpoints connected to core Managers and Stores. Added complete integration tests (`AdminUIEndpointTests.cs`) and resolved trailing-slash relative assets resolving issues and Alpine execution race conditions. The dashboard is fully dynamic, featuring interactive client selection, visual selection highlights, and real-time C#/JSON integration code generators.
12. **v0.8 MongoDB Provider** — Implemented `Vefa.CustomAuth.MongoDB` package with all 7 store implementations (`MongoCustomAuthClientStore`, `MongoCustomAuthAuthorizationCodeStore`, `MongoCustomAuthRefreshTokenStore`, `MongoCustomAuthSessionStore`, `MongoCustomAuthSigningKeyStore`, `MongoCustomAuthScopeStore`, `MongoCustomAuthAuditLogStore`), `MongoCustomAuthCleanupService`, `MongoCustomAuthIndexManager` for index creation, BsonClassMap registrations, and `AddVefaCustomAuthMongoDbStores` DI extension. Added 12 comprehensive contract tests using Testcontainers.MongoDb (all pass). Total test count: 56 (24 store/manager + 32 AspNetCore).

### What is the user's intended next step

Phase 2 goals up to `v0.8` (MongoDB Provider) are fully implemented! The next major milestone is:
1. **v0.9 — Admin UI Extended Management**: Extend the SPA dashboard with scope management, active session viewer, token/session revocation, signing key viewer, and audit log viewer.

Recent troubleshooting note: if `http://localhost:5043/` shows a 401 from the API after previous successful login, the browser likely has an old WebApp auth cookie containing tokens signed by an older local signing key. Open `http://localhost:5043/logout`, then reload `http://localhost:5043/` and sign in again with `demo / demo`.

### Operating rules reminder for the next model

- Read the rest of this file before touching anything.
- Build must stay at 0 warnings / 0 errors. Run `dotnet build` after each meaningful change.
- Update `plan.md` `Status:` lines in the same change that advances them.
- All code, comments, logs, exception messages, and commit messages in English. Turkish only in chat replies.
- Do not commit unless explicitly asked.

## Project context

- OAuth2 / OIDC SSO library for ASP.NET Core, distributed as NuGet packages.
- Target framework: `net8.0` (LTS). Do not introduce other TFMs without discussion.
- See [`plan.md`](plan.md) for the full requirements roadmap. It is the source of truth for scope and design intent — extend it when scope changes, but do not silently rewrite existing sections.

## Language rules (strict)

Everything that ships inside the repository as part of the codebase must be in **English**:

- All code identifiers (types, members, parameters, locals).
- All code comments (`//`, `/* */`, XML doc `///`).
- All log messages and structured log property names.
- All exception messages.
- All user-facing strings emitted by the libraries (error responses, problem details).
- All commit messages and PR descriptions.
- All `.md` files written for the public (README, package READMEs, XML doc output).
- All NuGet package metadata (`Description`, `PackageTags`, etc.).
- All test names and test data unless the test explicitly verifies non-ASCII handling.

Turkish is allowed **only** in:

- `Codex.local.md` if it exists (personal scratch, gitignored).
- Conversational replies to the user in this chat.

If you find existing Turkish content in the codebase, flag it and offer to convert it.

## Code style

- `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` is on — keep builds warning-free.
- Nullable reference types are enabled. No `!` null-forgiving without a comment justifying it.
- Prefer `sealed` on classes that aren't designed for inheritance.
- Use `ArgumentNullException.ThrowIfNull` / `ArgumentException.ThrowIfNullOrEmpty` for guard clauses.
- Use `TimeProvider` for time, never `DateTime.UtcNow` directly. The DI container registers `TimeProvider.System` by default; tests substitute `FakeTimeProvider`.
- Async methods take `CancellationToken cancellationToken = default` as the last parameter and use `.ConfigureAwait(false)` in library code.
- One public top-level type per file. File name matches the type.
- Namespaces follow folder structure (`Vefa.CustomAuth.<Project>.<Folder>`).

## Architecture rules

- **`Core`** holds models, store abstractions, options. No ASP.NET Core, no EF Core, no JWT references.
- **`Tokens`** depends on `Core` only. Handles signing keys, JWT issuance, hashing.
- **`AspNetCore`** depends on `Core` + `Tokens`. Endpoint handlers and DI extensions live here.
- **`EntityFrameworkCore`** depends on `Core` only. Provides EF-backed store implementations and `CustomAuthDbContext`.
- **`Server`** is the composition root that pulls everything together for the auth server scenario.
- Domain types in `Core` must not reference any concrete user model — go through `ICustomAuthUserStore`.
- Endpoint handlers must be minimal API (no MVC controllers).
- Public APIs that ship via NuGet need XML doc comments.

## Security rules (non-negotiable)

- PKCE is required by default.
- Authorization codes are single-use, short-lived (≤ 2 min), hashed in storage.
- Refresh tokens are opaque, hashed in storage, rotated on use.
- `redirect_uri` must match exactly — no prefix matching, no wildcard.
- Signing keys' private material never leaves the server; only public JWK is exposed.
- Never log secrets, raw tokens, authorization codes, passwords, or PII.

## Plan tracking

- [`plan.md`](plan.md) is the requirements roadmap. Each top-level numbered section represents a discrete deliverable.
- When a section is fully implemented, insert a `Status: completed` line directly under its heading.
- For partial progress, use `Status: partial — <short note in English>` and update the note as scope advances. Convert it to `completed` only when nothing in the section remains undone.
- Leave unstarted sections unmarked.
- Update the status marker in the same change that completes (or advances) the work, so `plan.md` always reflects reality.

## Workflow rules

- After meaningful changes, run `dotnet build` from the repo root and confirm 0 warnings / 0 errors before reporting done.
- Do not edit `obj/` or `bin/` output. If a Turkish string shows up there, fix the source (e.g. `Directory.Build.props`), not the generated file.
- Do not commit unless the user explicitly asks.
- Do not push, force-push, or amend commits unless explicitly asked.
- Prefer adding new files over rewriting existing ones when extending; prefer editing over rewriting when modifying.
