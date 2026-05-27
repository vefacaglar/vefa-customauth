# CLAUDE.md

Project-specific rules for Claude when working on **Vefa.CustomAuth**.

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

- `CLAUDE.local.md` if it exists (personal scratch, gitignored).
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
