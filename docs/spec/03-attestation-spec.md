# Attestation Specification

## Overview

Attestation is how AgentSSO verifies that an agent runtime is *what it claims
to be* — a specific codebase, running on a specific runtime, launched by a
specific host. It is the cryptographic substitute for a static API key: instead
of proving "I have a secret," the agent proves "I am this software, running on
this platform."

## Attestation Document

The attestation document is a **signed JWT-like envelope** (JWS, compact
serialization) produced by the agent runtime at session start and re-produced
on demand during continuous re-attestation.

### Header

```json
{
  "alg": "EdDSA",
  "typ": "agent-attestation+jwt",
  "kid": "host:runtime-host-001"
}
```

- `alg`: EdDSA (Ed25519) — signed by the **hosting platform's attestation
  key**, not by the agent itself.
- `kid`: Identifies the host/platform attestation key in the trusted runtime
  registry.

### Payload

```json
{
  "agent_id": "a:f3b7c1e2-89d4-4a6b-9c0e-7f2a1b8d3e5f",
  "codebase_hash": "sha256:a1b2c3d4...",
  "runtime_hash": "sha256:b2c3d4e5...",
  "started_at": "2026-07-10T01:14:00Z",
  "expires_at": "2026-07-10T01:29:00Z",
  "host_id": "runtime-host-001",
  "host_claims": {
    "platform": "opencode",
    "version": "0.5.0",
    "arch": "darwin/arm64",
    "git_commit": "abc1234"
  },
  "jti": "att_3f1c8d2e"
}
```

### Payload Fields

| Field | Type | Description |
|---|---|---|
| `agent_id` | string | Stable agent identity (UUID, prefixed `a:`) |
| `codebase_hash` | string | SHA-256 of the git tree SHA (deterministic codebase fingerprint) |
| `runtime_hash` | string | SHA-256 of runtime version + builder identity |
| `started_at` | string (ISO8601) | When the agent runtime started |
| `expires_at` | string (ISO8601) | When this attestation expires (≤15 min from `started_at`) |
| `host_id` | string | Hosting platform instance ID |
| `host_claims` | object | Platform-specific attestation claims (version, architecture, commit) |
| `jti` | string | Unique attestation ID — linked from AIT's `att_jti` claim |

### Codebase Hash (`cnp`)

The codebase hash is computed as:

```
codebase_hash = "sha256:" + hex(sha256(git_tree_sha_of_HEAD))
```

This is the SHA of the git tree object at `HEAD`, **not** a hash of all files.
This ensures:

- Deterministic across machines (same commit = same hash).
- Resistant to timestamp/mode noise.
- Cheap to compute (git cat-file).

### Runtime Hash (`rtm`)

The runtime hash is computed as:

```
runtime_hash = "sha256:" + hex(sha256(runtime_name + ":" + runtime_version + ":" + builder_id))
```

Where `builder_id` is the identity of the build system (e.g., a CI signing key
ID). This ensures two different builds of "opencode v0.5.0" produce different
hashes if built by different builders.

## Verification Flow

```
Agent Runtime                    aIdP
    │                             │
    │  1. POST /v1/attest          │
    │  body: attestation_doc (JWS) │
    │  ─────────────────────────► │
    │                             │
    │                      2. Extract kid from header
    │                      3. Lookup host_id in runtime registry
    │                      4. Verify Ed25519 signature
    │                      5. Check expires_at not expired
    │                      6. Check agent_id is registered
    │                      7. Check codebase_hash is in allowed set
    │                      8. Check runtime_hash is in allowed set
    │                             │
    │  9. Return AIT (JWT)         │
    │  ◄───────────────────────── │
    │                             │
```

## Trusted Runtime Registry

The registry is a Postgres table mapping `(host_id, host_public_key)` pairs
and their allowed `(codebase_hash, runtime_hash)` combinations.

```
agent_registrations:
  tenant_id        | text
  agent_id         | text    -- will be prefixed a:
  host_id          | text
  host_public_key  | bytea   -- Ed25519 public key
  allowed_codebases| text[]  -- allowed codebase_hash values
  allowed_runtimes | text[]  -- allowed runtime_hash values
  created_at       | timestamptz
  updated_at       | timestamptz
```

Only a human principal (via the admin UI) can register/modify this table.

## Continuous Re-Attestation

Every **N minutes** (default: 5), the aIdP requests re-attestation from the
agent runtime:

```
aIdP                           Agent Runtime
  │                                │
  │  1. POST /v1/reattest           │
  │     (authenticated via old AIT)  │
  │  ──────────────────────────►    │
  │                                │
  │                      2. Produce new attestation_doc
  │                                │
  │  3. New attestation_doc (JWS)   │
  │  ◄──────────────────────────    │
  │                                │
  │  4. Verify new attestation     │
  │  5. Compare codebase_hash +    │
  │     runtime_hash to old values │
  │                                │
  │  if match: refresh AIT          │
  │  if mismatch: revoke AIT       │
  │    (blocklist old jti)          │
  │    (deny new AIT issuance)      │
```

### Drift Detection

Drift is defined as any change in `codebase_hash` or `runtime_hash` between
the initial attestation and the re-attestation. Drift triggers:

1. Immediate revocation of the current AIT (`jti` blocklisted).
2. Refusal to issue a new AIT for the drifted config.
3. Audit log entry: `DRIFT_DETECTED` with old and new hashes.
4. Alert to the admin (webhook/email).

This protects against live-patching, dependency injection, or runtime
swapping during an active session.

## Key Pair Lifecycle

- **Host attestation keys** (Ed25519): generated by the hosting platform,
  registered in the runtime registry by an admin. Rotated annually or on
  platform compromise.
- **aIdP signing keys** (ES256): used for AIT/JIT issuance. Rotated every
  90 days. Published at JWKS endpoint.
- **Agent runtime keys**: none required. The agent does not hold a persistent
  key — it re-attests via its host platform's key each session.