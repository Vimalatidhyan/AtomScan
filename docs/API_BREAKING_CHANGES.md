# API Breaking Changes

This document records all API-level breaking changes introduced during the production-hardening program.

---

## Auth Endpoint Changes

### HTTP 403 → 401 for Missing/Invalid API Keys

**Previous behaviour**: Missing or invalid API key returned `403 Forbidden`.
**New behaviour**: Returns `401 Unauthorized`.

**Affected endpoints**: All endpoints except `/health`, `/version`, `/docs`, `/openapi.json`, `/redoc`.

**Reason**: RFC 7235 — 401 means "not authenticated"; 403 means "authenticated but not authorised". The API uses API keys for identity, not role gating.

**Migration**: Update client code that checks `response.status_code == 403` for auth errors to check `== 401`.

---

## API Key Format Enforcement

**Previous behaviour**: Any string was accepted as an API key.
**New behaviour**: Keys must be 32–64 alphanumeric characters (validated before any DB lookup).

**Error response** (`401`):
```json
{"detail": "Invalid API key format"}
```

**Migration**: Re-generate any API keys shorter than 32 characters or containing non-alphanumeric characters.

---

## Findings — PUT replaces PATCH

**Previous behaviour**: `PATCH /api/v1/findings/{id}` was used for partial updates.
**New behaviour**: `PUT /api/v1/findings/{id}` is the canonical update endpoint.

**Migration**: Change client calls from `PATCH` to `PUT`.

---

## Vulnerability Model — `status` Field Added

**Previous behaviour**: `Vulnerability` objects had no `status` field.
**New behaviour**: `status` is a `VARCHAR(50)` column, default `"open"`.

**Allowed values**: `"open"`, `"in_progress"`, `"resolved"`, `"false_positive"` (enforced at application layer).

**Migration**: Existing rows have `status = "open"` applied by migration `002`.

---

## CSRF Exempt Path Updates

**Previous behaviour**: Exempt paths were prefixed `/api/webhooks/` and `/api/stream/`.
**New behaviour**: Exempt paths are prefixed `/api/v1/webhooks/` and `/api/v1/stream/`.

**Impact**: Webhook integrations calling the old paths without CSRF tokens will receive `403 Forbidden` until updated to the versioned paths.

---

## `X-API-Key` / Bearer Requests Bypass CSRF

**Previous behaviour**: CSRF was enforced even for API-key-authenticated requests.
**New behaviour**: Requests presenting a valid `X-API-Key` or `Authorization: Bearer` header skip CSRF validation entirely.

**Impact**: Programmatic clients no longer need to obtain or send CSRF tokens.

---

## Nuclei Scan — Template Auto-Update Disabled

**Previous behaviour**: Every vulnerability scan triggered `nuclei -update-templates`.
**New behaviour**: Template update only runs when `TECHNIEUM_NUCLEI_UPDATE=true` is set in the environment.

**Default**: `false` — templates are not auto-updated.

**Impact**: Operators who relied on automatic template updates must either set the env var or update templates manually with `nuclei -update-templates`.

---

## Scan Run — Field Renames

| Old field | New field | Notes |
|-----------|-----------|-------|
| `target` | `domain` | Renamed for clarity |
| `current_phase` | _(removed)_ | Use SSE stream for real-time phase info |
| `progress_percentage` | _(removed)_ | Use SSE stream for progress |
| `started_at` | _(removed)_ | Use `created_at` |

---

## Pydantic Model Config

`class Config: from_attributes = True` replaced with `model_config = ConfigDict(from_attributes=True)` across all response schemas. This is a Pydantic v2 internal change with no wire-format impact.
