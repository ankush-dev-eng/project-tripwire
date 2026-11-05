# Audit of Modifications to `lab/app.py`

This document provides a transparent, auditable log of every modification made to the benchmark target application (`lab/app.py`) across the lifecycle of the TRIPWIRE project, fulfilling the Honesty Rules specified in Section 10 of `PROJECT_TRIPWIRE.md`.

---

## Modification Summary

| Commit | Date | Area | Summary of Change | Motivation & Technical Rationale |
|---|---|---|---|---|
| `574e94e` | 2026-11-05 00:58 | Baseline Architecture | Initial creation of Voyager Mock B2B Travel Platform | Created FastAPI application with 26 seeded vulnerabilities, multi-tenant roles (Alpha, Beta, Admin), workflow state machine, and dynamic patch registry. |
| `a7137cd` | 2026-11-05 01:59 | Token Parsing (`get_current_user`) | Enforce token validation and explicit tenant dispatching | Replaced blanket fallback returning `USR_ALPHA_AGENT` for unknown tokens with explicit tenant checks (`"alpha"` vs `"beta"`), raising HTTP 401 for invalid tokens. Required to accurately simulate multi-tenant BOLA/BFLA authorization boundaries. |
| `2f9bf04` | 2026-11-05 02:33 | Auth Patch Toggle (`VULN-AUTH-02`) | Explicit 401 rejection for unsigned JWTs when patched | Restructured `none_alg_` check so that when `VULN-AUTH-02` is patched, the endpoint explicitly rejects the token with `HTTP 401 ("Unsigned 'none' algorithm token rejected")` rather than falling through to session lookup. |
| `6cb79f0` | 2026-11-05 03:56 | Token Precedence (`get_current_user`) | Prioritize `"beta"` substring over `"test"`/`"alpha"` | Fixed token evaluation order. Test tokens containing both `"test"` and `"beta"` (such as `"test_beta_session"`) were previously intercepted by `"test" in token`, inadvertently resolving to Alpha instead of Beta. |

---

## Detailed Commit Audit

### 1. Commit `574e94e` — Initial Application Scaffolding
- **Files**: `lab/app.py`
- **Scope**: Implemented mock distribution API simulating flights, bookings, pricing, ticketing, payments, refunds, documents, admin diagnostic routes, and shadow endpoints.
- **Seeded Flaws**: 26 real-world API security defects mapped to OWASP API Security Top 10 (2023).

### 2. Commit `a7137cd` — Multi-Tenant Token Parsing
- **Diff**:
  ```python
  -    # By default, authenticate as alpha agent for test simulation
  -    return db.users["USR_ALPHA_AGENT"]
  +    if "test" in token or "alpha" in token:
  +        return db.users["USR_ALPHA_AGENT"]
  +    if "beta" in token:
  +        return db.users["USR_BETA_AGENT"]
  +
  +    raise HTTPException(status_code=401, detail="Invalid or expired token")
  ```
- **Rationale**: Real DAST testing requires authenticating as Tenant A (Alpha) and attempting cross-tenant access to Tenant B (Beta) resources. Defaulting all unrecognized tokens to Alpha broke unauthorized BOLA detection by returning valid responses under the wrong tenant.

### 3. Commit `2f9bf04` — Deterministic Auth Patching
- **Diff**:
  ```python
  -    # VULN-AUTH-02: Check if unsigned JWT accepted
  -    if not PatchRegistry.is_patched("VULN-AUTH-02") and token.startswith("none_alg_"):
  -        # Simulated 'none' alg payload: none_alg_<user_id>
  -        user_id = token.replace("none_alg_", "")
  -        if user_id in db.users:
  -            return db.users[user_id]
  +    if token.startswith("none_alg_"):
  +        if not PatchRegistry.is_patched("VULN-AUTH-02"):
  +            # Simulated 'none' alg payload: none_alg_<user_id>
  +            user_id = token.replace("none_alg_", "")
  +            if user_id in db.users:
  +                return db.users[user_id]
  +        raise HTTPException(status_code=401, detail="Unsigned 'none' algorithm token rejected")
  ```
- **Rationale**: When the patch toggle for `VULN-AUTH-02` was activated, the server bypassed the unsigned token block but continued executing session checks, which could produce inconsistent status codes. The patch enforces an immediate 401 response when patched.

### 4. Commit `6cb79f0` — Substring Disambiguation in Multi-Tenant Tokens
- **Diff**:
  ```python
  -    if "test" in token or "alpha" in token:
  -        return db.users["USR_ALPHA_AGENT"]
       if "beta" in token:
           return db.users["USR_BETA_AGENT"]
  +    if "test" in token or "alpha" in token:
  +        return db.users["USR_ALPHA_AGENT"]
  ```
- **Rationale**: Disambiguated tenant token resolution so that `"beta"` tokens used during DAST attack scenarios are correctly parsed as Tenant Beta even when prefixed with `"test"`.

---

## Helper Scripts Elimination
In accordance with Section 10, all ephemeral helper patch scripts (`patch_*.py`) created during earlier debugging phases have been permanently removed. All test runs and benchmarks execute directly through supported public APIs and test harnesses.
