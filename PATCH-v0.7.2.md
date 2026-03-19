# ai-rsk v0.7.2 - Patch Notes - Bugfix: crates.io API

## Bug Fixed

### `ai-rsk update` and version check failed for all users

**Symptom:** `ai-rsk update` returned "Could not reach crates.io. Check your internet connection." even with a working internet connection.

**Root cause:** crates.io API requires a `User-Agent` HTTP header. Without it, the server returns HTTP 403 (Forbidden). The `curl` command in `fetch_latest_version()` did not include this header. The `-sf` flags (silent + fail) caused the 403 to be silently swallowed, making it look like a network error.

**Additionally:** The timeout was set to 3 seconds, which could be too short on slow connections or when IPv6 resolution takes time.

**Fix:**
- Added `-H "User-Agent: ai-rsk"` to the curl command
- Increased timeout from 3s to 5s

**File changed:** `src/version.rs` (line 224)

**Before:**
```
curl -sfL --max-time 3 https://crates.io/api/v1/crates/ai-rsk
```

**After:**
```
curl -sfL --max-time 5 -H "User-Agent: ai-rsk" https://crates.io/api/v1/crates/ai-rsk
```

## Impact

This bug affected both:
- `ai-rsk update` (the new self-update command from v0.7.1)
- `check_for_update()` (the automatic version check at the start of every scan)

Both features were non-functional in v0.7.0 and v0.7.1 for all users.

## Testing

| Test | Result |
|---|---|
| `ai-rsk update` (up to date) | "ai-rsk 0.7.2 is already the latest version." |
| `ai-rsk update` (outdated) | Detects newer version, installs via cargo |
| `cargo test` | 187 passed |
| `cargo clippy` | 0 warnings |
| `cargo fmt` | 0 diff |
| CI (ubuntu, macos, windows) | All green |

## Why this was missed

The version check and update were tested in a sandboxed environment without real network access. The test showed "Could not reach crates.io" and was incorrectly marked as "expected behavior in sandbox." A real test on a machine with internet access would have caught the 403 immediately. This is a testing failure.
