# Staging Rollout Checklist (Real Network Scan)

## Prerequisites
- Install `nmap` on the Flask host and verify with `nmap --version`.
- Set `REAL_SCAN_ENABLED=true` only in staging first.
- Configure `SCAN_ALLOWED_CIDRS` to internal lab CIDRs only.
- Set `SCAN_TIMEOUT_SEC` and `SCAN_MAX_TARGETS` to conservative values.

## Safety Controls
- Confirm scanner account has least privilege needed for selected profile.
- Validate `/api/v1/scan/trigger` rejects CIDRs outside allowlist.
- Confirm concurrent scan trigger returns controlled error.

## Functional Validation
- Trigger real scan from dashboard and watch `/api/v1/scan/status`.
- Verify discovered devices are updated in `devices` table.
- Verify `scan_result` rows are created with parsed port findings.
- Verify enrichment creates/links vulnerabilities and patches.
- Verify known exploited CVEs generate critical alerts.

## Rollback
- Set `REAL_SCAN_ENABLED=false` to switch back to simulation immediately.
- Keep simulation endpoint behavior available during rollout period.
