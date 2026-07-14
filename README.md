# ent support tools

Small, self-contained diagnostics you can run on your own machines to check and
troubleshoot connectivity to your ent tenant. Everything here is **read-only** and
sends **no credentials** — the scripts only inspect network reachability and TLS.

## Tools

| Tool | What it's for |
|------|---------------|
| [`connectivity-check/verify-ent-connectivity.sh`](connectivity-check/verify-ent-connectivity.sh) | Verify a workstation can reach your ent tenant admin API, and diagnose the common case where the portal loads but data never appears (usually a corporate TLS-inspection / Zero-Trust proxy). |

---

## Connectivity check

If the ent operator portal loads but pages stay empty — endpoints, users, or
activity show zeros, or you see `CORS request did not succeed` errors in the
browser console — this script tells you **where** the connection is breaking and
**how to fix it**.

The usual cause is a corporate secure-web-gateway / Zero-Trust proxy (Cloudflare,
Zscaler, Netskope, Palo Alto, …) that inspects HTTPS traffic by re-signing it with
its own certificate. Browsers that don't trust that certificate — Firefox in
particular, which keeps its own trust store — reject every request to the tenant
API. This script detects exactly that and points at the fix.

### Requirements

- `bash` and `curl` (preinstalled on macOS and Linux).
- On Windows: run it under **WSL** or **Git Bash**.
- `openssl` is optional and only adds extra certificate detail.

### Get it

```bash
curl -fsSLO https://raw.githubusercontent.com/ent-security/ent-support-tools/main/connectivity-check/verify-ent-connectivity.sh
chmod +x verify-ent-connectivity.sh
```

…or clone the repo and run it from `connectivity-check/`.

### Run it

```bash
./verify-ent-connectivity.sh <your-admin-api-url> [portal-origin]
```

- `<your-admin-api-url>` — the API host your portal talks to. The easiest way to
  find it: open the portal, press **F12** → **Network** tab, reload, click any
  failing request, and copy its URL host. It looks like
  `https://admin.<cluster>.<tenant>.prod.ent.ai`.
- `[portal-origin]` — optional; the portal you sign in to. Defaults to
  `https://operator.ent.ai`.

Example:

```bash
./verify-ent-connectivity.sh https://admin.abc123def456.11111111-2222-3333-4444-555555555555.prod.ent.ai
```

### Reading the output

The script walks the connection stage by stage — DNS → TCP/TLS → **certificate
issuer** → CORS preflight → portal reachability — and prints `PASS` / `WARN` /
`FAIL` per stage, then a **verdict** with remediation. Exit code is `0` (clean),
`1` (problem found), or `2` (usage error).

The decisive line is the **certificate issuer**:

- Issued by **Amazon** → you're connecting directly to ent; the network path is clean.
- Issued by **Cloudflare / Zscaler / Netskope / Palo Alto / a corporate CA** → a
  TLS-inspection proxy is in the path. If a browser (especially Firefox) doesn't
  trust that proxy's certificate authority, that's why the portal fails.

### Common fix

If the script reports TLS inspection, ask your IT / proxy administrators to either:

- add a **do-not-inspect / TLS-decryption bypass** for `*.prod.ent.ai` (so the
  genuine certificate reaches the browser untouched), or
- distribute the proxy's inspection **CA certificate** to browsers — including
  Firefox, which needs it added to its own trust store (or
  `security.enterprise_roots.enabled` set to `true`).

A quick way to confirm it's the corporate network: try loading the portal from a
device off that network (e.g. a phone hotspot).

### Safety

The script only issues `GET` and `OPTIONS` requests to the endpoint you give it.
It sends no credentials, stores nothing, and changes nothing.

---

## Support

Share the full output of the script with your ent point of contact — it captures
everything needed to pinpoint the issue.

## License

[Apache License 2.0](LICENSE). Copyright 2026 Ent Security, Inc.
