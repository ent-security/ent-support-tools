# ent support tools

Small, self-contained diagnostics you can run on your own machines to check and
troubleshoot connectivity to your ent tenant. Everything here is **read-only** and
sends **no credentials** — the scripts only inspect network reachability and TLS.

## Tools

| Tool | What it's for |
|------|---------------|
| [`connectivity-check/verify-ent-connectivity.sh`](connectivity-check/verify-ent-connectivity.sh) | Verify a workstation can reach your ent tenant admin API, and diagnose the common case where the portal loads but data never appears (usually a corporate TLS-inspection / Zero-Trust proxy). |
| [`connectivity-check/Test-PlatformConnectivity.ps1`](connectivity-check/Test-PlatformConnectivity.ps1) | Verify a Windows endpoint can reach the ent platform. Checks DNS, TCP, TLS, and the platform health endpoint, and reports which stage fails. |

---

## Admin API Connectivity check (verify-ent-connectivity.sh)

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

## Platform connectivity check (Test-PlatformConnectivity.ps1)

If an endpoint isn't reporting to the ent platform, this script tells you **which
stage** of the connection is failing: name resolution, the network path, the TLS
handshake, or the platform itself.

### Requirements

- Windows PowerShell 5.1 or later. No installation and no administrator rights needed.

### Get it

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/ent-security/ent-support-tools/main/connectivity-check/Test-PlatformConnectivity.ps1 -OutFile Test-PlatformConnectivity.ps1
```

…or clone the repo and run it from `connectivity-check\`.

### Run it

```powershell
.\Test-PlatformConnectivity.ps1 -Address <platform-host> [-Port <port>]
```

- `-Address` — the platform hostname or IP the endpoint reports to. This is the
  `address` of the server entry in the agent configuration.
- `-Port` — optional; defaults to `443`.
- `-ConfigJson <path>` — optional; read the address and port from the first server
  entry of an agent configuration file instead of passing them.
- `-TimeoutSec <n>` — optional; per-stage timeout, defaults to `5`.

Examples:

```powershell
.\Test-PlatformConnectivity.ps1 -Address platform.example.com
.\Test-PlatformConnectivity.ps1 -ConfigJson C:\path\to\config.json
```

If PowerShell reports that running scripts is disabled on this system, allow local
scripts for your user account (no administrator rights needed):

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

If the script was downloaded through a browser, Windows may still block it. Clear
that with `Unblock-File .\Test-PlatformConnectivity.ps1`.

If your organization's policy prevents changing the execution policy, run the script
for a single session instead:
`powershell -ExecutionPolicy Bypass -File .\Test-PlatformConnectivity.ps1 -Address <platform-host>`.

### Reading the output

The script prints the machine's proxy settings, then checks each stage and prints
`PASS` or `FAIL` with a hint when one fails. Exit code is `0` if every check passed
and `1` otherwise.

| Stage | What it checks |
|-------|----------------|
| `DNS` | The address resolves to an IP. |
| `TCP` | A connection to the port succeeds. A timeout usually means a firewall is dropping traffic; "actively refused" means nothing is listening there. |
| `TLS` | The TLS handshake completes. Shows the protocol, the server certificate's subject, issuer and expiry, and whether this machine trusts it. A certificate issued by a corporate or proxy CA means HTTPS inspection is in the path. |
| `HEALTH` | An unauthenticated `GET /health` returns a 2xx status. A 5xx means the platform behind the network path is unhealthy; a 407 means an authenticating proxy is blocking the request. |

### Safety

The script only opens a connection and issues a single unauthenticated `GET /health`.
It sends no credentials, stores nothing, and changes nothing.

---

## Support

Share the full output of the script with your ent point of contact — it captures
everything needed to pinpoint the issue.

## License

[Apache License 2.0](LICENSE). Copyright 2026 Ent Security, Inc.
