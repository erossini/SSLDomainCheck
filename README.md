# TLS Certificate CA Checker

Checks the TLS certificate chain of every URL in a list and flags any chain that involves an **eMudhra / emSign** certificate authority. The results go into a Markdown report (`ca-report.md`).

**Repository:** [github.com/erossini/PythonCheck](https://github.com/erossini/PythonCheck)

## Background

This tool was written during the investigation into the **eMudhra / emSign CA security incident**. The Python Software Foundation's announcement is here: [Information for Python users regarding eMudhra/emSign CA certificate security incident](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576) (discuss.python.org, 20 October 2026).

According to that thread:

- **What happened:** the private keys of eMudhra's intermediate CA certificates were insecure, and those intermediates were declared compromised and revoked. Clients that still trust them could be hit by man-in-the-middle attacks on TLS, including connections to python.org and pypi.org.
- **Response:**
  - The emSign root CA was removed from **certifi**. The fixed version is `2026.10.19`.
  - New Python releases reject the compromised intermediates: **3.15.2, 3.14.10, 3.13.18, 3.12.16 and 3.11.18**.
  - Tools that bundle their own certificates were also updated, for example **pip 26.2.2** and **uv 0.13.6**.
  - The full list of fixed versions is in the announcement.

This creates two separate jobs:

1. **Client side:** upgrade Python, pip, certifi and the related tools as the announcement describes. This README doesn't cover that.
2. **Server side:** find any service you depend on that still uses an eMudhra / emSign certificate chain. Patched clients will stop trusting it, and unpatched clients are exposed. **This tool does the server-side check.**

The tool flags *any* chain that includes an eMudhra / emSign CA, not only the specific compromised intermediates. If you need an exact match, set the affected pattern to the intermediate names from eMudhra's disclosure.

## Scripts

There are two versions of the script, and they produce the same report:

| Script | Runs on | Needs |
|---|---|---|
| `Check-CertificateCA.ps1` | Windows PowerShell 5.1, PowerShell 7+ (Windows, macOS, Linux) | Nothing extra |
| `check-certificate-ca.sh` | macOS (stock bash 3.2), Linux | `openssl` (or LibreSSL) and `perl` |

## Getting the code

Clone the repository and go into its folder:

```bash
git clone https://github.com/erossini/PythonCheck.git
cd PythonCheck
```

Or download it as a ZIP from the [repository page](https://github.com/erossini/PythonCheck) (**Code** > **Download ZIP**).

## Quick start

1. Add the services to check to `urls.txt` (see [Input file](#input-file)).
2. Run one of the scripts:

   **PowerShell**
   ```powershell
   .\Check-CertificateCA.ps1
   ```

   **bash**
   ```bash
   chmod +x check-certificate-ca.sh
   ./check-certificate-ca.sh
   ```

3. Open `ca-report.md`.

If `urls.txt` isn't in the current folder, both scripts look for it next to the script.

## Input file

Put one entry on each line, with an optional service name after a `|`:

```text
# Lines starting with # and blank lines are ignored
https://api.example.com/path | Payments API
api.example.com
api.example.com:8443         | Admin portal
```

- An entry can be a full URL, a bare domain or `domain:port`. The path and query string are ignored.
- The default port is 443. An `http://` URL with no port is also checked on 443.
- If an entry has no service name, the report shows `-`.

## Options

**PowerShell**

```powershell
.\Check-CertificateCA.ps1 -InputFile .\urls.txt -OutputFile .\report.md -TimeoutSeconds 5 -AffectedPattern 'emSign|eMudhra'
```

| Parameter | Default | Description |
|---|---|---|
| `-InputFile` | `urls.txt` | List of URLs to check |
| `-OutputFile` | `ca-report.md` | Where the report is written |
| `-TimeoutSeconds` | `10` | Timeout for each host |
| `-AffectedPattern` | `emSign\|eMudhra` | Regex that marks a CA as affected (case-insensitive) |

**bash**

```bash
./check-certificate-ca.sh [input-file] [output-file]
TIMEOUT=5 AFFECTED_PATTERN='emsign|emudhra|other-ca' ./check-certificate-ca.sh urls.txt report.md
```

| Setting | Default | Description |
|---|---|---|
| 1st argument | `urls.txt` | List of URLs to check |
| 2nd argument | `ca-report.md` | Where the report is written |
| `TIMEOUT` | `10` | Timeout in seconds for each host |
| `AFFECTED_PATTERN` | `emsign\|emudhra` | Extended regex that marks a CA as affected (case-insensitive) |

To flag more CAs, such as other intermediates named in an incident advisory, add their names to the pattern.

## How it works

For each entry, the script:

1. Opens a TLS connection with SNI and collects the certificate chain. It **does not enforce trust**, so expired or untrusted chains are still inspected.
2. Reports the **Issuing CA** (the leaf certificate's issuer) and the **Root CA** (the top certificate if it is self-signed, otherwise that certificate's issuer).
3. Matches the pattern against every issuer in the chain and the subject of every non-leaf certificate. The leaf's own subject is skipped, so a site such as `emsign.com` that has a certificate from another CA isn't flagged.
4. Lists the matching CA names in the **Affected** column.

### Differences between the two scripts

- The bash script uses only the certificates the **server sends** (`openssl s_client -showcerts`).
- The PowerShell script uses the chain that **.NET builds** with the local trust store, so the Root CA can come from the machine's store even when the server doesn't send it.

On a few servers this can make the Root CA column differ between the two versions. The affected/not affected result is normally the same.

## Report format

```markdown
# TLS Certificate CA Report

Generated: 2026-11-09 15:38:12
Affected pattern: `emSign|eMudhra`
Checked: 13 - Affected: 4 - Errors: 0

| Service | Domain | Issuing CA | Root CA | Affected (eMudhra / emSign) |
|---|---|---|---|---|
| PyPI package index | pypi.org | GlobalSign Atlas R3 DV TLS CA 2025 Q4 | GlobalSign | No |
| ICAR (test - emSign) | icar.gov.in | EM DV TLS CA - G2A-1 | emSign Root CA - G1 | **YES** (EM DV TLS CA - G2A-1, emSign Root TLS CA - G1, emSign Root CA - G1) |
```

If a host can't be reached (DNS failure, connection refused or timeout), its row shows `ERROR: <reason>` and counts towards **Errors**. The other hosts are still checked.

> The scripts always exit with code 0 once the report is written, whatever they find. To use them in CI, read the `Affected:` count in the report.

## Test entries

`urls.txt` includes four domains that were confirmed on 2026-11-09 to use an emSign chain (`icar.gov.in`, `eagleconsulting.co.in`, `erp.vaamaa.com`, `imageinfosystems.com`). They should show **YES** and are there to check that detection works. Remove them before you run a real audit, or keep them as a control.

## Files

| File | Purpose |
|---|---|
| `Check-CertificateCA.ps1` | PowerShell version |
| `check-certificate-ca.sh` | bash version |
| `urls.txt` | Input list of URLs and service names |
| `ca-report.md` | The latest generated report |

## References

- [erossini/PythonCheck](https://github.com/erossini/PythonCheck): source code for this tool
- [Information for Python users regarding eMudhra/emSign CA certificate security incident](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576): the PSF announcement and discussion
- [eMudhra incident disclosure](https://emudhra.we-have-a-problem.com/): linked from the announcement
- [python/cpython#160040](https://github.com/python/cpython/issues/160040): "ssl: distrust compromised eMudhra intermediate CA keys"
