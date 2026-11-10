#!/usr/bin/env bash
#
# Checks the TLS certificate chain of every URL in a list and flags chains issued by
# eMudhra / emSign CAs. Writes the results as a Markdown table.
#
# Works with the stock macOS bash 3.2, openssl (LibreSSL) and perl.
#
# Usage:
#   chmod +x check-certificate-ca.sh
#   ./check-certificate-ca.sh                      # reads urls.txt, writes ca-report.md
#   ./check-certificate-ca.sh urls.txt [ca-report.md]
#
# Environment overrides:
#   TIMEOUT=5 ./check-certificate-ca.sh urls.txt
#   AFFECTED_PATTERN='emsign|emudhra|other-ca' ./check-certificate-ca.sh urls.txt
#
# The input file has one entry per line, with an optional service name after a pipe:
#   https://api.example.com/path | Payments API
#   api.example.com
#   api.example.com:8443 | Admin portal
# Blank lines and lines starting with # are ignored.

set -u

# Defaults to urls.txt in the current folder, or next to this script if not found there.
INPUT="${1:-urls.txt}"
OUTPUT="${2:-ca-report.md}"
if [ ! -f "$INPUT" ] && [ "${INPUT#/}" = "$INPUT" ] && [ -f "$(dirname "$0")/$INPUT" ]; then
  INPUT="$(dirname "$0")/$INPUT"
fi
TIMEOUT="${TIMEOUT:-10}"
# Extended regex, matched case-insensitively against the subject and issuer of every certificate in the chain.
AFFECTED_PATTERN="${AFFECTED_PATTERN:-emsign|emudhra}"

[ -f "$INPUT" ] || { echo "Input file not found: $INPUT (usage: $0 [url-list-file] [output.md])" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl not found" >&2; exit 1; }
command -v perl >/dev/null 2>&1 || { echo "perl not found" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# "https://user@host:8443/path?q" -> "host 8443"
parse_target() {
  local s="$1"
  case "$s" in *://*) s="${s#*://}" ;; esac
  s="${s%%/*}"
  s="${s%%\?*}"
  s="${s##*@}"
  local host="${s%%:*}" port=443
  case "$s" in *:*) port="${s##*:}" ;; esac
  echo "$host $port"
}

# Prints the CN of the subject or issuer ($1 = subject|issuer) of cert file $2; falls back to O, then the full DN.
name_of() {
  local dn val
  dn="$(openssl x509 -noout "-$1" -nameopt RFC2253 -in "$2" 2>/dev/null | sed -E 's/^(subject|issuer)= *//')"
  val="$(printf '%s\n' "$dn" | grep -o 'CN=[^,]*' | head -n 1 | sed 's/^CN=//')"
  [ -z "$val" ] && val="$(printf '%s\n' "$dn" | grep -o 'O=[^,]*' | head -n 1 | sed 's/^O=//')"
  [ -z "$val" ] && val="$dn"
  printf '%s' "$val"
}

full_dn() {
  openssl x509 -noout "-$1" -nameopt RFC2253 -in "$2" 2>/dev/null | sed -E 's/^(subject|issuer)= *//'
}

md_escape() { printf '%s' "$1" | sed 's/|/\\|/g' | tr '\r\n' '  '; }

ROWS="$TMP/rows.md"
: > "$ROWS"
checked=0
affected=0
errors=0

while IFS= read -r line || [ -n "$line" ]; do
  line="$(printf '%s' "$line" | tr -d '\r' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  case "$line" in ''|\#*) continue ;; esac
  checked=$((checked + 1))

  # Optional service name after a pipe: "https://pypi.org/simple/ | PyPI"
  target="$(printf '%s' "${line%%|*}" | sed -E 's/[[:space:]]+$//')"
  service="-"
  case "$line" in
    *"|"*) service="$(printf '%s' "${line#*|}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
           [ -z "$service" ] && service="-" ;;
  esac

  set -- $(parse_target "$target")
  host="$1"; port="$2"
  if [ "$port" = "443" ]; then domain="$host"; else domain="$host:$port"; fi
  printf 'Checking %s ... ' "$domain"

  rm -f "$TMP"/cert*.pem
  # perl alarm provides a timeout (macOS has no `timeout` command by default).
  perl -e 'alarm shift; exec @ARGV' "$TIMEOUT" \
    openssl s_client -connect "$host:$port" -servername "$host" -showcerts </dev/null 2>"$TMP/err" |
    awk -v dir="$TMP" '
      /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/cert%02d.pem", dir, n) }
      f != "" { print > f }
      /-----END CERTIFICATE-----/ { close(f); f = "" }'

  certs=$(ls "$TMP"/cert*.pem 2>/dev/null | sort)
  if [ -z "$certs" ]; then
    errors=$((errors + 1))
    msg="$(grep -iE 'error|errno|refused|unknown|timed|alarm' "$TMP/err" | head -n 1)"
    [ -z "$msg" ] && msg="no certificate received (timeout or connection failure)"
    echo "ERROR: $msg"
    printf '| %s | %s | - | - | ERROR: %s |\n' "$(md_escape "$service")" "$(md_escape "$domain")" "$(md_escape "$msg")" >> "$ROWS"
    continue
  fi

  leaf="$(printf '%s\n' "$certs" | head -n 1)"
  top="$(printf '%s\n' "$certs" | tail -n 1)"
  issuing_ca="$(name_of issuer "$leaf")"
  # If the top certificate is self-signed it is the root; otherwise the root is its issuer.
  if [ "$(full_dn subject "$top")" = "$(full_dn issuer "$top")" ]; then
    root_ca="$(name_of subject "$top")"
  else
    root_ca="$(name_of issuer "$top")"
  fi

  # Only CA names matter: every issuer, plus the subject of every non-leaf certificate.
  # (The leaf subject is the site itself, e.g. *.emsign.com, which is not a CA.)
  hits=""
  for c in $certs; do
    if [ "$c" = "$leaf" ]; then fields="issuer"; else fields="subject issuer"; fi
    for field in $fields; do
      if full_dn "$field" "$c" | grep -Eiq "$AFFECTED_PATTERN"; then
        n="$(name_of "$field" "$c")"
        case ", $hits, " in *", $n, "*) ;; *) hits="${hits:+$hits, }$n" ;; esac
      fi
    done
  done

  if [ -n "$hits" ]; then
    affected=$((affected + 1))
    status="**YES** ($hits)"
    echo "AFFECTED"
  else
    status="No"
    echo "ok"
  fi
  printf '| %s | %s | %s | %s | %s |\n' "$(md_escape "$service")" "$(md_escape "$domain")" "$(md_escape "$issuing_ca")" \
    "$(md_escape "$root_ca")" "$(md_escape "$status")" >> "$ROWS"
done < "$INPUT"

{
  echo "# TLS Certificate CA Report"
  echo
  echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')  "
  echo "Affected pattern: \`$AFFECTED_PATTERN\`  "
  echo "Checked: $checked - Affected: $affected - Errors: $errors"
  echo
  echo "| Service | Domain | Issuing CA | Root CA | Affected (eMudhra / emSign) |"
  echo "|---|---|---|---|---|"
  cat "$ROWS"
} > "$OUTPUT"

echo
echo "Report written to $OUTPUT"
