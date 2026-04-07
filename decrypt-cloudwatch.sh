#!/usr/bin/env bash
#
# Decrypts all secure_json_data fields for CloudWatch datasources in Grafana.
#
# Prerequisites: mysql (or psql/sqlite3), jq, and the secretdecrypt Go tool.
#
# Usage:
#   ./tools/secretdecrypt/decrypt-cloudwatch.sh \
#     -s <secret_key> \
#     -d <db_type>       (mysql|postgres|sqlite) \
#     -h <db_host>       (mysql/postgres only) \
#     -P <db_port>       (mysql/postgres only) \
#     -u <db_user>       (mysql/postgres only) \
#     -p <db_password>   (mysql/postgres only) \
#     -n <db_name>       (database name or sqlite file path)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

SECRET_KEY=""
DB_TYPE="mysql"
DB_HOST="127.0.0.1"
DB_PORT=""
DB_USER="grafana"
DB_PASS=""
DB_NAME="grafana"

usage() {
    cat <<EOF
Usage: $0 -s <secret_key> [options]

Required:
  -s    Grafana secret_key (from [security] section in grafana.ini)

Database options:
  -d    Database type: mysql (default), postgres, sqlite
  -h    Database host (default: 127.0.0.1)
  -P    Database port (default: 3306/5432)
  -u    Database user (default: grafana)
  -p    Database password
  -n    Database name or sqlite file path (default: grafana)

Example:
  $0 -s 'SW2YcwTIb9zpOO' -d mysql -h db.example.com -u grafana -p secret -n grafana
  $0 -s 'SW2YcwTIb9zpOO' -d sqlite -n /var/lib/grafana/grafana.db
EOF
    exit 1
}

while getopts "s:d:h:P:u:p:n:" opt; do
    case $opt in
        s) SECRET_KEY="$OPTARG" ;;
        d) DB_TYPE="$OPTARG" ;;
        h) DB_HOST="$OPTARG" ;;
        P) DB_PORT="$OPTARG" ;;
        u) DB_USER="$OPTARG" ;;
        p) DB_PASS="$OPTARG" ;;
        n) DB_NAME="$OPTARG" ;;
        *) usage ;;
    esac
done

if [[ -z "$SECRET_KEY" ]]; then
    echo "error: -s <secret_key> is required" >&2
    usage
fi

for cmd in jq go; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: '$cmd' is required but not found in PATH" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Database query helpers
# ---------------------------------------------------------------------------
run_query() {
    local query="$1"
    case "$DB_TYPE" in
        mysql)
            local port="${DB_PORT:-3306}"
            mysql -h "$DB_HOST" -P "$port" -u "$DB_USER" ${DB_PASS:+-p"$DB_PASS"} \
                  -N -B "$DB_NAME" -e "$query"
            ;;
        postgres)
            local port="${DB_PORT:-5432}"
            PGPASSWORD="${DB_PASS}" psql -h "$DB_HOST" -p "$port" -U "$DB_USER" \
                  -d "$DB_NAME" -t -A -F $'\t' -c "$query"
            ;;
        sqlite)
            sqlite3 -separator $'\t' "$DB_NAME" "$query"
            ;;
        *)
            echo "error: unsupported db type '$DB_TYPE'" >&2
            exit 1
            ;;
    esac
}

# Query to get encrypted_data for a given data key ID.
# Returns hex-encoded encrypted_data.
get_dek_hex() {
    local key_id="$1"
    local query
    case "$DB_TYPE" in
        mysql)
            query="SELECT HEX(encrypted_data) FROM data_keys WHERE id = '${key_id}';"
            ;;
        postgres)
            query="SELECT encode(encrypted_data, 'hex') FROM data_keys WHERE id = '${key_id}';"
            ;;
        sqlite)
            query="SELECT hex(encrypted_data) FROM data_keys WHERE id = '${key_id}';"
            ;;
    esac
    run_query "$query" | tr -d '[:space:]'
}

# ---------------------------------------------------------------------------
# Locate the pre-built decrypter binary for the current OS/arch
# ---------------------------------------------------------------------------
DIST_DIR="$SCRIPT_DIR/dist"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')    # linux, darwin
ARCH=$(uname -m)                                 # x86_64, aarch64, arm64

case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "error: unsupported architecture '$ARCH'" >&2; exit 1 ;;
esac

SUFFIX=""
if [[ "$OS" == "windows"* || "$OS" == "mingw"* || "$OS" == "msys"* ]]; then
    OS="windows"
    SUFFIX=".exe"
fi

DECRYPTER="$DIST_DIR/secretdecrypt-${OS}-${ARCH}${SUFFIX}"

if [[ ! -x "$DECRYPTER" ]]; then
    echo "Pre-built binary not found at $DECRYPTER" >&2
    echo "Falling back to 'go build'..." >&2
    DECRYPTER="$SCRIPT_DIR/secretdecrypt"
    (cd "$REPO_ROOT" && go build -o "$DECRYPTER" ./tools/secretdecrypt/)
else
    echo "Using pre-built binary: $DECRYPTER" >&2
fi

# ---------------------------------------------------------------------------
# Cache for data key lookups: key_id -> dek_hex
# ---------------------------------------------------------------------------
declare -A DEK_CACHE

get_cached_dek() {
    local key_id="$1"
    if [[ -n "${DEK_CACHE[$key_id]+x}" ]]; then
        echo "${DEK_CACHE[$key_id]}"
        return
    fi
    local dek_hex
    dek_hex=$(get_dek_hex "$key_id")
    if [[ -z "$dek_hex" ]]; then
        echo "error: no data_keys row found for id='$key_id'" >&2
        return 1
    fi
    DEK_CACHE[$key_id]="$dek_hex"
    echo "$dek_hex"
}

# ---------------------------------------------------------------------------
# Extract the data key ID from a base64 ciphertext without calling Go.
# Envelope format: #<base64-raw(key_id)>#<payload>
# ---------------------------------------------------------------------------
extract_key_id() {
    local b64_ciphertext="$1"
    # Decode base64 to raw bytes, grab between first pair of '#' delimiters.
    local raw
    raw=$(echo -n "$b64_ciphertext" | base64 -d 2>/dev/null | xxd -p | tr -d '\n')

    # Check first byte is '#' (0x23).
    if [[ "${raw:0:2}" != "23" ]]; then
        echo ""  # legacy, no key id
        return
    fi

    # Find second '#' (0x23) after the first byte.
    local rest="${raw:2}"
    local pos=0
    while [[ $pos -lt ${#rest} ]]; do
        local byte="${rest:$pos:2}"
        if [[ "$byte" == "23" ]]; then
            break
        fi
        pos=$((pos + 2))
    done

    if [[ $pos -ge ${#rest} ]]; then
        echo ""
        return
    fi

    # Bytes between first and second '#' are base64-raw-encoded key ID.
    local key_id_b64_hex="${rest:0:$pos}"
    local key_id_b64
    key_id_b64=$(echo -n "$key_id_b64_hex" | xxd -r -p)
    # Base64-raw decode to get the actual key ID string.
    # Add padding if needed for standard base64 decode.
    local padded="$key_id_b64"
    local mod=$((${#padded} % 4))
    if [[ $mod -eq 2 ]]; then padded="${padded}=="; fi
    if [[ $mod -eq 3 ]]; then padded="${padded}="; fi
    echo -n "$padded" | base64 -d 2>/dev/null
}

# ---------------------------------------------------------------------------
# Main: query all CloudWatch datasources and decrypt their secrets
# ---------------------------------------------------------------------------
echo "==========================================" >&2
echo " Decrypting CloudWatch datasource secrets" >&2
echo "==========================================" >&2
echo "" >&2

QUERY="SELECT id, name, secure_json_data FROM data_source WHERE type = 'cloudwatch';"

run_query "$QUERY" | while IFS=$'\t' read -r ds_id ds_name sjd; do
    # Skip empty secure_json_data.
    if [[ -z "$sjd" || "$sjd" == "{}" || "$sjd" == "null" ]]; then
        echo "[$ds_name] (id=$ds_id): no secure_json_data, skipping" >&2
        continue
    fi

    echo "" >&2
    echo "──────────────────────────────────────────" >&2
    echo "Datasource: $ds_name (id=$ds_id)" >&2
    echo "──────────────────────────────────────────" >&2

    # Output header for this datasource.
    echo "=== Datasource: $ds_name (id=$ds_id) ==="

    # Iterate over each key in the secure_json_data JSON.
    for field in $(echo "$sjd" | jq -r 'keys[]'); do
        b64_value=$(echo "$sjd" | jq -r --arg k "$field" '.[$k]')

        if [[ -z "$b64_value" || "$b64_value" == "null" ]]; then
            echo "  $field: (empty)"
            continue
        fi

        echo "  Decrypting field: $field" >&2

        # Extract key ID to look up the DEK.
        key_id=$(extract_key_id "$b64_value")

        if [[ -n "$key_id" ]]; then
            # Envelope encryption — need the DEK.
            dek_hex=$(get_cached_dek "$key_id") || continue
            plaintext=$("$DECRYPTER" \
                -secret-key "$SECRET_KEY" \
                -ciphertext "$b64_value" \
                -encrypted-dek "$dek_hex" \
                -encoding base64 2>/dev/null) || plaintext="<DECRYPTION FAILED>"
        else
            # Legacy encryption — secret_key only.
            plaintext=$("$DECRYPTER" \
                -secret-key "$SECRET_KEY" \
                -ciphertext "$b64_value" \
                -encoding base64 2>/dev/null) || plaintext="<DECRYPTION FAILED>"
        fi

        echo "  $field: $plaintext"
    done

    echo ""
done

echo "Done." >&2
