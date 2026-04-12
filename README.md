# secretdecrypt

A standalone CLI tool to decrypt Grafana datasource credentials (`secure_json_data`) outside of Grafana.

## How Grafana encrypts datasource secrets

Grafana uses **envelope encryption** with two layers:

```
Plaintext credential
    |
    v
[Encrypt with DEK (AES-256-CFB, PBKDF2-SHA256)]
    |
    v
Ciphertext = *<b64(algorithm)>*<salt 8B><IV 16B><encrypted bytes>
    |
    v
Prepend envelope header: #<b64(data-key-id)>#<ciphertext>
    |
    v
Stored in data_source.secure_json_data (base64-encoded per field)
```

The **Data Encryption Key (DEK)** is itself encrypted with the **Key Encryption Key (KEK)**, which is derived from `secret_key` in Grafana's `[security]` config section. The encrypted DEK is stored in the `data_keys` table.

Legacy secrets (pre-envelope encryption) are encrypted directly with the `secret_key` and have no `#...#` prefix.

## Prerequisites

- Go 1.21+ (only for building from source)
- Access to the Grafana database (MySQL, PostgreSQL, or SQLite)
- The `secret_key` from Grafana's configuration

## Build

From the repository root:

```bash
# Current platform
go build -o tools/secretdecrypt/secretdecrypt ./tools/secretdecrypt/

# All platforms
GOOS=linux   GOARCH=amd64 go build -o tools/secretdecrypt/dist/secretdecrypt-linux-amd64       ./tools/secretdecrypt/
GOOS=linux   GOARCH=arm64 go build -o tools/secretdecrypt/dist/secretdecrypt-linux-arm64       ./tools/secretdecrypt/
GOOS=darwin  GOARCH=amd64 go build -o tools/secretdecrypt/dist/secretdecrypt-darwin-amd64      ./tools/secretdecrypt/
GOOS=darwin  GOARCH=arm64 go build -o tools/secretdecrypt/dist/secretdecrypt-darwin-arm64      ./tools/secretdecrypt/
GOOS=windows GOARCH=amd64 go build -o tools/secretdecrypt/dist/secretdecrypt-windows-amd64.exe ./tools/secretdecrypt/
GOOS=windows GOARCH=arm64 go build -o tools/secretdecrypt/dist/secretdecrypt-windows-arm64.exe ./tools/secretdecrypt/
```

No CGo dependencies -- binaries are fully static and portable.

## Usage

### Flags

| Flag | Required | Description |
|------|----------|-------------|
| `-secret-key` | Yes | `secret_key` from `[security]` section in `grafana.ini` |
| `-ciphertext` | Yes | Encrypted value (a single field from `secure_json_data`) |
| `-encrypted-dek` | For envelope | Hex-encoded `encrypted_data` from `data_keys` table |
| `-encoding` | No | Input encoding: `hex` (default) or `base64` |

### Decrypt a single value

**Step 1: Get the ciphertext from the database**

```sql
-- MySQL
SELECT name, secure_json_data FROM data_source WHERE name = 'my-datasource';

-- The secure_json_data column contains JSON like:
-- {"accessKey":"I1ltWmhNMl...","secretKey":"I0ZDUGt4Mk..."}
```

Each value in the JSON map is a base64-encoded encrypted blob.

**Step 2: Extract the data key ID (envelope encryption only)**

Run without `-encrypted-dek` to see which key ID is needed:

```bash
./secretdecrypt \
  -secret-key "anything" \
  -ciphertext "I1ltWmhNMlJ5Y1RacU1EQjZhMkkj..." \
  -encoding base64
```

Output:

```
Data key ID: F54a5DuVk
error: envelope encryption detected -- you must supply -encrypted-dek
       (from data_keys.encrypted_data for key "F54a5DuVk")
```

**Step 3: Get the encrypted DEK**

```sql
-- MySQL
SELECT HEX(encrypted_data) FROM data_keys WHERE name = 'F54a5DuVk';

-- PostgreSQL
SELECT encode(encrypted_data, 'hex') FROM data_keys WHERE name = 'F54a5DuVk';

-- SQLite
SELECT hex(encrypted_data) FROM data_keys WHERE name = 'F54a5DuVk';
```

**Step 4: Decrypt**

```bash
./secretdecrypt \
  -secret-key "SW2YcwTIb9zpOOhoPsMm" \
  -ciphertext "I1ltWmhNMlJ5Y1RacU1EQjZhMkkj..." \
  -encrypted-dek "2A5957567A4C574E6D59672A794D36..." \
  -encoding base64
```

The decrypted plaintext is printed to stdout. Diagnostic messages go to stderr.

### Where to find the secret_key

```bash
# From grafana.ini or custom.ini
grep 'secret_key' /etc/grafana/grafana.ini

# From environment variable (if configured)
echo $GF_SECURITY_SECRET_KEY
```

## Batch decryption (shell script)

`decrypt-cloudwatch.sh` queries the database and decrypts all fields for every CloudWatch datasource.

### Prerequisites

- `jq` for JSON parsing
- `mysql`, `psql`, or `sqlite3` depending on your database

### Usage

```bash
# MySQL
./decrypt-cloudwatch.sh \
  -s 'YOUR_SECRET_KEY' \
  -d mysql \
  -h db-host.example.com \
  -P 3306 \
  -u grafana \
  -p 'db_password' \
  -n grafana

# PostgreSQL
./decrypt-cloudwatch.sh \
  -s 'YOUR_SECRET_KEY' \
  -d postgres \
  -h db-host.example.com \
  -u grafana \
  -p 'db_password' \
  -n grafana

# SQLite
./decrypt-cloudwatch.sh \
  -s 'YOUR_SECRET_KEY' \
  -d sqlite \
  -n /var/lib/grafana/grafana.db
```

### Shell script flags

| Flag | Required | Description |
|------|----------|-------------|
| `-s` | Yes | Grafana `secret_key` |
| `-d` | No | Database type: `mysql` (default), `postgres`, `sqlite` |
| `-h` | No | Database host (default: `127.0.0.1`) |
| `-P` | No | Database port (default: `3306` / `5432`) |
| `-u` | No | Database user (default: `grafana`) |
| `-p` | No | Database password |
| `-n` | No | Database name or SQLite file path (default: `grafana`) |

### Sample output

```
=== Datasource: cloudwatch-non-prod (id=42) ===
  accessKey: AKIAIOSFODNN7EXAMPLE
  secretKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

=== Datasource: cloudwatch-prod (id=43) ===
  accessKey: AKIAI44QH8DHBEXAMPLE
  secretKey: je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
```

## Encryption details

| Property | Value |
|----------|-------|
| Algorithm | AES-256-CFB (default), AES-256-GCM (legacy fallback) |
| Key derivation | PBKDF2-SHA256, 10,000 iterations, 32-byte output |
| Salt | 8 bytes (alphanumeric in Grafana, random bytes also work) |
| IV | 16 bytes (CFB) or 12 bytes nonce (GCM) |
| DEK size | 16 bytes random |
| Blob layout | `*<b64(algo)>*` + `<salt>` + `<IV>` + `<ciphertext>` |
| Envelope layout | `#<b64(key-id)>#` + blob |

## Database tables involved

| Table | Column | Purpose |
|-------|--------|---------|
| `data_source` | `secure_json_data` | JSON map of field name to base64-encoded ciphertext |
| `data_keys` | `id` | Short UID embedded in envelope ciphertext header |
| `data_keys` | `encrypted_data` | DEK encrypted with KEK (from `secret_key`) |
| `data_keys` | `label` | Human-readable: `YYYY-MM-DD/scope@provider` |

## Security considerations

- This tool requires the Grafana `secret_key`. Treat it as a root credential.
- Decrypted output is printed to stdout. Pipe to a file with restricted permissions if persisting.
- The `secret_key` and database password will appear in your shell history. Use environment variables or a secrets manager to avoid this.
- Delete built binaries from servers after use.
