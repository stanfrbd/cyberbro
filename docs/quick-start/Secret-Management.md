# Secret Management

Cyberbro relies on API keys and credentials stored in `secrets.json` or `.env`.
Both files are listed in `.gitignore` to prevent accidental commits, but they remain
**unencrypted on disk** — meaning a local infostealer or any process with filesystem access
can read them in plain text.

**Mozilla SOPS + age** solves this by encrypting those files **at rest on your machine**.
The encrypted files never need to leave your disk; `.gitignore` stays in place and nothing is
committed to Git.

!!! warning
    **Never commit your secrets to Git**, even if they are encrypted.
    The encryption described here is for **local disk protection only**.

---

## Compatibility with existing workflows

!!! note
    SOPS is **fully opt-in**. No application code, `docker-compose.yml`, or startup procedure
    changes. Cyberbro continues to read credentials from `secrets.json` or `.env` exactly as
    before.

    The workflow is:

    1. **Encrypt** — `secrets.json` / `.env` → encrypted file stored locally on disk.
    2. **Decrypt at runtime** — encrypted file → original `secrets.json` / `.env` (or injected directly as env vars, never touching the filesystem).
    3. **Application starts normally** — reads the same files / env vars it always has.

---

## Getting Started with SOPS + age

### 1 · Install SOPS and age

=== "Linux / macOS (Homebrew) — recommended"
    ```bash
    brew install sops age
    ```
    Homebrew always installs the latest stable release and handles future upgrades automatically.

=== "Linux (binary — always latest)"
    ```bash
    # Fetch the latest SOPS release tag dynamically
    SOPS_VERSION=$(curl -fsSL https://api.github.com/repos/getsops/sops/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4)
    [ -z "$SOPS_VERSION" ] && { echo "Failed to fetch SOPS version"; exit 1; }
    curl -Lo sops "https://github.com/getsops/sops/releases/download/${SOPS_VERSION}/sops-${SOPS_VERSION}.linux.amd64"
    chmod +x sops && sudo mv sops /usr/local/bin/

    # Fetch the latest age release tag dynamically
    AGE_VERSION=$(curl -fsSL https://api.github.com/repos/FiloSottile/age/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4)
    [ -z "$AGE_VERSION" ] && { echo "Failed to fetch age version"; exit 1; }
    curl -Lo age.tar.gz "https://github.com/FiloSottile/age/releases/download/${AGE_VERSION}/age-${AGE_VERSION}-linux-amd64.tar.gz"
    tar -xzf age.tar.gz && sudo mv age/age age/age-keygen /usr/local/bin/ && rm -rf age age.tar.gz
    ```

=== "Windows (winget)"
    ```powershell
    winget install --id Mozilla.SOPS
    winget install --id FiloSottile.age
    ```

!!! tip
    Always check the official release pages for the most recent versions:

    - SOPS: <https://github.com/getsops/sops/releases>
    - age: <https://github.com/FiloSottile/age/releases>

### 2 · Generate an age key pair and protect it with a passphrase

`age-keygen` does not support passphrases natively. The recommended approach is to generate
the key into a temporary file, immediately encrypt it with a passphrase using `age --passphrase`,
then delete the plain-text copy. **Only the passphrase-protected file is kept on disk.**

=== "Linux / macOS"
    ```bash
    mkdir -p ~/.config/sops/age
    # Generate key pair — note the public key printed (age1...)
    age-keygen -o /tmp/age_key.txt
    # Encrypt the private key with a passphrase (you will be prompted twice)
    age --passphrase -o ~/.config/sops/age/keys.age /tmp/age_key.txt
    # Remove the plain-text key from disk
    rm /tmp/age_key.txt
    ```

=== "Windows (PowerShell)"
    ```powershell
    New-Item -ItemType Directory -Force -Path "$env:APPDATA\sops\age" | Out-Null
    # Generate key pair — note the public key printed (age1...)
    age-keygen -o "$env:TEMP\age_key.txt"
    # Encrypt the private key with a passphrase (you will be prompted twice)
    age --passphrase -o "$env:APPDATA\sops\age\keys.age" "$env:TEMP\age_key.txt"
    # Remove the plain-text key from disk
    Remove-Item "$env:TEMP\age_key.txt"
    ```

!!! warning
    **Note the `age1...` public key printed by `age-keygen`** before running the next step.
    Once the plain-text file is deleted, the public key is only recoverable by decrypting
    `keys.age` (which requires the passphrase). Store the public key in your notes or password
    manager alongside the passphrase — losing either means losing access to your encrypted secrets.

### 3 · Configure SOPS

Set your **public key** as an environment variable so SOPS knows which key to use when encrypting:

=== "Linux / macOS"
    ```bash
    # Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.) for convenience
    export SOPS_AGE_RECIPIENTS=age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    ```

=== "Windows (PowerShell)"
    ```powershell
    # For the current session only:
    $env:SOPS_AGE_RECIPIENTS = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    # To persist across sessions, add it to your PowerShell profile:
    [System.Environment]::SetEnvironmentVariable("SOPS_AGE_RECIPIENTS", "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "User")
    ```

Replace the `age1...` value with your **public key** from step 2.

### 4 · Encrypt your secrets file

=== "secrets.json (Linux / macOS)"
    ```bash
    # Start from the existing sample and fill in real values
    cp secrets-sample.json secrets.json
    # Edit secrets.json with your real API keys, then encrypt:
    sops --encrypt secrets.json > secrets.enc.json
    # Remove the plaintext file — only the encrypted copy stays on disk
    rm secrets.json
    ```

    `secrets.json` and `secrets.enc.json` are both listed in `.gitignore` — **neither is committed**.

=== "secrets.json (Windows PowerShell)"
    ```powershell
    # Start from the existing sample and fill in real values
    Copy-Item secrets-sample.json secrets.json
    # Edit secrets.json with your real API keys, then encrypt:
    sops --encrypt secrets.json | Out-File -Encoding utf8 secrets.enc.json
    # Remove the plaintext file — only the encrypted copy stays on disk
    Remove-Item secrets.json
    ```

    `secrets.json` and `secrets.enc.json` are both listed in `.gitignore` — **neither is committed**.

=== ".env (Linux / macOS)"
    ```bash
    # Start from the existing sample and fill in real values
    cp .env.sample .env
    # Edit .env with your real API keys, then encrypt (dotenv format):
    sops --encrypt --input-type dotenv --output-type dotenv .env > .env.enc
    # Remove the plaintext file — only the encrypted copy stays on disk
    rm .env
    ```

    `.env` and `.env.enc` are both listed in `.gitignore` — **neither is committed**.

=== ".env (Windows PowerShell)"
    ```powershell
    # Start from the existing sample and fill in real values
    Copy-Item .env.sample .env
    # Edit .env with your real API keys, then encrypt (dotenv format):
    sops --encrypt --input-type dotenv --output-type dotenv .env | Out-File -Encoding utf8 .env.enc
    # Remove the plaintext file — only the encrypted copy stays on disk
    Remove-Item .env
    ```

    `.env` and `.env.enc` are both listed in `.gitignore` — **neither is committed**.

### 5 · Use in Docker Compose

To decrypt, you first unlock the passphrase-protected age key in memory and pass the raw key
material to SOPS via the `SOPS_AGE_KEY` environment variable. **You will be prompted for your
passphrase every time.** The plain-text key never touches the filesystem.

=== "secrets.json (Linux / macOS)"
    ```bash
    # Prompts for the age passphrase; decrypted key lives only in memory
    SOPS_AGE_KEY=$(age --decrypt ~/.config/sops/age/keys.age) \
      sops --decrypt secrets.enc.json > secrets.json
    docker compose up -d
    ```

=== "secrets.json (Windows PowerShell)"
    ```powershell
    # Prompts for the age passphrase; decrypted key lives only in memory
    # -join "`n" is required: PowerShell returns an array per line; SOPS needs newline-separated text
    $env:SOPS_AGE_KEY = (age --decrypt "$env:APPDATA\sops\age\keys.age") -join "`n"
    sops --decrypt secrets.enc.json | Out-File -Encoding utf8 secrets.json
    docker compose up -d
    ```

=== ".env (Linux / macOS)"
    ```bash
    # Prompts for the age passphrase; decrypted key lives only in memory
    SOPS_AGE_KEY=$(age --decrypt ~/.config/sops/age/keys.age) \
      sops --decrypt --input-type dotenv --output-type dotenv .env.enc > .env
    docker compose up -d
    ```

=== ".env (Windows PowerShell)"
    ```powershell
    # Prompts for the age passphrase; decrypted key lives only in memory
    # -join "`n" is required: PowerShell returns an array per line; SOPS needs newline-separated text
    $env:SOPS_AGE_KEY = (age --decrypt "$env:APPDATA\sops\age\keys.age") -join "`n"
    sops --decrypt --input-type dotenv --output-type dotenv .env.enc | Out-File -Encoding utf8 .env
    docker compose up -d
    ```

In both cases Docker Compose reads the decrypted file exactly as it always did — **no changes to
`docker-compose.yml` or the application**.

!!! tip
    Use `sops exec-env` to inject secrets directly as environment variables without ever writing
    a plaintext file to disk:
    ```bash
    # Prompts for the age passphrase; secrets are decrypted in memory — plaintext never touches disk
    SOPS_AGE_KEY=$(age --decrypt ~/.config/sops/age/keys.age) \
      sops exec-env secrets.enc.json 'docker compose up -d'
    ```
