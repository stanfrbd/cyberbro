# Secret Management

Cyberbro relies on API keys and credentials that must be kept out of source control.
By default, secrets live in `secrets.json` or `.env` — both are listed in `.gitignore`, which
prevents accidental commits but leaves the files unencrypted on disk.

**Mozilla SOPS + age** is the recommended solution for Cyberbro: it encrypts individual values
inside your existing file so the encrypted copy can be safely committed to Git, with zero new
infrastructure and a single-binary install.

---

## Compatibility with existing workflows

!!! note
    SOPS is **fully opt-in**. No application code, `docker-compose.yml`, or startup procedure
    changes. Cyberbro continues to read credentials from `secrets.json` or `.env` exactly as
    before — SOPS just encrypts those files at rest.

    The workflow is:

    1. **Encrypt once** — `secrets.json` / `.env` → encrypted file committed to Git.
    2. **Decrypt at runtime** — encrypted file → original `secrets.json` / `.env` (or injected directly as env vars).
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

### 2 · Generate an age key pair

```bash
age-keygen -o ~/.config/sops/age/keys.txt
# Outputs: Public key: age1...
```

!!! warning
    Back up `~/.config/sops/age/keys.txt` securely. Losing this file means losing access to all
    encrypted secrets.

### 3 · Configure SOPS

Create a `.sops.yaml` file at the root of the repository (safe to commit — contains only public keys):

```yaml
# .sops.yaml
creation_rules:
  - path_regex: secrets\.enc\..*
    age: >-
      age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  - path_regex: \.env\.enc$
    age: >-
      age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Replace the `age1...` value with your **public key** from step 2.

!!! note
    For team environments, add each team member's public age key (one per line) to the `age:` field
    and re-encrypt: `sops updatekeys secrets.enc.json`.

### 4 · Encrypt your secrets file

=== "secrets.json"
    ```bash
    # Start from the existing sample and fill in real values
    cp secrets-sample.json secrets.json
    # Edit secrets.json with your real API keys, then encrypt:
    sops --encrypt secrets.json > secrets.enc.json
    # Remove the plaintext file
    rm secrets.json
    ```

    `secrets.json` is already in `.gitignore`. Commit `secrets.enc.json` safely.

=== ".env"
    ```bash
    # Start from the existing sample and fill in real values
    cp .env.sample .env
    # Edit .env with your real API keys, then encrypt (dotenv format):
    sops --encrypt --input-type dotenv --output-type dotenv .env > .env.enc
    # Remove the plaintext file
    rm .env
    ```

    `.env` is already in `.gitignore`. Commit `.env.enc` safely.

### 5 · Use in Docker Compose

Add the following step to your startup procedure (or a `Makefile` / shell script):

=== "secrets.json"
    ```bash
    export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
    sops --decrypt secrets.enc.json > secrets.json
    docker compose up -d
    ```

=== ".env"
    ```bash
    export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
    sops --decrypt --input-type dotenv --output-type dotenv .env.enc > .env
    docker compose up -d
    ```

In both cases Docker Compose reads the decrypted file exactly as it always did — **no changes to
`docker-compose.yml` or the application**.

!!! tip
    You can also pass secrets directly as environment variables without writing any plaintext file to
    disk using `sops exec-env`:
    ```bash
    # Decrypt inline — secrets never touch the filesystem
    sops exec-env secrets.enc.json 'docker compose up -d'
    ```

### 6 · CI/CD integration

Store the **age private key** as a CI secret (e.g., `SOPS_AGE_KEY` in GitHub Actions) and decrypt
before the Docker build step:

=== "secrets.json"
    ```yaml
    # .github/workflows/deploy.yml (excerpt)
    - name: Decrypt secrets
      env:
        SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
      run: |
        mkdir -p ~/.config/sops/age
        echo "$SOPS_AGE_KEY" > ~/.config/sops/age/keys.txt
        sops --decrypt secrets.enc.json > secrets.json
    ```

=== ".env"
    ```yaml
    # .github/workflows/deploy.yml (excerpt)
    - name: Decrypt secrets
      env:
        SOPS_AGE_KEY: ${{ secrets.SOPS_AGE_KEY }}
      run: |
        mkdir -p ~/.config/sops/age
        echo "$SOPS_AGE_KEY" > ~/.config/sops/age/keys.txt
        sops --decrypt --input-type dotenv --output-type dotenv .env.enc > .env
    ```

### 7 · Key rotation

When a team member leaves or a key is compromised:

```bash
# Remove the old public key from .sops.yaml, add the new one, then:
sops updatekeys secrets.enc.json
```

SOPS re-encrypts only the data key, not all values, so rotation is fast.
