# Secret Management

Cyberbro relies on API keys and credentials that must be kept out of source control.
This page evaluates the main secret-management approaches available for a Docker-based
deployment and recommends the best fit for a small or medium engineering team.

---

## Comparative Overview

| Criterion | `.env` / `secrets.json` *(baseline)* | **Mozilla SOPS** | Doppler | HashiCorp Vault | Docker Secrets *(Swarm)* |
|---|---|---|---|---|---|
| **Encryption at rest** | ❌ Plain text | ✅ AES-256-GCM / age | ✅ AES-256 (vendor-managed) | ✅ AES-256-GCM | ✅ Raft-encrypted |
| **Encryption in transit** | N/A | ✅ (via KMS/age) | ✅ TLS | ✅ TLS | ✅ TLS (overlay network) |
| **Key management** | None | KMS / age keypair | Vendor | Vault PKI / auto-unseal | Swarm manager key |
| **RBAC** | ❌ | ✅ (via KMS IAM) | ✅ (projects, environments, groups) | ✅ (fine-grained policies) | ⚠️ Service-level only |
| **Git-friendly** | ⚠️ `.gitignore` only | ✅ Encrypted file is safe to commit | ❌ Secrets stored in SaaS | ❌ External service | ❌ Not applicable |
| **Docker Compose support** | ✅ Native | ✅ Decrypt → `.env` before `docker compose up` | ✅ CLI injects env vars | ✅ Via agent / env injection | ⚠️ Swarm mode only |
| **Local dev experience** | ✅ Simple | ✅ `sops --decrypt` | ✅ `doppler run --` | ⚠️ Vault dev server needed | ❌ Requires Swarm |
| **Operational overhead** | None | Low (key rotation only) | Low (SaaS) | High (HA cluster, unsealing, auditing) | Medium (Swarm management) |
| **Cost** | Free | Free / OSS | Free tier; paid plans | Free / OSS (BSL for enterprise) | Free |
| **Vendor lock-in** | None | None (portable encrypted files) | Medium (Doppler SaaS) | Low (self-hostable) | None |
| **Scalability** | Low | Medium | High | Very high | Medium (Swarm) |
| **Plug-and-play readiness** | ✅ | ✅ | ✅ | ❌ | ❌ |

---

## Agent Debate Summary

### Position 1 — Mozilla SOPS (recommended)

**Strengths:**

- Encrypts individual values inside a YAML/JSON/`.env` file; the structure (key names) remains readable, enabling meaningful diffs in pull requests.
- Supports multiple backends out of the box: **age** (zero-infrastructure, modern, recommended), AWS KMS, GCP KMS, Azure Key Vault, PGP.
- The encrypted file can be safely committed to Git — no risk of accidental secret exposure when developers clone the repo.
- Zero new infrastructure: a single binary + an age keypair is all that is needed for local development.
- CI/CD integration is a one-liner: `sops --decrypt secrets.enc.json > secrets.json` before starting the container.

**Weaknesses:**

- Rotation requires re-encrypting files; teams must establish a key-rotation runbook.
- No real-time audit trail out of the box (rely on Git history and KMS logs).

### Position 2 — Doppler

**Strengths:**

- SaaS dashboard; no infrastructure to manage.
- First-class Docker and CI/CD integrations (`doppler run -- docker compose up`).
- Built-in RBAC, secret versioning, and audit logs.

**Weaknesses:**

- Introduces an external SaaS dependency; outage = blocked deployments.
- Free tier has limitations; team growth moves into paid plans.
- Secrets live outside the repository — harder to reproduce historical deployments without a secrets snapshot.

### Position 3 — HashiCorp Vault

**Strengths:**

- Gold standard for enterprise secret management: dynamic secrets, leases, detailed audit logs, fine-grained policies.

**Weaknesses:**

- Significant operational overhead: HA cluster setup, unsealing, TLS certificate management, monitoring.
- Over-engineered for a single-service Docker Compose deployment.
- License changed to BSL (not OSS) for Vault 1.14+; consider OpenBao as an open-source fork.

### Position 4 — Docker Secrets (Swarm mode)

**Strengths:**

- Native Docker feature; secrets are injected as in-memory tmpfs files inside containers.
- No external tooling required for a Swarm deployment.

**Weaknesses:**

- Only available in **Swarm mode** — incompatible with plain `docker compose`.
- Secrets are not encrypted before being stored in the Raft log on manager nodes without additional configuration.
- Adds Swarm management overhead for a project that doesn't otherwise need orchestration.

---

## Recommendation: Mozilla SOPS with age

For a small-to-medium team running Cyberbro via Docker Compose, **Mozilla SOPS + age** provides
the best balance of security, simplicity, and zero operational overhead:

- Secrets are **encrypted at rest and safe to commit** to the repository.
- No external services or infrastructure are required.
- Works seamlessly with the existing `.env` / `secrets.json` workflow.
- Easy to adopt gradually: start with a single encrypted file and expand as needed.

---

## Compatibility with existing workflows

!!! note
    The SOPS approach is **fully opt-in**. No application code is changed and no existing mechanism
    is removed. Cyberbro will continue to read credentials from `secrets.json` or `.env` exactly as
    before — SOPS simply encrypts those files at rest so they can be safely stored in version control.

    The workflow is:

    1. **Encrypt once** — `secrets.json` / `.env` → encrypted file committed to Git.
    2. **Decrypt at runtime** — encrypted file → original `secrets.json` / `.env` (or injected as env vars).
    3. **Application starts normally** — reads the same files / env vars it always has.

---

## Getting Started with SOPS + age

### 1 · Install SOPS and age

=== "Linux / macOS (Homebrew)"
    ```bash
    brew install sops age
    ```

=== "Linux (binary)"
    ```bash
    # age
    curl -Lo age.tar.gz https://github.com/FiloSottile/age/releases/latest/download/age-v1.2.1-linux-amd64.tar.gz
    tar -xzf age.tar.gz && sudo mv age/age age/age-keygen /usr/local/bin/

    # sops
    curl -Lo sops https://github.com/getsops/sops/releases/latest/download/sops-v3.10.2.linux.amd64
    chmod +x sops && sudo mv sops /usr/local/bin/
    ```

=== "Windows (Scoop)"
    ```powershell
    scoop install sops age
    ```

### 2 · Generate an age key pair

```bash
age-keygen -o ~/.config/sops/age/keys.txt
# Outputs: Public key: age1...
```

!!! warning
    Back up `~/.config/sops/age/keys.txt` securely. Losing this file means losing access to all encrypted secrets.

### 3 · Configure SOPS

Create a `.sops.yaml` file at the root of the repository (add it to version control):

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

Add the following step to your startup procedure (or a `Makefile`/shell script):

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

In both cases Docker Compose reads the decrypted file exactly as it always did — **no changes to `docker-compose.yml` or the application**.

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

!!! tip
    You can also pass the decrypted values directly as environment variables without writing `secrets.json` to disk, using `sops exec-env`:
    ```bash
    sops exec-env secrets.enc.json 'docker compose up -d'
    ```

!!! note
    For team environments, add each team member's public age key (one per line) to the `age:` field in `.sops.yaml` and re-encrypt: `sops updatekeys secrets.enc.json`.
