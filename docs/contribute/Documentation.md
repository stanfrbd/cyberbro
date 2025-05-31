# Documentation Deployment Workflow

This GitHub Actions workflow (`deploy-docs.yml`) automates the deployment of your documentation site using [MkDocs Material](https://squidfunk.github.io/mkdocs-material/).

!!! tip
    Why use MkDocs Material?  
    Everyone can now easily contribute to the documentation, and it provides a clean, modern look with built-in search functionality.

## How it works

- **Trigger:** Runs automatically on every push to the `main` branch.
- **Build & Deploy:** Installs MkDocs Material, builds the documentation, and deploys it to the `gh-pages` branch, which is used by GitHub Pages to serve your site.

## Local Development

To preview your documentation locally before pushing changes:

1. Ensure you have Python installed.
2. Install MkDocs Material:
    ```sh
    pip install -r requirements-doc.txt
    ```
3. Serve the documentation locally:
    ```sh
    mkdocs serve
    ```
    This will start a local server (usually at [http://127.0.0.1:8000/](http://127.0.0.1:8000/)) where you can view your docs.

## Requirements

- Your documentation source files should be present (typically in a `docs/` directory).
- The `mkdocs.yml` configuration file should be present at the root of your repository.
- The workflow will deploy the built site to the `gh-pages` branch automatically; you do not need to manually push to this branch.

For more details, see the [MkDocs Material documentation](https://squidfunk.github.io/mkdocs-material/getting-started/).