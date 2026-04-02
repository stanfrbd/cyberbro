## Summary
- What does this PR change?
- Why is this change needed?

## Scope
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor
- [ ] Documentation
- [ ] New engine
- [ ] Other (describe):

## Validation (required)
- [ ] I ran relevant tests locally and they pass.
- [ ] I validated real behavior (not only code style or static checks).
- [ ] I checked edge cases and failure paths.

### Test evidence
List exact commands you ran and the outcome.

```bash
# Example
pytest -q
```

## AI-assisted contribution disclosure
- [ ] This PR includes AI-assisted work.
- [ ] I reviewed and understood all generated code.
- [ ] I refined AI output where needed (no low-quality slop).
- [ ] I am fully responsible for this submission.

If AI was used, briefly describe what parts were AI-assisted:

## Maintainer merge policy acknowledgement
- [ ] I understand uncertain changes may be merged to `dev` first for additional validation.
- [ ] I understand `main` is kept clean/stable for releases and tags.

## New engine checklist (only if applicable)
### Engine Implementation
- [ ] Added engine file in `engines/engine_name.py` (using existing engines as template).
- [ ] Added engine import/registration in `engines/__init__.py`.
- [ ] Added engine config/secret variable in `utils/config.py` (if relevant).

### Configuration & Secrets
- [ ] Added needed API key/config vars to `.env.sample`.
- [ ] Verified variable templating in `docker-compose.yml`.

### UI & Frontend
- [ ] Engine result is copyable via GUI in `static/format_results.js`.
- [ ] Added/updated layouts in `templates/engines_layouts/` for card/table rendering.
- [ ] Added engine in `templates/display_cards.html` and `templates/display_table.html`.
- [ ] Added engine in `templates/index.html` with description (alphabetic order).
- [ ] Added engine support for graph view in `templates/graph.html`.

### Documentation
- [ ] Added docs in `docs/api-keys/Get-Engine-API-key.md` (if relevant).
- [ ] Added API key guide link in `docs/index.md` (if relevant).
- [ ] Added engine to `docs/quick-start/API-usage-and-engine-names.md`.
- [ ] Added page in `mkdocs.yml` sidebar.
- [ ] Updated `docs/quick-start/Quick-start-&-Installation.md` and `.env` examples.
- [ ] Added env vars to `docs/quick-start/Advanced-options-for-deployment.md` (`docker compose` example).
- [ ] Updated `README.md` references (env vars and API/services section).

## Risk and rollback
- Risk level: Low / Medium / High
- Potential impact:
- Rollback strategy:

## Additional notes
- Any reviewer context, trade-offs, or follow-up tasks.
