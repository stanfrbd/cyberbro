# Contributions & Community

For details on contributing, community standards, and licensing, see:

- [Contributing Guidelines](https://github.com/stanfrbd/cyberbro/blob/main/CONTRIBUTING.md)
- [Code of Conduct](https://github.com/stanfrbd/cyberbro/blob/main/CODE_OF_CONDUCT.md)
- [Roadmap](https://github.com/stanfrbd/cyberbro/blob/main/ROADMAP.md)
- [License](https://github.com/stanfrbd/cyberbro/blob/main/LICENSE)

## Checklist when adding a new engine

### Engine Implementation
* Add the engine class to `engines/engine_name.py` (use `engines/abuseipdb.py` as a template).
* Import and instantiate the engine in `utils/load_engines.py`.
* Add the engine's configuration or secret fields to `utils/config.py`, if relevant.
* Add focused tests for the engine and its edge cases in `tests/`.
* Run `node --test tests/test_recorded_future_graph.cjs` when changing the graph.

### Configuration & Secrets
* Add any API key or configuration needed for the engine to `.env.sample`.
* Add any new environment variables to `docker-compose.yml` using the existing
  variable substitution conventions and an appropriate default.

### UI & Frontend
* Add the engine's result fields to `static/format_results.js` so GUI results can
  be copied to the clipboard.
* Add the engine result templates to `templates/engine_layouts/`:
  `engine_name_card.html` and `engine_name_table.html`, when both views apply.
* Add the engine to `templates/display_cards.html` and
  `templates/display_table.html`.
* Add the engine to the GUI form in `templates/index.html` with a relevant
  description, keeping the list alphabetized.
* Make the engine usable in `templates/graph.html`, including relevant
  engine-specific relationships or nodes.

### Documentation
* Document the engine's API key setup in `docs/api-keys/` if relevant, and link
  that guide from `docs/index.md`.
* Document the engine name, supported observable types, and requirements in
  `docs/quick-start/API-usage-and-engine-names.md`.
* Add new documentation pages to the sidebar in `mkdocs.yml`.
* Update `docs/quick-start/Quick-start-&-Installation.md` when the engine
  requires changes to the installation or setup instructions.
* Add the engine's environment variables to `.env.sample`, the README
  environment example, and the environment and `docker compose` examples in
  `docs/quick-start/Advanced-options-for-deployment.md`.
* Add the engine and its provider URL to the README's
  "API and third-party services" section.

Note: if you use an LLM to code, just make sure to use this list as a checklist to verify everything is covered (if something is missing, add it!).
