# Cyberbro interface preview

An opt-in Vue 3 + TypeScript interface. The classic Flask/Jinja routes and API contracts remain available.

## Build and use

```sh
cd frontend
npm ci
npm run build
cd ..
# Start Cyberbro normally, then open /ui
# /ui?analysis=<analysis-id> opens existing results
# /ui?demo=1 loads synthetic preview data without calling reputation services
```

Node.js is required to build the frontend, not to serve the compiled output. Flask serves the generated `static/ui/` assets using Vite's manifest. The Dockerfile has not yet been changed to build these assets automatically: build before building the image.

For development use `npm run dev -- --host 127.0.0.1` and open the Vite URL with `?demo=1`. A live backend connection is bootstrapped by Flask at `/ui`.

## Standalone preview

After building:

```sh
node frontend/create-preview.mjs
python -m http.server 8765 --bind 127.0.0.1
# Open http://127.0.0.1:8765/preview/cyberbro-preview.html
```

The standalone preview uses the same compiled UI and forces synthetic data mode. It does not submit the input to any engines. The preview includes local filters, pagination, source details, JSON inspection, CSV/JSON exports, and theme switching. History and statistics links target the existing Flask pages; these are not implemented again in the new frontend.

## Scope and limitations

- Source signals currently summarize explicit VirusTotal detections and AbuseIPDB confidence. Other engines' responses are accessible in the details panel; no global risk verdict is inferred.
- `null` results are displayed as missing data, not clean verdicts. Existing backend nulls do not distinguish unsupported observables, missing credentials, failed requests, and empty responses.
- Engine names are bootstrapped from the backend; the browser never receives credentials. Engine health/configuration status is not inferred from visibility.
- The preview does not yet replicate the classic graph, engine dependency dialogs, saved presets, or every engine's specialized result card. Use the classic interface for those workflows.
- Live polling has a ten-minute timeout. The backend still reports only completion rather than per-engine progress.
- The source detail drawer includes raw per-engine responses and only permits HTTP/HTTPS source links.
- Google Fonts is optional; system fonts provide the fallback when unavailable.
