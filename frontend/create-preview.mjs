/** Package the same production UI into a standalone, synthetic-only preview. */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const build = resolve(root, "static/ui");
const manifest = JSON.parse(
  await readFile(resolve(build, ".vite/manifest.json"), "utf8"),
)["index.html"];
let script = await readFile(resolve(build, manifest.file), "utf8");
if (!script.includes("new URLSearchParams(location.search)"))
  throw new Error("Preview configuration marker not found");
script = script.replace(
  "new URLSearchParams(location.search)",
  'new URLSearchParams("demo=1")',
);
const styles = (
  await Promise.all(
    (manifest.css ?? []).map((file) => readFile(resolve(build, file), "utf8")),
  )
).join("\n");
await mkdir(resolve(root, "preview"), { recursive: true });
await writeFile(
  resolve(root, "preview/cyberbro-preview.html"),
  `<!doctype html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cyberbro · Local interface preview</title><style>${styles}</style></head>
<body><div id="app"></div><script type="module">${script.replaceAll("</script", "<\\/script")}</script></body></html>`,
);
