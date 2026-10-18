/* Run from any working directory after npm run build. No external services are contacted. */
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs/promises");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
(async () => {
  const server = http.createServer(async (req, res) => {
    const file = path.resolve(
      root,
      "." + new URL(req.url, "http://localhost").pathname,
    );
    if (!file.startsWith(root + path.sep)) {
      res.writeHead(403).end();
      return;
    }
    try {
      const data = await fs.readFile(file);
      res.setHeader(
        "Content-Type",
        file.endsWith(".js")
          ? "text/javascript"
          : file.endsWith(".css")
            ? "text/css"
            : "text/html",
      );
      res.end(data);
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({
    headless: true,
    executablePath:
      process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined,
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--use-gl=angle",
      "--use-angle=swiftshader",
      "--enable-unsafe-swiftshader",
      "--no-zygote",
    ],
  });
  const errors = [];
  try {
    const page = await browser.newPage({
      viewport: { width: 1600, height: 1080 },
    });
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(base + "/static/ui/index.html?demo=1");
    await page.waitForSelector(".observable-cell");
    await fs.mkdir(path.join(root, "preview"), { recursive: true });
    await page.screenshot({
      path: path.join(root, "preview/cyberbro-desktop.png"),
      fullPage: true,
    });
    assert.equal(await page.locator("tbody tr").count(), 8);
    await page.getByRole("button", { name: "Next page", exact: true }).click();
    assert.equal(await page.locator("tbody tr").count(), 4);
    await page
      .getByRole("button", { name: "Signals found 4", exact: true })
      .click();
    assert.equal(await page.locator("tbody tr").count(), 4);
    await page
      .getByLabel("Search observables", { exact: true })
      .fill("203.0.113.42");
    assert.equal(await page.locator("tbody .observable-cell").count(), 2);
    await page.getByRole("button", { name: "Export", exact: true }).click();
    const downloadPromise = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Download CSV", exact: true })
      .click();
    const download = await downloadPromise;
    const csv = await fs.readFile(await download.path(), "utf8");
    assert.ok(csv.includes("203.0.113.42"));
    assert.equal(csv.split("\r\n").length, 3);
    await page
      .getByLabel("Search observables", { exact: true })
      .fill("nothing-matches");
    assert.ok(
      await page
        .getByText("No matching observables. Try another search or filter.")
        .isVisible(),
    );
    await page.getByLabel("Search observables", { exact: true }).fill("");
    await page
      .getByRole("button", { name: "All observables 12", exact: true })
      .click();
    await page
      .getByRole("button", {
        name: "Inspect login-update.example.test",
        exact: true,
      })
      .click();
    assert.equal(
      await page.locator(".detail-identity h2").textContent(),
      "login-update.example.test",
    );
    await page.getByRole("button", { name: "Raw JSON", exact: true }).click();
    assert.ok(
      (await page.locator(".json-panel pre").textContent()).includes(
        '"total_malicious": 8',
      ),
    );
    await page
      .getByRole("button", { name: "Switch to light theme", exact: true })
      .click();
    assert.ok(await page.locator(".workspace.light").isVisible());
    await page.screenshot({
      path: path.join(root, "preview/cyberbro-light.png"),
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "New analysis", exact: true })
      .first()
      .click();
    await page
      .getByLabel("Observables to analyze", { exact: true })
      .fill("example.test");
    assert.equal(await page.locator(".engine-choice").count(), 6);
    await page.screenshot({
      path: path.join(root, "preview/cyberbro-new-analysis.png"),
      fullPage: true,
    });
    await page
      .getByRole("button", { name: "Explore sample results", exact: true })
      .click();
    assert.ok(
      await page
        .getByRole("heading", { name: "Investigation workspace" })
        .isVisible(),
    );

    const mobile = await browser.newPage({
      viewport: { width: 390, height: 844 },
      isMobile: true,
      hasTouch: true,
      deviceScaleFactor: 1,
    });
    mobile.on("pageerror", (error) => errors.push(error.message));
    await mobile.goto(base + "/preview/cyberbro-preview.html");
    await mobile.waitForSelector(".observable-cell");
    assert.equal(await mobile.locator(".detail-panel").count(), 0);
    assert.ok(
      await mobile.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    );
    await mobile.screenshot({
      path: path.join(root, "preview/cyberbro-mobile.png"),
      fullPage: true,
    });
    await mobile
      .getByRole("button", { name: "Inspect 203.0.113.42", exact: true })
      .click();
    assert.ok(await mobile.locator(".detail-panel").isVisible());
    await mobile
      .getByRole("button", { name: "Close details", exact: true })
      .click();
    assert.equal(await mobile.locator(".detail-panel").count(), 0);

    // Exercise the real API adapter with a deterministic custom-prefix mock.
    const live = await browser.newPage();
    live.on("pageerror", (error) => errors.push(error.message));
    await live.addInitScript(() => {
      window.CYBERBRO_CONFIG = {
        apiPrefix: "custom/api",
        engines: ["reverse_dns", "rdap_whois"],
        enabledEngines: [],
      };
    });
    let calls = 0;
    await live.route("**/custom/api/**", async (route) => {
      const request = route.request();
      if (request.url().endsWith("/analyze")) {
        const body = request.postDataJSON();
        assert.equal(body.text, "example.test");
        assert.deepEqual(body.engines, ["reverse_dns", "rdap_whois"]);
        calls++;
        await route.fulfill({ json: { analysis_id: "test-analysis" } });
      } else if (request.url().includes("/is_analysis_complete/")) {
        await route.fulfill({ json: { complete: true } });
      } else {
        await route.fulfill({
          json: [
            {
              observable: "example.test",
              type: "FQDN",
              reverse_dns: { reverse_dns: ["192.0.2.1"] },
            },
          ],
        });
      }
    });
    await live.goto(base + "/static/ui/index.html");
    await live
      .getByLabel("Observables to analyze", { exact: true })
      .fill("example.test");
    await live
      .getByRole("button", { name: "Start analysis", exact: true })
      .click();
    await live.waitForSelector(".observable-cell");
    assert.equal(calls, 1);
    assert.ok(live.url().includes("analysis=test-analysis"));
    assert.ok(
      (await live.locator(".observable-cell").textContent()).includes(
        "example.test",
      ),
    );
    assert.deepEqual(errors, []);
    console.log(
      "PASS: filters, pagination, missing data, details, JSON, CSV download, theme, form, mobile layout/drawer, standalone preview, custom-prefix API adapter. No JavaScript errors.",
    );
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
