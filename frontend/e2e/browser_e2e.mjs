/**
 * Browser end-to-end test for the Malware Scan UI (puppeteer-core).
 *
 * Requires the API on :8000 and the web app on :3000 (see README).
 * Chromium: set CHROME_PATH to a Chrome/Chromium binary, or use any
 * chromium-compatible binary available on the machine.
 *
 *   MS_ADMIN_PASSWORD='...' CHROME_PATH=/usr/bin/chromium node browser_e2e.mjs
 */
import puppeteer from "puppeteer-core";
import fs from "node:fs";

const BASE = process.env.MS_BASE || "http://127.0.0.1:3000";
const USER = process.env.MS_ADMIN_USER || "admin";
const PASS = process.env.MS_ADMIN_PASSWORD || "E2eAdmin!12345";
const CHROME = process.env.CHROME_PATH;
const OUT = process.env.MS_SHOTS || "./screens";
fs.mkdirSync(OUT, { recursive: true });

let passed = 0;
const failed = [];
const check = (name, ok, detail = "") => {
  if (ok) { passed++; console.log(`  ✔ ${name}`); }
  else { failed.push(name); console.log(`  ✘ ${name} ${detail}`); }
};

const launchOpts = CHROME
  ? { executablePath: CHROME, headless: true, args: ["--no-sandbox"] }
  : null;
let browser;
if (launchOpts) {
  browser = await puppeteer.launch({ ...launchOpts, defaultViewport: { width: 1366, height: 860 } });
} else {
  const chromium = (await import("@sparticuz/chromium")).default;
  browser = await puppeteer.launch({ executablePath: await chromium.executablePath(), args: chromium.args, headless: true, defaultViewport: { width: 1366, height: 860 } });
}
const page = await browser.newPage();
const pageErrors = [];
const consoleErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e.message || e)));
page.on("console", (m) => { if (m.type() === "error" && !/Failed to load resource|404|favicon/.test(m.text())) consoleErrors.push(m.text()); });

const textOf = (sel) => page.$eval(sel, (e) => e.textContent).catch(() => "");
const bodyText = () => page.evaluate(() => (document.body ? document.body.innerText : "")).catch(() => "");
const waitText = async (re, timeout = 30000) => {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const t = await bodyText();
    if (re.test(t)) return true;
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
};
const clickByText = async (selector, text) => {
  const handles = await page.$$(selector);
  for (const h of handles) {
    const t = await h.evaluate((e) => e.textContent || "");
    if (t.includes(text)) { await h.click(); return true; }
  }
  return false;
};
const shot = (name) => page.screenshot({ path: `${OUT}/${name}.png`, fullPage: false });

console.log("\n=== Authentication ===");
await page.goto(`${BASE}/login`, { waitUntil: "networkidle0" });
await page.type('input[autocomplete="username"]', "wrong-user-x");
await page.type('input[type="password"]', "not-the-password");
await page.click('button[type="submit"]');
check("wrong credentials show an error", await waitText(/Invalid credentials/, 10000));
await page.evaluate(() => { document.querySelectorAll("input").forEach((i) => (i.value = "")); });
await page.click('input[autocomplete="username"]', { clickCount: 3 });
await page.type('input[autocomplete="username"]', USER);
await page.click('input[type="password"]', { clickCount: 3 });
await page.type('input[type="password"]', PASS);
await page.click('button[type="submit"]');
await page.waitForFunction(() => location.pathname === "/dashboard", { timeout: 20000 }).catch(() => {});
check("admin sign-in redirects to /dashboard", (await page.evaluate(() => location.pathname)) === "/dashboard");

console.log("\n=== Dashboard (live) ===");
check("KPI tiles render", await waitText(/open alerts/i, 20000));
check("endpoint status table lists local-host", await waitText(/local-host/, 20000));
check("alert/incident/process panels render", await waitText(/Suspicious processes/, 15000) && (await waitText(/Incident timeline/, 5000)));
await shot("01-dashboard");

console.log("\n=== File scanner: EICAR test sample ===");
await page.goto(`${BASE}/scan`, { waitUntil: "networkidle0" });
const ran = await page.evaluate(() => {
  const row = [...document.querySelectorAll("div.row")].find((d) => d.textContent.includes("EICAR test file"));
  const btn = row && [...row.querySelectorAll("button")].find((b) => b.textContent.trim() === "Run");
  if (btn) { btn.click(); return true; }
  return false;
});
check("EICAR sample button runs a scan", ran);
check("scan completes with MALICIOUS verdict", await waitText(/MALICIOUS · severity info/, 40000));
check("pipeline steps shown", await waitText(/Static analysis/, 2000));
await shot("02-scan-eicar");

console.log("\n=== File upload with progress ===");
const payload = Buffer.from("Quarterly report draft for review\n".repeat(200));
fs.writeFileSync("/tmp/ms_ui_upload.txt", payload);
const input = await page.$('input[type="file"]');
await input.uploadFile("/tmp/ms_ui_upload.txt");
const sawProgress = await waitText(/Uploading…|Received & hashed|Static analysis/, 15000);
check("upload shows progress / pipeline state", sawProgress);
check("uploaded file reaches a verdict", await waitText(/(CLEAN|SUSPICIOUS|MALICIOUS) · severity/, 40000));
await shot("03-scan-upload");

console.log("\n=== Recent scans & detail view ===");
check("recent scans table lists the uploaded file", await waitText(/ms_ui_upload\.txt/, 10000));
await page.goto(`${BASE}/scan`, { waitUntil: "networkidle0" });
const navWait = page.waitForNavigation({ waitUntil: "networkidle0", timeout: 15000 }).catch(() => null);
await page.evaluate(() => { const r = [...document.querySelectorAll("tbody tr")].find((t) => /eicar/i.test(t.textContent)); r && r.click(); });
await navWait;
await page.waitForFunction(() => /\/scan\/\d+/.test(location.pathname), { timeout: 10000 }).catch(() => {});
check("clicking a scan opens its report", /\/scan\/\d+/.test(await page.evaluate(() => location.pathname)));
check("report shows explanation and risk factors", await waitText(/Risk factors/, 15000) && (await waitText(/Explanation/, 3000)));
check("report shows static analysis block", await waitText(/Static analysis/, 5000));
await shot("04-scan-report");

console.log("\n=== Alert triage drawer ===");
await page.goto(`${BASE}/alerts`, { waitUntil: "networkidle0" });
check("alerts table has rows", await waitText(/severity[\s\S]*alert[\s\S]*category/i, 15000));
await page.evaluate(() => { const r = document.querySelector("tbody tr.clickable"); r && r.click(); });
check("alert drawer opens with explanation", await waitText(/Why it fired/, 10000));
check("triage controls visible to analyst", await waitText(/Mark false positive/, 5000));
await shot("05-alert-drawer");
await page.keyboard.press("Escape");

console.log("\n=== Assistant ===");
await page.goto(`${BASE}/assistant`, { waitUntil: "networkidle0" });
await page.type('input[aria-label="Ask the assistant"]', "top threats right now");
await page.keyboard.press("Enter");
check("assistant answers from database", await waitText(/unresolved threats|No unresolved alerts/i, 15000));
check("assistant reports its engine honestly", await waitText(/engine: local-analyst/, 5000));
await shot("06-assistant");

console.log("\n=== Reports ===");
await page.goto(`${BASE}/reports`, { waitUntil: "networkidle0" });
await clickByText("button", "Generate report");
check("report generated and listed", await waitText(/Report #\d+ generated/, 15000));

console.log("\n=== Admin console ===");
await page.goto(`${BASE}/admin`, { waitUntil: "networkidle0" });
check("admin user table lists the administrator", await waitText(/Accounts/, 15000) && (await waitText(new RegExp(USER), 5000)));
await clickByText('[role="tab"]', "Audit trail");
check("audit trail records actions", await waitText(/auth\.login|scan\.upload|scan\.test_sample/, 10000));
await clickByText('[role="tab"]', "Detection rules");
check("rule integrity status displayed", await waitText(/integrity verified|integrity check failed/, 10000));
await clickByText('[role="tab"]', "Integrations");
check("optional integrations shown honestly", await waitText(/not configured/, 10000));
await shot("07-admin");

console.log("\n=== Route smoke test (every page) ===");
const routes = ["/alerts", "/incidents", "/quarantine", "/logs", "/fim", "/vulnerabilities", "/compliance",
  "/network", "/hunt", "/intelligence", "/mitre", "/response", "/agents", "/reports", "/assistant", "/admin", "/settings", "/scan"];
for (const r of routes) {
  await page.goto(`${BASE}${r}`, { waitUntil: "networkidle0", timeout: 30000 }).catch(() => {});
  await new Promise((res) => setTimeout(res, 400));
  const t = await bodyText();
  const inlineErr = await page.$(".alert-box.error");
  const ok = !/Application error|Unhandled Runtime Error|This page could not be found/.test(t) && t.length > 200 && !inlineErr;
  check(`route ${r} renders`, ok);
}
await shot("08-response");

console.log("\n=== Sign out ===");
await page.goto(`${BASE}/dashboard`, { waitUntil: "networkidle0" });
await clickByText("button", "Sign out");
await page.waitForFunction(() => location.pathname === "/login", { timeout: 10000 }).catch(() => {});
check("sign-out returns to /login", (await page.evaluate(() => location.pathname)) === "/login");
await page.goto(`${BASE}/dashboard`, { waitUntil: "networkidle0" });
check("protected page redirects when signed out", (await page.evaluate(() => location.pathname)) === "/login");

check("no uncaught page errors", pageErrors.length === 0, JSON.stringify(pageErrors.slice(0, 3)));
check("no console errors", consoleErrors.length === 0, JSON.stringify(consoleErrors.slice(0, 3)));

await browser.close();
console.log(`\nBROWSER E2E RESULT: ${passed} passed, ${failed.length} failed`);
if (failed.length) { console.log("Failed:", failed.join(" | ")); process.exit(1); }
