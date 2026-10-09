# Browser end-to-end test

`browser_e2e.mjs` drives the real UI with headless Chromium (puppeteer-core). It covers sign-in, the live dashboard, EICAR and upload scans with progress, the scan report, alert triage, the assistant, report generation, admin tabs, a smoke pass over every route (fails on inline error alerts), console/page-error capture, sign-out and route protection.

## Run

Start the API (`:8000`) and the web app (`:3000`), then:

```bash
npm i --no-save puppeteer-core          # or use an existing install
MS_ADMIN_PASSWORD='your-admin-password' CHROME_PATH=/usr/bin/chromium node e2e/browser_e2e.mjs
```

Screenshots are written to `./screens` (override with `MS_SHOTS`). The directory is git-ignored.

## Notes

- The API E2E suite deliberately trips the auth rate limit from the same IP. Wait 60 seconds before running this suite.
- Without `CHROME_PATH`, the script tries `@sparticuz/chromium` (a Chromium build packaged for AWS Lambda). It may need `LD_LIBRARY_PATH` pointing at the bundled Amazon Linux libraries on non-Lambda hosts.
