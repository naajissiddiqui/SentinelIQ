# Isolated rehearsal environment (`npm run demo`)

For presenting the real application, follow [PRESENTATION.md](PRESENTATION.md). This page covers
the separate rehearsal copy, which never touches your real data.

```powershell
$env:MONGOD_BIN = "C:\path\to\mongod.exe"   # any local MongoDB 6.x/7.x server binary
npm run demo                                  # add -- --verify-amoy for a read-only check of the published report
```

The script does the following:

- Starts a MongoDB in a temporary directory. It never reads `MONGO_URI` from `apps/backend/.env`.
- Starts the backend on port 4123 and the web app on port 3005.
- Registers a rehearsal organisation and a "Network Sensor (recorded traffic)" endpoint.
- Forwards the recorded-traffic alerts in `data/recorded-traffic/` through the sensor's
  `ingest-alerts` forwarder: three from the machine-learning detector and one from the packet-rate
  rule.

Publishing is disabled because the backend is given an unreachable RPC, so a publish attempt fails
visibly and no transaction is sent. The script prints the URL, a local-only sign-in
(`rehearsal-analyst@sentineliq.local` / `Rehearsal-local-2026`) and a detection link. Ctrl+C stops
everything it started.

Options:

- `--no-web`: API only.
- `--exit`: load the data, print a summary and stop.
- `DEMO_MONGO_PORT`, `DEMO_API_PORT`, `DEMO_WEB_PORT`: change the ports.

Provenance and hashes for the alert files are in
[`data/recorded-traffic/README.md`](../data/recorded-traffic/README.md).
