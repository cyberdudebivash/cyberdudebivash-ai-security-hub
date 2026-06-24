# ai-core/ — Status: Not deployed to production

This is a standalone Python agent/scanner framework. It is **not** part of the
live CYBERDUDEBIVASH AI Security Hub at https://cyberdudebivash.in.

The production backend is the Cloudflare Worker in `../workers/src/` (JS),
deployed by `.github/workflows/deploy.yml`. `ai-core/` has no runtime path
into that Worker — there is no import, RPC call, or build step connecting
the two.

## Why it's still in the repo

CI (`lint-ai-core` in `.github/workflows/ci.yml`) runs syntax checks and
`pip-audit` against this code, so it is exercised and dependency-scanned,
but never executed in production. Treat it as an incubating module: useful
for prototyping agent/scanner logic before porting it to the Worker, not a
second production surface.

If you are looking for the code that actually serves traffic, see
`README.md` → Architecture, and `workers/`.
