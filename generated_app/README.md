# generated_app/ — Status: Not deployed to production

This is a FastAPI + Celery container stack, runnable locally via the root
`docker-compose.yml` (`uvicorn generated_app.main:app`, Celery workers against
`generated_app.core.celery_app`). It is **not** the platform running at
https://cyberdudebivash.in.

The production backend is the Cloudflare Worker in `../workers/src/` (JS),
deployed by `.github/workflows/deploy.yml` directly to Cloudflare's edge —
no Docker, no FastAPI, no Celery involved. `generated_app/` and `workers/`
are two independent implementations; only `workers/` is live.

## Why it's still in the repo

It's a self-contained alternative deployment target (e.g. for self-hosting
off Cloudflare). If you are extending the live platform, changes belong in
`workers/src/`, not here — edits to `generated_app/` will not appear on
cyberdudebivash.in.
