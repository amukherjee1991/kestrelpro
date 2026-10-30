# KestrelPro

DNS blocking with an AI second opinion: a fork of Pi-hole® v6 with the Kestrel review
engine built in. New domains are judged by a local model (Ollama) within seconds;
nothing leaves the network. See [PLAN_LS.md](PLAN_LS.md) for the design.

KestrelPro is a modified version of Pi-hole software (EUPL-1.2). Pi-hole is a registered
trademark of Pi-hole, LLC. KestrelPro is not affiliated with or endorsed by Pi-hole, LLC.

## Layout

| Path | What | Branch |
|---|---|---|
| `docker-pi-hole/` | Fork of pi-hole/docker-pi-hole: image build, `start.sh`, engine supervision | `kestrelpro/2026.10.0-k0` |
| `web/` | Fork of pi-hole/web: the admin UI (unchanged so far; KestrelPro pages arrive in P3) | `kestrelpro/v6.6.1-k0` |
| `engine/` | The review engine (Python): cursor ingest, micro-batches, verdict cache | this repo |
| `compose.yaml` | The product: `kestrelpro` + optional bundled `ollama` | |

The two forks are separate git repos with an `upstream` remote; they are not pushed anywhere yet.

Pinned upstream: docker-pi-hole 2026.10.0, web v6.6.1, core v6.5, FTL v6.8
(SHA-256 `1f511e70…2b0e`, checked at build time).

## Build and run

```bash
cp .env.example .env          # edit
docker compose up -d --build
docker compose exec ollama ollama pull gemma4:12b
```

The admin UI is on `ADMIN_PORT` (8080); the interim engine dashboard is on 8090 until P3.

## Engine

```bash
cd engine
python -m unittest discover -s tests -t .
docker exec kestrelpro sh -c 'cd /opt/kestrel-engine && su-exec kestrel python3 -m kestrel_engine report'
```

The engine signs in to FTL with its CLI password (`/etc/pihole/cli_pw`), which can manage
lists but not change settings. Its database is `/etc/kestrel/kestrel.db`; a `kestrel.db`
from the old add-on is migrated in place on first start.
