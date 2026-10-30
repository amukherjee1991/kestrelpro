# KestrelPro

DNS blocking with an AI second opinion: a fork of Pi-hole® v6 with the Kestrel review
engine built in. New domains are judged by a local model (Ollama) within seconds;
nothing leaves the network. See [PLAN_LS.md](PLAN_LS.md) for the design.

![AI review overview](docs/screenshots/ai-review-overview.png)

KestrelPro is a modified version of Pi-hole software (EUPL-1.2). Pi-hole is a registered
trademark of Pi-hole, LLC. KestrelPro is not affiliated with or endorsed by Pi-hole, LLC.

## Layout

| Path | What | Branch |
|---|---|---|
| `docker-pi-hole/` | Fork of pi-hole/docker-pi-hole: image build, `start.sh`, engine supervision | `kestrelpro/2026.10.0-k0` |
| `web/` | Fork of pi-hole/web: the admin UI with the KestrelPro pages, debranded | `kestrelpro/v6.6.1-k0` |
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

Open the admin UI on `ADMIN_PORT` (8080) and choose **KestrelPro → AI review** in the menu.
There is one login: the admin UI's. The pages call the engine with that session.

### How the browser reaches the engine

- **Default (no proxy):** the pages call the engine on the same host at `KESTREL_ENGINE_PORT`
  (8090). The container adds that port to the admin UI's Content-Security-Policy on start-up.
  This needs plain HTTP: a page served over HTTPS can't call an HTTP engine.
- **Behind a reverse proxy (recommended with HTTPS):** route `/admin/api/kestrel/*` to the
  engine (port 8090 in the container) and everything else to the admin UI, then set
  `KESTREL_ENGINE_URL=/admin/api/kestrel`. Example for Caddy:

  ```caddyfile
  dns.example.lan {
      reverse_proxy /admin/api/kestrel/* 192.168.1.53:8090
      reverse_proxy 192.168.1.53:8080
  }
  ```

The engine accepts a request only with a live admin-UI session (`sid` cookie, checked with
FTL and cached for 10 s); changes also need that session's CSRF token. An admin password
is required: a password-less admin UI is treated as signed out.

## Safety net

- **Trial period.** A new automatic block is on trial for 24 h. It is withdrawn (back to
  *Needs approval*) if you unblock another domain of the same site, or if two or more devices
  each retry it 20+ times within 5 minutes, which is what broken apps do. Tunable in AI settings.
- **Pause.** *Pause KestrelPro blocks* on the AI review page (or `kestrel_engine pause`)
  disables every block KestrelPro added, without deleting anything; *Resume* turns them back
  on. Your block lists are not affected. While paused, Automatic mode only suggests.
- **Something broke?** Pick a device and a time window to see the KestrelPro blocks it ran
  into, busiest first, with *Unblock* and *Never block*.
- **Query Log.** Domains KestrelPro has judged get an AI badge. Clicking it shows the verdict,
  which list or rule blocked the domain, and one-click actions.

| | |
|---|---|
| ![Query Log](docs/screenshots/querylog-ai-explanation.png) | ![Something broke?](docs/screenshots/something-broke.png) |
| AI verdict in the Query Log | Something broke? |

## Device policies, models and accuracy

- **Device policies.** Give a group of devices (Group Management → Clients) its own rules:
  same as AI settings, Review first, Automatic or Off, with its own threshold and kinds of
  domain. An automatic block made under a group's policy is assigned to that group only, so
  other devices are unaffected; Decisions labels it, e.g. "Kids only". Blocks you make or
  approve yourself apply to everyone. A device only in a non-Default group gets no block lists
  unless they're assigned to that group too; the page warns about such groups.
- **Models.** Installed models with GPU/CPU placement; download with progress; *Use* switches
  and pins the exact build (a later `ollama pull` that changes it shows a warning until you
  re-pin); delete; *Benchmark* grades a model against your own decisions.
- **Accuracy.** Your *Block* / *Don't block* decisions are a labelled set: how often the model
  agrees with you, by category and model, and where you disagree. With *Learn from my
  decisions* on (AI settings), a few recent decisions are shown to the model as examples;
  verdicts made that way carry a `+fs` prompt version.

| | |
|---|---|
| ![Device policies](docs/screenshots/device-policies.png) | ![Models](docs/screenshots/models-benchmark.png) |
| Device policies | Models and a benchmark |
| ![Accuracy](docs/screenshots/accuracy.png) | ![Kids-only blocks](docs/screenshots/decisions-device-policy.png) |
| Accuracy | Blocks under a device policy |

## Screenshots

Taken from a test container filled with made-up data (`engine/tools/seed_demo.py`).

| | |
|---|---|
| ![Needs approval](docs/screenshots/needs-approval.png) | ![Decisions](docs/screenshots/decisions-blocked.png) |
| Needs approval | Decisions |
| ![History](docs/screenshots/history.png) | ![AI settings](docs/screenshots/ai-settings.png) |
| History | AI settings |
| ![Dark theme](docs/screenshots/ai-review-overview-dark.png) | ![Login](docs/screenshots/login.png) |
| Dark theme | Sign-in |

All screenshots are in [docs/screenshots/](docs/screenshots/), including phone layouts.

## Design

The whole admin UI, not only the KestrelPro pages, uses one modern skin
(`web/style/kestrelpro.css`, dark tokens in `kestrelpro-dark.css`): neutral surfaces, the
falcon's rust as the single accent, stat tiles as cards, soft badges, visible keyboard focus.
Motion is limited to press feedback and the dialog entrance, and is off under the system's
reduced-motion setting. It applies to the Default themes (light, dark, darker, auto); LCARS
and the high-contrast themes are left as upstream ships them.

| | |
|---|---|
| ![Dashboard](docs/screenshots/dashboard.png) | ![Query Log](docs/screenshots/querylog-light.png) |
| Dashboard | Query Log |
| ![Domains](docs/screenshots/domains-dark.png) | ![System settings](docs/screenshots/settings-system-dark.png) |
| Domains (dark) | System settings (dark) |

## Debranding

Pi-hole's trademark rules forbid redistributing the software with its marks. In `web/`,
`tools/debrand.sh` replaces them (logo, favicons, name in titles and text, links to Pi-hole's
website and donation page) and `tools/check-branding.sh` fails if any are left. The result
is one generated commit at the top of the web fork's branch; see
`web/KESTRELPRO-CHANGES.md` for the rebase procedure. The About page states the software's
origin and links to the upstream project.

## Engine

```bash
cd engine
python -m unittest discover -s tests -t .
docker exec kestrelpro sh -c 'cd /opt/kestrel-engine && su-exec kestrel:pihole python3 -m kestrel_engine report'   # once | undo | pause | resume
```

The engine signs in to FTL with its CLI password (`/etc/pihole/cli_pw`), which can manage
lists but not change settings. Its database is `/etc/kestrel/kestrel.db`; a `kestrel.db`
from the old add-on is migrated in place on first start.
