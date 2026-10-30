# Moving to KestrelPro

KestrelPro is built on Pi-hole v6, so it uses the same configuration directory
(`/etc/pihole`, mounted from `./etc-pihole`), the same `FTLCONF_*` settings and the same
Teleporter backups. Its own data lives separately in `./etc-kestrel`.

Pick the section that matches what you run today. In every case, start KestrelPro in
**Review first** mode (`DRY_RUN=true`, the default) and switch to Automatic only after you've
checked its suggestions for a few days.

## Before you start (all cases)

1. **Back up.** In your current admin UI: *Settings → Teleporter → Export*. Keep the file.
2. **Free port 53.** Only one DNS server can listen on port 53 per address. On many Linux
   desktops `systemd-resolved` holds it; see [Port 53 is already in use](#port-53-is-already-in-use).
3. **Have a fallback.** Note your router's current DNS settings, so you can point clients
   back at another resolver if anything goes wrong.

## From Pi-hole v6 in Docker

1. Copy (don't share) the configuration directory. Two DNS servers must never use the same
   `gravity.db` at once.
   ```bash
   cp -a /path/to/pihole/etc-pihole ./etc-pihole
   ```
2. Copy your `FTLCONF_*` settings (and `TZ`) from the old `docker-compose.yml` into `.env`.
   Set `ADMIN_PASSWORD` (it replaces `FTLCONF_webserver_api_password`).
3. Stop the old container and start KestrelPro; the gap is a few seconds and clients retry:
   ```bash
   docker stop pihole
   docker compose up -d --build
   ```
4. Check it: `dig @<this-host> example.com` resolves, a domain on your block lists returns
   `0.0.0.0`, and the admin UI (port `ADMIN_PORT`) shows **KestrelPro → AI review** in the menu.

**Rollback:** `docker compose down`, then `docker start pihole`. Your old directory was
never touched.

## From Pi-hole v5, or a Pi-hole installed without Docker (the usual Raspberry Pi install)

On a Raspberry Pi, install Docker first (`curl -fsSL https://get.docker.com | sh`), then clone
KestrelPro as in the README's quick start. Keep the model on another machine (see the README's
Raspberry Pi section).

1. Export a Teleporter backup from the old admin UI (v5 backups are accepted by v6).
2. Start KestrelPro with an empty `./etc-pihole` (or move the old install's port 53 first;
   see the next step).
3. Stop the old Pi-hole (`sudo systemctl stop pihole-FTL` and disable it) so port 53 is free,
   then `docker compose up -d --build`.
4. In KestrelPro's admin UI: *Settings → Teleporter → Import* the backup.

## From the Kestrel add-on (a separate `kestrel` container next to Pi-hole)

KestrelPro includes the add-on's engine, so its decisions and history come along:

1. Do the steps for your Pi-hole above.
2. Copy the add-on's database before starting KestrelPro:
   ```bash
   mkdir -p ./etc-kestrel && cp /path/to/kestrel-data/kestrel.db ./etc-kestrel/
   ```
   It's upgraded in place on first start. Blocks it made stay in the deny list with their
   `kestrel:` comments, so undo, pause and History keep working.
3. Carry over your settings: `DRY_RUN`, `MODEL`, `MIN_CONFIDENCE`, `BLOCK_CATEGORIES`,
   `INTERVAL_SECONDS` and `PROTECTED_DOMAINS` keep their names; `VPN_SUBNET` still works
   (`VPN_SUBNETS` takes several ranges). `PIHOLE_URL`, `PIHOLE_PASSWORD` and
   `DASHBOARD_PASSWORD` are no longer needed: there's one login, the admin UI's.
4. Remove the old `kestrel` container. Its dashboard on port 8090 is replaced by the
   KestrelPro pages in the admin UI.

## Switching with almost no DNS gap

If even a few seconds without DNS matter (many devices, or clients that cache failures),
run KestrelPro next to the old server first:

1. Give the host a second address, or use a second machine, and start KestrelPro there
   with `DNS_BIND_IP` set to that address.
2. Test it directly (`dig @<new-address> ...`).
3. Change the DNS server your router hands out (DHCP) to the new address. Clients move over
   as their leases renew; both servers answer in the meantime.
4. When the old server's query log goes quiet, stop it.

## Port 53 is already in use

`docker compose up` fails with "address already in use" when another DNS service listens on
port 53. On Ubuntu and many other desktops this is `systemd-resolved`:

```bash
sudo sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
```

Or publish DNS on one specific address with `DNS_BIND_IP`, leaving the loopback resolver alone.
