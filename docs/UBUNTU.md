# KestrelPro on Ubuntu

A step-by-step install on **Ubuntu 22.04, 24.04 or 26.04** (Server or Desktop), on a PC,
a mini-PC or server (x86-64), or **Ubuntu Server on a Raspberry Pi** (arm64). The same
ready-made image runs on all of them; nothing is built on your machine.

Already running Pi-hole on this machine? Read [MIGRATING.md](MIGRATING.md) first, then come
back for the Ubuntu-specific steps.

Commands are run as a normal user with `sudo`. Addresses such as `192.168.1.50` are examples:
use your own.

## 1. Give the machine a fixed address

Your devices will use this machine for DNS, so its address must not change. The easiest way is
a **DHCP reservation** in your router (look for "static lease", "address reservation" or
"fixed IP"), then reboot the machine and check it with:

```bash
ip -br addr
```

<details>
<summary>Or set a static address on the machine with netplan</summary>

Find the network interface name (`ip -br addr`, e.g. `enp1s0` or `eth0`) and create
`/etc/netplan/60-kestrelpro.yaml`:

```yaml
network:
  version: 2
  ethernets:
    enp1s0:
      dhcp4: false
      addresses: [192.168.1.50/24]
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [1.1.1.1, 9.9.9.9]
```

```bash
sudo chmod 600 /etc/netplan/60-kestrelpro.yaml
sudo netplan try        # keeps the change only if you confirm within 120 s
```

Keep the machine itself on a public resolver (as above) rather than on KestrelPro, so it can
still download updates when KestrelPro is stopped.
</details>

## 2. Install Docker

Use Docker's own packages (Ubuntu's `docker.io` package and the Docker snap often lack the
Compose v2 plugin). If you ticked Docker during the Ubuntu Server install, remove the snap
first: `sudo snap remove docker`.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker "$USER"     # run docker without sudo; log out and back in afterwards
```

Check it after logging back in:

```bash
docker run --rm hello-world
docker compose version              # must print v2.x
```

## 3. Free port 53

Ubuntu's own resolver, `systemd-resolved`, listens on port 53 for the machine itself, so
KestrelPro can't. Turn off just that listener; the machine keeps resolving names normally:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/kestrelpro.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

Check that port 53 is now free (no output) and that the machine still resolves names:

```bash
sudo ss -lntup 'sport = :53'
getent hosts github.com
```

If `ss` still shows something on port 53, it's another DNS server (`dnsmasq`, `bind9`,
`unbound`, or an old Pi-hole): stop and disable it, or see [MIGRATING.md](MIGRATING.md).

## 4. Install KestrelPro

```bash
mkdir ~/kestrelpro && cd ~/kestrelpro
curl -fsSLO https://raw.githubusercontent.com/amukherjee1991/kestrelpro/main/compose.yaml
curl -fsSL https://raw.githubusercontent.com/amukherjee1991/kestrelpro/main/.env.example -o .env
nano .env
```

In `.env`, set at least:

- `ADMIN_PASSWORD=`: the admin UI password (required).
- `TZ=`: your time zone, e.g. `Europe/Berlin` (`timedatectl` shows the machine's).

> While the image is private ([RELEASING.md](RELEASING.md)), sign in to the registry first with
> a GitHub token that has the `read:packages` scope:
> `docker login ghcr.io -u <your-github-user>`.

Then choose where the AI model runs:

| This machine has | Do this |
|---|---|
| An NVIDIA GPU with 8 GB+ | [Step 5a](#5a-nvidia-gpu), then start with `compose.nvidia.yaml` |
| An AMD GPU supported by ROCm | [Step 5b](#5b-amd-gpu), then start with `compose.amd.yaml` |
| No GPU, but another computer on the network has one | [Step 5c](#5c-model-on-another-computer) |
| No GPU at all | Start as is, use a 3–4B model and `CADENCE=eco` in `.env` |

## 5a. NVIDIA GPU

Install the driver and the NVIDIA Container Toolkit, so containers can use the GPU:

```bash
sudo ubuntu-drivers install         # then reboot
nvidia-smi                          # shows your GPU

curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list > /dev/null
sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

Download the GPU file and start:

```bash
cd ~/kestrelpro
curl -fsSLO https://raw.githubusercontent.com/amukherjee1991/kestrelpro/main/compose.nvidia.yaml
docker compose -f compose.yaml -f compose.nvidia.yaml up -d
docker compose exec ollama ollama pull gemma4:12b
```

## 5b. AMD GPU

Ubuntu's kernel already includes the AMD GPU driver; check that the compute device exists with
`ls /dev/kfd`. Then:

```bash
cd ~/kestrelpro
curl -fsSLO https://raw.githubusercontent.com/amukherjee1991/kestrelpro/main/compose.amd.yaml
docker compose -f compose.yaml -f compose.amd.yaml up -d
docker compose exec ollama ollama pull gemma4:12b
```

If the model runs on the CPU anyway (`docker compose logs ollama` says so), your GPU may need
`HSA_OVERRIDE_GFX_VERSION`; see Ollama's AMD GPU documentation.

## 5c. Model on another computer

Run [Ollama](https://ollama.com) on the computer with the GPU, reachable from the network
(`OLLAMA_HOST=0.0.0.0`), and pull the model there (`ollama pull gemma4:12b`). In `.env` on
this machine:

```bash
COMPOSE_PROFILES=
OLLAMA_URL=http://192.168.1.60:11434
```

Then start KestrelPro on its own:

```bash
docker compose up -d
```

This is also the usual setup for **Ubuntu on a Raspberry Pi**.

## 6. Check it works

```bash
docker compose ps                                   # kestrelpro (and ollama) "Up"/"healthy"
dig @127.0.0.1 example.com +short                   # an address
dig @127.0.0.1 doubleclick.net +short               # 0.0.0.0: blocked by the lists
```

(`dig` is in the `dnsutils` package: `sudo apt-get install -y dnsutils`.)

Open `http://192.168.1.50:8080/admin/` from another device, sign in with `ADMIN_PASSWORD`, and
look for **KestrelPro → AI review** in the menu. Its status shows whether the model is
reachable.

## 7. Point your network at it

In your router's DHCP settings, set the DNS server to this machine's address
(`192.168.1.50`), with no second DNS server (devices would use it to bypass blocking). Devices
pick it up when they renew their lease; reconnecting Wi-Fi speeds that up.

Leave **AI settings** on *Review first* for a few days and check **Needs approval** before you
switch to Automatic.

## Firewall and security

- **Docker bypasses `ufw`.** Ports published by Docker (53, 8080, 8090) are reachable even if
  `ufw` denies them. On a home network behind a router that's what you want.
- **Never expose port 53 to the internet.** On a server with a public address (a cloud VPS,
  or a machine in your router's DMZ) an open DNS server is abused for attacks within hours. Set
  `DNS_BIND_IP` in `.env` to the machine's private address, and block 53, 8080 and 8090 in
  your provider's firewall.
- For HTTPS on the admin UI, put a reverse proxy in front; see the README.

## Day to day

```bash
cd ~/kestrelpro
docker compose pull && docker compose up -d     # update (add the same -f files you started with)
docker compose logs -f kestrelpro               # logs
docker compose restart kestrelpro               # restart
```

KestrelPro starts by itself after a reboot. Back up `./etc-pihole` and `./etc-kestrel` (or use
*Settings → Teleporter* for the block-list settings).

## Uninstall

First point your router back at another DNS server, then stop KestrelPro:

```bash
cd ~/kestrelpro && docker compose down
```

Give port 53 back to Ubuntu:

```bash
sudo rm /etc/systemd/resolved.conf.d/kestrelpro.conf
sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

Delete `~/kestrelpro` to remove all settings and data (and `./ollama` holds the downloaded models).
