# Releasing KestrelPro

Users run a ready-made image, `ghcr.io/amukherjee1991/kestrelpro`, built by
`.github/workflows/image.yml` for PCs (linux/amd64) and Raspberry Pi (linux/arm64 for a 64-bit
OS, linux/arm/v7 for a 32-bit OS). Every push to `main` builds and smoke-tests it without
publishing; a version tag publishes it.

## One-time setup

The image is built from this repository plus the two forks listed in `forks.json`. The
workflow's own token can't read other private repositories, so give it one that can:

1. GitHub → *Settings → Developer settings → Fine-grained personal access tokens → Generate*.
   Repository access: **only** `kestrelpro-web` and `kestrelpro-docker`.
   Permissions: **Contents: Read-only** (nothing else).
2. Store it as a secret of this repository:
   ```bash
   gh secret set FORKS_TOKEN -R amukherjee1991/kestrelpro
   ```
Until then, pushes to `main` show a warning and skip the image build; tags fail.

## Releasing a version

Versions follow the upstream docker release they're built on, plus a KestrelPro revision:
`2026.10.0-k1`, `2026.10.0-k2`, … (a new upstream release starts again at `-k1`).

```bash
git tag v2026.10.0-k1
git push origin v2026.10.0-k1
```

The workflow then smoke-tests the PC build (`tools/smoke-test.sh`: DNS, block list, admin UI,
engine), builds all platforms and publishes `:<version>` and `:latest`. Check a Raspberry Pi
build before a release with:

```bash
docker buildx build --platform linux/arm64 docker-pi-hole/src \
  --build-context kestrelpro-web=./web --build-context kestrelpro-engine=./engine \
  --build-arg CORE_BRANCH=v6.5 --build-arg PADD_BRANCH=master -t kestrelpro:arm64 --load
tools/smoke-test.sh kestrelpro:arm64 linux/arm64      # needs QEMU/binfmt, e.g. Docker Desktop
```

## Who can pull the image

Images in the GitHub container registry start **private**: only you (and people you add) can
pull them, after `docker login ghcr.io`. Keep it that way until the open items in
`docs/DESIGN.md` (*Licensing and names*) are settled, because publishing the image is
distribution:

- the source of each image must be public (EUPL-1.2): make this repository and both forks
  public first, or publish the matching sources alongside each release;
- Pi-hole LLC's confirmation that the internal `pihole` names in an unmodified FTL are acceptable;
- a trademark check on the KestrelPro name;
- remove the old planning notes from this repository's git history before making it public.

Then: GitHub → *Packages → kestrelpro → Package settings → Change visibility → Public*, and
the README's quick start works for anyone.
