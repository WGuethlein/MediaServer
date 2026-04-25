# Docker Media Server v2

Docker Compose stack for Plex + *arrs + supporting services on Ubuntu 25.10.

## Layout

| Path | Purpose |
|---|---|
| `compose/` | Per-service compose files, included from `docker-compose.yml` |
| `traefik/rules/` | Traefik dynamic config (middlewares, TLS opts, manual routers) |
| `traefik/acme/` | Let's Encrypt certificate state (gitignored) |
| `appdata/` | Container persistent state (gitignored) |
| `logs/` | Container logs that bind-mount out (gitignored) |
| `scripts/` | Helper scripts (backup, maintenance, etc.) |
| `secrets/` | Secret files referenced by Docker secrets (gitignored) |
| `.env` | Environment variables (gitignored — see `.env.example`) |

## Operations

```bash
# Start the stack
docker compose up -d

# Tail a service
docker compose logs -f <service>

# Update images (after Diun notifies)
docker compose pull
docker compose up -d --remove-orphans

# Stop everything
docker compose down
```

## Hosts

- `wyatt-serv1` (192.168.1.108) — single-node operator
- NAS: Synology DS224+ at 192.168.1.12, NFS export `/volume1/media` mounted at `/mnt/media`
- Local downloads: `/mnt/local-downloads` on the host's NVMe
