# UDMS Restore Procedure

In the event of disk failure or catastrophic config corruption.

## Prerequisites
- Restic password (memorized or stored externally — NOT on the dead host)
- Restic repo accessible at /srv/backups/restic-repo (or wherever you copied it)
- Docker installed on the new/recovered host

## Steps

1. Restore the secret file:
```bash
   echo -n 'YOUR-PASSWORD' > /tmp/restic_password
   chmod 600 /tmp/restic_password
```

2. List available snapshots:
```bash
   docker run --rm \
     -v /srv/backups:/srv/backups \
     -v /tmp/restic_password:/run/secrets/restic_password:ro \
     -e RESTIC_PASSWORD_FILE=/run/secrets/restic_password \
     -e RESTIC_REPOSITORY=/srv/backups/restic-repo \
     restic/restic:0.17.3 \
     snapshots
```

3. Pick a snapshot ID (or use `latest`) and restore everything to a target dir:
```bash
   mkdir -p /home/docker_user/mediaserver
   docker run --rm \
     -v /srv/backups:/srv/backups \
     -v /home/docker_user/mediaserver:/restore-target \
     -v /tmp/restic_password:/run/secrets/restic_password:ro \
     -e RESTIC_PASSWORD_FILE=/run/secrets/restic_password \
     -e RESTIC_REPOSITORY=/srv/backups/restic-repo \
     restic/restic:0.17.3 \
     restore latest \
       --target /restore-target \
       --include /home/docker_user/mediaserver
```

4. The restore puts everything under `/restore-target/home/docker_user/mediaserver/...` (preserves absolute paths). Move it:
```bash
   sudo mv /restore-target/home/docker_user/mediaserver/* /home/docker_user/mediaserver/
   sudo chown -R docker_user:docker_user /home/docker_user/mediaserver
```

5. Bring up the stack:
```bash
   cd /home/docker_user/mediaserver
   docker compose up -d
```

6. Verify per the Phase 8 Stage F regression matrix.

## Notes
- Plex media files (/data/media) are NOT in the backup. They're large and recoverable.
- Download history may show items as "missing" until the *arrs rescan their libraries.
- DNS records and Cloudflare API tokens are in the backup but Cloudflare-side state isn't.
