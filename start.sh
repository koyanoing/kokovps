#!/bin/sh
set -e
VOL="${RAILWAY_VOLUME_MOUNT_PATH:-/data}"

mkdir -p "$VOL/home" "$VOL/ssh" /run/sshd
chmod 755 "$VOL" "$VOL/home"

# Keep the same SSH host keys across redeploys so customers never see a key-changed warning.
for t in ed25519 rsa; do
  [ -f "$VOL/ssh/ssh_host_${t}_key" ] || ssh-keygen -q -t "$t" -N "" -f "$VOL/ssh/ssh_host_${t}_key"
done

sed "s#__VOL__#$VOL#g" /app/sshd_config > /etc/ssh/sshd_config.dockyard
printf 'Shared server managed by Dockyard.\nMining, spam and attacks are not allowed.\n' > /etc/motd

/usr/sbin/sshd -f /etc/ssh/sshd_config.dockyard
exec node server.js
