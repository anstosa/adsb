#!/usr/bin/env bash
set -euo pipefail

# require explicit public inputs
if [[ ${EUID:-$(id -u)} -ne 0 || $# -ne 2 ]]; then
    printf '%s\n' 'usage: sudo install-source.sh PUBLIC_KEY_FILE AGE_RECIPIENT_FILE' >&2
    exit 2
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
public_key_file=$1
recipient_file=$2

# require the application-installed age binary
[[ -x /usr/bin/age ]] || {
    printf '%s\n' 'error: /usr/bin/age is required' >&2
    exit 1
}

# read one public SSH key
mapfile -t public_key_lines <"$public_key_file"
[[ ${#public_key_lines[@]} -eq 1 && ${public_key_lines[0]} =~ ^(ssh-ed25519|ssh-rsa)[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]] || {
    printf '%s\n' 'error: invalid SSH public key' >&2
    exit 1
}

# read one public age recipient
mapfile -t recipient_lines <"$recipient_file"
[[ ${#recipient_lines[@]} -eq 1 && (${recipient_lines[0]} == age1* || ${recipient_lines[0]} == ssh-*) ]] || {
    printf '%s\n' 'error: invalid age recipient' >&2
    exit 1
}

# create the isolated source account
if ! getent passwd adsb-backup >/dev/null; then
    useradd --system --home-dir /var/lib/adsb-backup --shell /bin/bash adsb-backup
fi
usermod --home /var/lib/adsb-backup --shell /bin/bash --lock adsb-backup
install -d -o root -g root -m 755 /var/lib/adsb-backup /var/lib/adsb-backup/.ssh
install -d -o root -g root -m 755 /etc/adsb-backup

# install the fixed command boundary
install -o root -g root -m 755 "$source_dir/ssh-entrypoint.sh" /usr/local/bin/adsb-backup-ssh-dispatch
install -o root -g root -m 755 "$source_dir/remote-ops-entrypoint.sh" /usr/local/sbin/adsb-backup-remote-ops
install -o root -g root -m 440 "$source_dir/adsb-backup.sudoers" /etc/sudoers.d/adsb-backup
/usr/sbin/visudo -cf /etc/sudoers.d/adsb-backup >/dev/null

# publish only public key material
printf 'restrict,command="/usr/local/bin/adsb-backup-ssh-dispatch" %s\n' "${public_key_lines[0]}" >/var/lib/adsb-backup/.ssh/authorized_keys
printf '%s\n' "${recipient_lines[0]}" >/etc/adsb-backup/recipient.txt
chown root:root /var/lib/adsb-backup/.ssh/authorized_keys /etc/adsb-backup/recipient.txt
chmod 644 /var/lib/adsb-backup/.ssh/authorized_keys
chmod 600 /etc/adsb-backup/recipient.txt

# verify the installed read boundary
/opt/adsb/current/deploy/backup/backup-proof.sh >/dev/null
