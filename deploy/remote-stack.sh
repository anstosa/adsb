#!/bin/sh
# invoke only the production ADS-B stack controls through the fixed SSH alias
set -eu

# require exactly one allowlisted RemoteAgents operation
if [ "$#" -ne 1 ]; then
    printf '%s\n' 'expected exactly one of: status, start, stop, restart' >&2
    exit 64
fi

# block shell fragments before crossing the SSH boundary
case "$1" in
    status|start|stop|restart) ;;
    *)
        printf '%s\n' 'expected exactly one of: status, start, stop, restart' >&2
        exit 64
        ;;
esac

exec /usr/bin/ssh -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
    adsb sudo -n /usr/local/sbin/adsb-stack "$1"
