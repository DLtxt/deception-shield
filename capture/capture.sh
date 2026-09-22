#!/usr/bin/env bash
#
# Full packet capture on the sensor interface.
#
# Rotation is driven by both time and size so that no single file grows
# unbounded during a sustained scan, and each closed file is gzipped so the
# extractor can tell a finished rotation from the one being written.
#
# Management traffic is excluded from the capture. Recording an operator's own
# SSH session would add nothing and would put administrative activity into an
# archive that is deliberately treated as hostile data.

set -euo pipefail

CONFIG=${CONFIG:-/etc/deception-shield/sensor.env}
if [ -r "$CONFIG" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG"
fi

INTERFACE=${CAPTURE_INTERFACE:-eth0}
DESTINATION=${CAPTURE_DIR:-/data/pcap}
ROTATE_SECONDS=${ROTATE_SECONDS:-900}
ROTATE_SIZE_MB=${ROTATE_SIZE_MB:-256}
RING_SIZE=${RING_SIZE:-512}

MANAGEMENT_FILTER='not (port 64294 or port 64295 or port 64297)'

mkdir -p "$DESTINATION"

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "capture interface $INTERFACE does not exist" >&2
    exit 1
fi

echo "capturing on $INTERFACE into $DESTINATION" >&2
echo "rotating every ${ROTATE_SECONDS}s or ${ROTATE_SIZE_MB}MB, keeping $RING_SIZE files" >&2

# -s 0 keeps whole frames: a truncated payload cannot be dissected later.
# -z gzip runs after each rotation, which is also the signal the extractor
#    watches for to know a file is complete.
exec tcpdump \
    -i "$INTERFACE" \
    -nn \
    -s 0 \
    -G "$ROTATE_SECONDS" \
    -C "$ROTATE_SIZE_MB" \
    -W "$RING_SIZE" \
    -w "${DESTINATION}/sensor-%Y%m%d-%H%M%S.pcap" \
    -z /usr/bin/gzip \
    "$MANAGEMENT_FILTER"
