#!/usr/bin/env bash
#
# Pulls archived captures out of S3 for offline analysis.
#
# Analysis runs on a workstation rather than on the sensor: the sensor is
# deliberately exposed, so anything that can be done elsewhere should be.

set -euo pipefail

BUCKET=${CAPTURE_BUCKET:-}
SENSOR=${SENSOR_ID:-}
DESTINATION=${DESTINATION:-./captures}
SINCE_DAYS=${SINCE_DAYS:-1}

if [ -z "${BUCKET}" ]; then
    echo "set CAPTURE_BUCKET to the archive bucket" >&2
    echo "  terraform -chdir=infra/terraform output -raw capture_bucket" >&2
    exit 2
fi

PREFIX="pcap/"
[ -n "${SENSOR}" ] && PREFIX="pcap/${SENSOR}/"

mkdir -p "${DESTINATION}"

if [[ "$OSTYPE" == "darwin"* ]]; then
    CUTOFF=$(date -u -v-"${SINCE_DAYS}"d +%Y-%m-%dT%H:%M:%SZ)
else
    CUTOFF=$(date -u -d "${SINCE_DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ)
fi

echo "fetching captures newer than ${CUTOFF} from s3://${BUCKET}/${PREFIX}"

mapfile -t keys < <(
    aws s3api list-objects-v2 \
        --bucket "${BUCKET}" \
        --prefix "${PREFIX}" \
        --query "Contents[?LastModified>='${CUTOFF}'].Key" \
        --output text | tr '\t' '\n' | grep -v '^$' || true
)

if (( ${#keys[@]} == 0 )); then
    echo "no captures in that window"
    exit 0
fi

echo "${#keys[@]} captures to fetch"
for key in "${keys[@]}"; do
    target="${DESTINATION}/$(basename "${key}")"
    [ -f "${target}" ] && { echo "  have $(basename "${key}")"; continue; }
    aws s3 cp "s3://${BUCKET}/${key}" "${target}" --only-show-errors
    echo "  got $(basename "${key}")"
done

echo
echo "analyse them with:"
echo "  make replay CAPTURE=${DESTINATION}"
