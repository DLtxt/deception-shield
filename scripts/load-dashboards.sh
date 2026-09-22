#!/usr/bin/env bash
#
# Imports the Kibana saved objects.
#
# Safe to re-run: the import overwrites objects with matching identifiers, which
# is how a dashboard change is rolled out.

set -euo pipefail

KIBANA_URL=${KIBANA_URL:-http://localhost:5601}
DASHBOARD_DIR=${DASHBOARD_DIR:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/stack/kibana/dashboards"}
TIMEOUT=${TIMEOUT:-180}

echo "waiting for kibana at ${KIBANA_URL}"
deadline=$(( SECONDS + TIMEOUT ))
until curl -fsS "${KIBANA_URL}/api/status" 2>/dev/null | grep -q '"level":"available"'; do
    if (( SECONDS >= deadline )); then
        echo "kibana did not become available within ${TIMEOUT}s" >&2
        exit 1
    fi
    sleep 5
done
echo "kibana is available"

shopt -s nullglob
saved_objects=( "${DASHBOARD_DIR}"/*.ndjson )
if (( ${#saved_objects[@]} == 0 )); then
    echo "no saved object files in ${DASHBOARD_DIR}" >&2
    exit 1
fi

for file in "${saved_objects[@]}"; do
    echo "importing $(basename "${file}")"
    response=$(curl -sS -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
        -H "kbn-xsrf: true" \
        --form "file=@${file}")

    if grep -q '"success":true' <<<"${response}"; then
        count=$(grep -o '"successCount":[0-9]*' <<<"${response}" | cut -d: -f2)
        echo "  imported ${count:-?} objects"
    else
        echo "  import reported a problem:" >&2
        echo "${response}" >&2
        exit 1
    fi
done

echo
echo "open ${KIBANA_URL}/app/dashboards"
