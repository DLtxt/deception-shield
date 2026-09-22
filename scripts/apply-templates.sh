#!/usr/bin/env bash
#
# Applies the index templates and ILM policies.
#
# Order matters: a policy referenced by a template must exist before the template
# is applied, or the first index created against it starts unmanaged.

set -euo pipefail

ES_URL=${ES_URL:-http://localhost:9200}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_DIR=${TEMPLATE_DIR:-"${ROOT}/stack/elasticsearch/index-templates"}
POLICY_FILE=${POLICY_FILE:-"${ROOT}/stack/elasticsearch/ilm-policies.json"}
TIMEOUT=${TIMEOUT:-180}

echo "waiting for elasticsearch at ${ES_URL}"
deadline=$(( SECONDS + TIMEOUT ))
until curl -fsS "${ES_URL}/_cluster/health" 2>/dev/null | grep -qE '"status":"(green|yellow)"'; do
    if (( SECONDS >= deadline )); then
        echo "elasticsearch did not become ready within ${TIMEOUT}s" >&2
        exit 1
    fi
    sleep 5
done
echo "elasticsearch is ready"

if [ -r "${POLICY_FILE}" ]; then
    echo "applying ILM policies"
    for policy in $(jq -r 'keys[]' "${POLICY_FILE}"); do
        body=$(jq -c --arg name "${policy}" '.[$name]' "${POLICY_FILE}")
        code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT \
            "${ES_URL}/_ilm/policy/${policy}" \
            -H 'Content-Type: application/json' -d "${body}")
        echo "  ${policy}: HTTP ${code}"
        [[ "${code}" =~ ^2 ]] || exit 1
    done
fi

echo "applying index templates"
shopt -s nullglob
for template in "${TEMPLATE_DIR}"/*.json; do
    name=$(basename "${template}" .json)
    code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT \
        "${ES_URL}/_index_template/${name}" \
        -H 'Content-Type: application/json' \
        --data-binary "@${template}")
    echo "  ${name}: HTTP ${code}"
    [[ "${code}" =~ ^2 ]] || exit 1
done

echo "done"
