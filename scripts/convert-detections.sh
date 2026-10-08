#!/usr/bin/env bash
#
# Converts the Sigma rules into Elasticsearch artefacts with sigma-cli.
#
#   stack/kibana/detections/deception-shield-detections.ndjson
#       One Discover saved search per rule, pointed at the stack's data view.
#       Committed, imported by load-dashboards.sh and the elk role, and checked
#       by CI to match the rules it was generated from.
#
#   build/detections/lucene.txt
#       The converted query for each rule, for reading or pasting into Discover.
#
#   build/detections/siem-rules.ndjson
#       Elastic Security detection rules. Generating them needs ATT&CK data
#       from the network, and importing them needs a Kibana with security
#       enabled, so they are a build artefact rather than part of the stack.
#
# Requires sigma-cli with the Elasticsearch backend, and jq:
#   pip install sigma-cli pySigma-backend-elasticsearch

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGMA=${SIGMA:-sigma}
RULES=${RULES:-"${ROOT}/detections/sigma"}
PIPELINE=${PIPELINE:-"${ROOT}/detections/pipelines/cowrie-ecs.yml"}
SEARCHES=${SEARCHES:-"${ROOT}/stack/kibana/detections/deception-shield-detections.ndjson"}
BUILD=${BUILD:-"${ROOT}/build/detections"}
DATA_VIEW=${DATA_VIEW:-ds-telemetry-view}
INDEX=${INDEX:-logs-honeypot-deception*}
SIEM_RULES=${SIEM_RULES:-1}

if ! command -v "${SIGMA}" >/dev/null 2>&1; then
    echo "sigma-cli not found; pip install sigma-cli pySigma-backend-elasticsearch" >&2
    exit 2
fi

mkdir -p "$(dirname "${SEARCHES}")" "${BUILD}"

convert() {
    "${SIGMA}" convert --target lucene --pipeline "${PIPELINE}" "$@" "${RULES}" 2>/dev/null
}

# sigma-cli writes these the way Kibana 7 did: the "beats-*" data view inlined,
# the query as raw query_string DSL, a flat sort. Rewrite each one into the shape
# Kibana 8 exports, pointed at the stack's own data view, so the import needs no
# migration. Sorting by id means the file changes only when a rule does.
convert --format kibana_ndjson \
    | jq -c --arg view "${DATA_VIEW}" '
        .attributes.kibanaSavedObjectMeta.searchSourceJSON |= (
            fromjson
            | {
                query: {query: .query.query_string.query, language: "lucene"},
                filter: [],
                indexRefName: "kibanaSavedObjectMeta.searchSourceJSON.index"
              }
            | tojson
          )
        | .attributes.description = "Converted from Sigma rule \(.id) by sigma-cli"
        | .attributes.columns = ["source.ip", "user.name", "session.id", "process.command_line"]
        | .attributes.sort = [["@timestamp", "desc"]]
        | .references = [{
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
            "id": $view
          }]
        | .migrationVersion = {"search": "8.0.0"}' \
    | sort > "${SEARCHES}"
echo "wrote $(wc -l < "${SEARCHES}" | tr -d ' ') saved searches to ${SEARCHES#"${ROOT}/"}"

convert > "${BUILD}/lucene.txt"
echo "wrote ${BUILD#"${ROOT}/"}/lucene.txt"

if [ "${SIEM_RULES}" = 1 ]; then
    convert --format siem_rule_ndjson --backend-option "index_names=${INDEX}" > "${BUILD}/siem-rules.ndjson"
    echo "wrote ${BUILD#"${ROOT}/"}/siem-rules.ndjson"
fi
