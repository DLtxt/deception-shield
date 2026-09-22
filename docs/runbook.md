# Runbook

## Daily

```bash
make report SINCE=24h
```

Reports render as Markdown by default and as JSON with `FORMAT=json`.

## Checking a sensor

```bash
ssh -p 64295 ubuntu@<sensor>

systemctl status deception-capture deception-extractor
df -h /data
docker ps --format 'table {{.Names}}\t{{.Status}}'
journalctl -u deception-extractor --since '1 hour ago'
```

## Captures are not appearing

Confirm the capture service is running and pointed at the right interface:

```bash
systemctl status deception-capture
grep CAPTURE_INTERFACE /etc/deception-shield/sensor.env
ip -br link
```

The interface on a Nitro instance is usually `ens5` rather than `eth0`. Correct
`capture_interface` in the inventory and re-run the playbook rather than editing
the environment file directly, since the playbook rewrites it.

## Records are not reaching Elasticsearch

Work along the path:

```bash
ls -lh /data/pcap | tail                      # is tcpdump writing?
journalctl -u deception-extractor -n 50       # is tshark dissecting?
docker logs logstash --tail 50                # is Logstash accepting?
curl -s localhost:64298/_cat/indices/logs-*   # are documents landing?
```

The extractor only processes captures whose size has stopped changing, so the
currently open capture is always skipped. A sensor writing its first rotation has
nothing to dissect until that rotation closes.

## The data volume is filling

Captures are removed after they are archived, so a filling volume usually means
archival is failing:

```bash
grep CAPTURE_BUCKET /etc/deception-shield/sensor.env
aws s3 ls s3://<bucket>/pcap/ --recursive | tail
journalctl -u deception-extractor | grep -i archive
```

For immediate relief, shorten `ROTATE_SECONDS` so files close and clear sooner.

## Elasticsearch is unhealthy

```bash
curl -s localhost:64298/_cluster/health?pretty
curl -s localhost:64298/_cat/indices?v&health=red
```

A single-node cluster reports yellow because replicas cannot be allocated, which
is expected. Red means a primary shard is unassigned, most often from disk
pressure — Elasticsearch stops writing at the flood-stage watermark and needs
space freed before it resumes.

## Rolling out a pipeline change

Edit the definitions in `stack/`, then:

```bash
make validate
make provision
```

The playbook copies the definitions to each sensor and restarts Logstash.

## Reprocessing archived captures

```bash
export CAPTURE_BUCKET=$(terraform -chdir=infra/terraform output -raw capture_bucket)
SINCE_DAYS=7 ./scripts/fetch-captures.sh
make replay CAPTURE=captures
```

Records carry a fingerprint derived from source, port, timestamp and dataset, so
a capture replayed into Elasticsearch twice does not duplicate documents.

## Adding a signature

1. Add it to `SIGNATURES` in `analysis/deception_shield/scoring.py`.
2. Add the matching entry to `stack/logstash/patterns/score_payload.rb`, keeping
   the name and weight identical so both paths agree.
3. Add a case to `analysis/tests/test_scoring.py`.
4. `make test`, then `make provision`.

## Rotating the web interface credentials

```bash
htpasswd -nbB tpotadmin '<new password>' | base64 -w0
```

Set the result as `tpot_web_htpasswd` in the inventory and re-run the playbook.
