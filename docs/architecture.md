# Architecture

Deception Shield is a honeypot sensor network on AWS. Each sensor presents a
large, deliberately vulnerable-looking attack surface to the internet, records
everything that arrives at it in full, and turns that traffic into structured,
queryable attack telemetry.

## The shape of the system

```
                            internet
                                │
                                ▼
┌───────────────────────────────────────────────────────────────┐
│  EC2 sensor  (Ubuntu 22.04, isolated VPC)                     │
│                                                               │
│  deception plane                                              │
│    T-Pot ── Cowrie (SSH/Telnet)  Dionaea (SMB/FTP/MSSQL)      │
│             Tanner (HTTP)        Honeytrap, Mailoney, …       │
│                    │                                          │
│                    │ session events (JSON)                    │
│                    ▼                                          │
│  capture plane                                                │
│    tcpdump ──► rotated .pcap.gz ──► tshark ──► payload records │
│    Suricata ──────────────────────► EVE alerts and flows      │
│                    │                          │               │
│                    ▼                          ▼               │
│  analysis plane                                               │
│    Logstash ──► Elasticsearch ──► Kibana                      │
│                                                               │
└───────────────────────────────────────────────────────────────┘
                     │                        │
                     ▼                        ▼
              S3 capture archive      analysis toolkit
                                      (offline replay)
```

## The three planes

The sensor is organised into three planes that can be started, stopped and
reasoned about independently. Compose profiles map directly onto them, so the
analysis plane runs on a workstation with no honeypots attached.

### Deception

T-Pot supplies the honeypot daemons. Roughly twenty listeners cover the services
attackers actually probe: SSH and Telnet, SMB, FTP, HTTP, database protocols,
industrial protocols and several IoT-specific ports.

Nothing on this plane is a real service. Cowrie's shell is emulated and its
filesystem is a snapshot, so an attacker who "gets in" is interacting with a
recording device.

### Capture

Two independent recorders watch the same interface:

- **tcpdump** writes full frames, rotating on time and size. Rotated files are
  gzipped, which is also the signal that a file is complete and ready to read.
- **Suricata** applies signature detection to live traffic and emits EVE JSON,
  giving each flow a named verdict.

**tshark** — Wireshark's command line engine — then dissects each rotated
capture. Running Wireshark rather than parsing frames directly is what gives the
pipeline protocol reassembly and the full dissector table: a payload split across
many TCP segments reaches the analysis stage as one application message, and
protocols are identified by dissection rather than by port number.

### Analysis

Logstash normalises all three sources onto shared field names, so one query spans
honeypot sessions, IDS verdicts and raw payloads. Elasticsearch stores the result
in per-dataset data streams with retention matched to each dataset's size.
Kibana presents it.

## How an attack becomes a finding

1. A scanner connects to port 445 on the sensor.
2. Dionaea answers as an SMB server and records the exchange.
3. tcpdump has already written the frames; Suricata has already matched them
   against its ruleset.
4. The capture rotates and is gzipped.
5. The extractor notices the closed file and passes it to tshark.
6. tshark reassembles the stream and emits one record per application payload.
7. Each payload is scored against the signature set, producing a score, the
   names of what matched, and a triage band.
8. Records ship to Logstash, which enriches them with geography and autonomous
   system, fingerprints them against duplication, and writes them to the
   appropriate data stream.
9. The capture uploads to S3 and is removed from the sensor.
10. The analysis toolkit groups the resulting records into attack patterns and
    correlates sources into campaigns.

## Scoring and triage

Payload scoring is the mechanism that separates the small amount of traffic worth
attention from the large amount that is not. Each signature carries a weight
reflecting how rarely it appears in benign traffic, matches are additive, and the
total maps onto a triage band from benign through critical.

Scoring is implemented twice on purpose: a Ruby filter inside Logstash scores
events as they stream in, and a Python module scores captures replayed offline
where Logstash is not in the path. The weights and names are identical in both,
so a payload receives the same verdict either way.

## Campaign correlation

Individual sources are rarely interesting on their own. The analysis toolkit
builds a behaviour profile for each source — the signatures it triggered and the
ports it touched — and links sources pairwise when they share at least one
signature, their profiles overlap past a threshold, and their activity falls
within the same window. Links merge transitively through union-find, so a chain
of similar hosts forms a single campaign.

Requiring a shared signature is what keeps the output meaningful. Profiles
include ports, and without that requirement any two hosts that happened to probe
the same port would correlate perfectly.

## Isolation

The sensor is built on the assumption that it will be attacked successfully.

- It lives in a dedicated VPC with no peering, so there is no lateral route into
  other infrastructure.
- It holds no long-lived credentials. The instance role can write its own
  captures to S3 and report to SSM, and nothing else.
- IMDSv2 is required, so a request-forgery probe against a honeypot web listener
  cannot reach the instance credentials.
- The management plane binds high ports — 64294, 64295 and 64297 — reachable
  only from the operator networks in `admin_cidr_blocks`, while the honeypot
  listeners are open to the internet.
- Management traffic is excluded from the packet capture, so administrative
  sessions never enter an archive that is treated as hostile data.
- Captures leave for S3 as soon as they are dissected, so evidence survives the
  host.
