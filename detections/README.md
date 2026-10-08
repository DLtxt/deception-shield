# detections

The detection rules and everything CI needs to hold them to account.

| Path | Contents |
| --- | --- |
| `sigma/` | Twelve Sigma rules across six ATT&CK techniques, written against Cowrie's event shape |
| `pipelines/cowrie-ecs.yml` | sigma-cli pipeline mapping Cowrie's fields to the index's |
| `fixtures/attack/`, `fixtures/benign/` | Labelled sessions the rules must catch, and must not fire on |
| `thresholds.yml` | What the fixture gate requires before a change can merge |
| `requirements.txt` | The pinned sigma-cli toolchain CI converts the rules with |

```bash
make rules-check     # every rule loads, and converts faithfully for Elasticsearch
make rules-test      # the fixture gate
make rules-convert   # Kibana searches and Elastic Security rules, via sigma-cli
```

Fixtures marked `provenance: seed` were written from published honeypot
reporting so that CI has something to run from the first commit. Fixtures
exported from captured sessions (`make fixtures`) are sanitised: public
addresses are remapped into the documentation ranges and passwords dropped.

The workflow, from capture to a held-out evaluation, is in
[`../docs/detections.md`](../docs/detections.md).
