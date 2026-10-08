# Detection as code

Deception Shield's detections are Sigma rules kept in this repository and
treated like any other code. Every rule is tested on each commit against
labelled attack sessions it must keep catching and benign sessions it must not
fire on. The rules are converted for Elasticsearch with sigma-cli, and they are
measured once, on a held-out week, against sessions the honeypot captured.

```
 Cowrie log or index ──► sessions build ──► corpus ──┐
                                                     ├──► label ──► labels
 shell history ───────► import-history ──► baseline ─┘                 │
                                                                       ▼
 detections/sigma ──► rules check ──► rules test ──► sigma-cli ──► Kibana, Elastic Security
                          (CI)         (CI gate)       (CI)
                                                                       │
                                               evaluate on a held-out week
```

## The rules

Twelve rules cover six ATT&CK techniques, two rules each, written against
behaviour SSH honeypots are known to record.

| Technique | Rule | What it catches |
| --- | --- | --- |
| T1098.004 SSH Authorized Keys | `ssh_authorized_keys_write` | a key echoed or downloaded into `authorized_keys` |
| | `ssh_directory_reset` | `chattr`/`lockr -ia .ssh`, or `.ssh` deleted before planting |
| T1082 System Information Discovery | `hardware_inventory_scripted` | `/proc/cpuinfo`, `free` and `df` cut down to bare figures |
| | `bot_environment_probe` | `uname -s -v -n -r -m`, `busybox ECCHI`, short hex `echo` probes |
| T1105 Ingress Tool Transfer | `download_from_ip_address` | wget, curl, tftp or ftpget from a public bare address |
| | `binary_written_with_escapes` | an ELF written a few dozen escaped bytes at a time |
| T1059.004 Unix Shell | `remote_script_piped_to_shell` | a fetched script piped to, expanded in, or run by a shell |
| | `decoded_payload_executed` | base64 decoded straight into a shell or `eval` |
| T1070.003 Clear Command History | `shell_history_cleared` | `history -c`, a history file deleted or truncated |
| | `shell_history_disabled` | `HISTFILE` unset or nulled, `set +o history` |
| T1053.003 Cron | `crontab_installed_noninteractively` | `... \| crontab -`, `crontab /tmp/x` |
| | `cron_file_written` | `/etc/crontab`, `/etc/cron.*` or the spool written to |

Each rule's `falsepositives` names what it is expected to trip on, and
`analysis/tests/test_detection_rules.py` holds the commands each rule must flag
and the neighbouring administrative commands it must leave alone.

`deception-shield rules check` prints the inventory and the rule set's
fingerprint, a hash of every rule file that later appears on evaluations.

### Log source and fields

Rules read Cowrie's own event shape, `logsource: product: cowrie`, matching
`eventid: cowrie.command.input` and the `input` field. Logstash renames those
fields on the way into Elasticsearch, and
[`detections/pipelines/cowrie-ecs.yml`](../detections/pipelines/cowrie-ecs.yml)
applies the same renames when sigma-cli converts a rule, so `input` becomes
`process.command_line`.

Benign sessions imported from shell history are presented to the rules in the
same shape, so one rule set reads an intruder's session and an administrator's
without translation.

### One rule, two engines

A rule runs in two places: the toolkit's engine, which CI and the evaluation use,
and Elasticsearch, after conversion. They are kept in agreement on purpose.

- **Regular expressions match the whole value** in both. Elasticsearch anchors a
  regular expression, so the toolkit does too, and `.` matches newlines in both.
  An expression meant to match inside a command says so with `.*`.
- **Only syntax both understand is allowed.** Lucene has no `\s`, `\b`, `\d`,
  anchors or lookaround, and treats `@ & ~ < > " #` as operators. `rules check`
  rejects a rule that uses any of these, or a field the conversion pipeline
  does not map, and fails CI.
- **Case is the one known difference.** Sigma's `contains` is case insensitive
  and the toolkit honours that; Elasticsearch's wildcard queries are case
  sensitive. Shell commands are typed in lower case in practice, and the rules
  are written in the case attackers use.

`process.command_line` is mapped as a `wildcard` field so that the converted
wildcard and regular expression queries match the whole command line. An
analysed text field would match them a word at a time, where a pattern such as
`*| sh*` can never match.

## The workflow

### 1. Capture sessions

Run the sensors for the collection period, then assemble command sessions,
those in which the intruder ran at least one command, from Elasticsearch:

```bash
ssh -p 64295 -L 9200:127.0.0.1:64298 ubuntu@<sensor>     # in another terminal
make sessions ES=http://localhost:9200 SINCE=28d
```

or from Cowrie's JSON logs copied off a sensor:

```bash
make sessions LOGS=data/cowrie
```

Either writes `data/sessions.jsonl` and prints the corpus figures:

```bash
deception-shield sessions stats data/sessions.jsonl
```

`data/` is ignored by git. Captured sessions are attack traffic.

### 2. Collect a benign baseline

A honeypot sees almost nothing but attack traffic, so false positives cannot be
measured from honeypot data. They are measured against ordinary administration
on hosts you control, imported from shell history.

History needs timestamps, which are off by default. Turn them on at the start
of the collection period, on every host that will contribute:

```bash
# bash, in ~/.bashrc
export HISTTIMEFORMAT='%F %T '
shopt -s histappend

# zsh, in ~/.zshrc
setopt EXTENDED_HISTORY INC_APPEND_HISTORY
```

Then import each host, which also labels its sessions benign:

```bash
make baseline HISTORY=~/.zsh_history HOST=laptop
make baseline HISTORY=/tmp/server-a.bash_history HOST=server-a
```

History records no logins, so a pause of more than thirty minutes ends a
session (`--idle` changes it). The baseline's size sets how tightly a false
positive rate can be stated: with no alerts in 500 sessions the true rate is
still only bounded at about 0.8%.

### 3. Label

```bash
make label
```

Sessions are grouped into families, sessions that ran the same commands in the
same order once addresses, passwords, keys and encoded blobs are set aside, and
labelled a family at a time, largest first. A month of honeypot traffic becomes
a few dozen decisions. Each decision is written immediately, so labelling can
stop and resume.

- **attack**: the session shows hostile intent. Record the techniques seen,
  including ones no rule covers yet; those show up in every evaluation as gaps.
- **benign**: nothing hostile happened.
- **exclude**: leave it out of measurement, for example your own test logins or
  sessions that sent nothing but empty lines.

The labeller never shows what the rules made of a session. Labels judged with
the verdicts in view would measure the rules against themselves.

Labels live in `data/labels.csv`, one row per decision; the last row for a
session wins, so a correction is another row.

### 4. Tune on the development weeks

Choose the held-out window now, normally the last full ISO week of collection,
and tune only on the weeks before it.

```bash
make evaluate HOLDOUT=2026-W40
```

The report lists the development weeks' missed attack sessions and false
alerts, which is what tuning works from. It deliberately does not list the
held-out window's.

### 5. Commit fixtures and let CI hold the line

```bash
make fixtures HOLDOUT=2026-W40 REPLACE='alice=operator laptop=host-a'
```

This takes one session per family from the labelled development weeks, never
from the held-out window, and adds them to `detections/fixtures/attack/` and
`detections/fixtures/benign/`. Public addresses are remapped into the
documentation ranges, since the repository is public and the addresses in an
attack belong to its victims as often as to the attacker. Passwords are
dropped. `REPLACE` swaps out names that identify you. Read the diff before
committing.

On every commit, [`.github/workflows/detections.yml`](../.github/workflows/detections.yml)
runs:

1. the toolkit's tests, including every rule's own attack and benign cases;
2. `deception-shield rules check`, which loads every rule and confirms it
   converts faithfully;
3. `deception-shield rules test`, the fixture gate, which fails the build when
   the rules detect too few attack fixtures, when a technique's own rules miss
   its fixtures, when any rule alerts on a benign fixture, or when a rule or
   technique has no fixture exercising it; the thresholds are in
   [`detections/thresholds.yml`](../detections/thresholds.yml);
4. `sigma check --fail-on-issues`, the reference validator, against the Sigma
   specification and the current ATT&CK release;
5. the conversion, and a check that the committed Kibana searches match it.

The gate's report appears on the run's summary page. Thresholds start strict;
loosening one goes in the same file with a note saying what it lets through.

The repository ships seed fixtures (`provenance: seed`) written from published
honeypot reporting, so the gate has something to run before anything is
captured. Captured fixtures are added beside them.

### 6. Freeze and evaluate the held-out week once

When tuning is finished, commit and tag the rule set, then:

```bash
make evaluate HOLDOUT=2026-W40
```

`data/evaluation.md` and `data/evaluation.json` carry the result, with the rule
set's fingerprint and a hash of every input, so the figures can be traced to
exactly the rules and data that produced them. Evaluate the held-out week once.
If the rules change afterwards, the next week is the new held-out week.

### 7. Deploy to the stack

```bash
pip install -r detections/requirements.txt
make rules-convert
make dashboards
```

`rules-convert` writes one Discover saved search per rule to
`stack/kibana/detections/`, which `make dashboards` and the provisioning
playbook import, and Elastic Security detection rules to
`build/detections/siem-rules.ndjson`. Importing those needs a Kibana with
security enabled, which the stack as shipped does not run.

## Reading an evaluation

| Figure | Meaning |
| --- | --- |
| Attack sessions detected | labelled attack sessions with at least one alert |
| Benign sessions alerted | labelled benign sessions with at least one alert |
| False alerts | alerts on benign sessions, one per rule per session |
| 95% interval | the Wilson score interval around a rate |
| Attack families detected | distinct scripts with at least one detected session |
| Families first seen in the window | the same, for scripts absent from the tuning weeks |
| Precision at this class mix | share of alerted sessions that were attacks; changes with the mix |

Botnets run one script thousands of times, so the session rate leans on the
largest families. The family rates count each script once, and the rate on
families first seen in the held-out window is the nearest thing to a measure of
whether the rules generalise.

## Reporting the numbers

Every figure comes from a command, not from memory:

| Claim | Where it comes from |
| --- | --- |
| command sessions captured, and over how long | `deception-shield sessions stats data/sessions.jsonl` |
| rules written, and techniques covered | the first line of `deception-shield rules check` |
| detection on the held-out week, false alerts, benign sessions | the headline of `data/evaluation.md` |

State the held-out window, give the interval with the rate, and say where the
benign baseline came from. A false positive rate measured on one person's laptop
and one measured across a team's servers are different claims.

## Adding or changing a rule

1. Write or edit the rule in `detections/sigma/`. Give a new rule a fresh UUID,
   a tactic and a technique tag, and its `falsepositives`.
2. Add the commands it must flag and the neighbouring ones it must not to
   `analysis/tests/test_detection_rules.py`.
3. `make rules-check rules-test test`.
4. `make rules-convert` and commit the regenerated Kibana searches with the rule.

When a rule is added or retired, the inventory test and the table above change
with it.
