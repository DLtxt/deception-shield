# Deployment

## Requirements

| Tool | Version | Used for |
| --- | --- | --- |
| Terraform | 1.6 or newer | AWS infrastructure |
| Ansible | 2.15 or newer | sensor configuration |
| AWS CLI | v2 | credentials and capture retrieval |
| Docker | 24 or newer | running the stack |
| Python | 3.10 or newer | the analysis toolkit |

An AWS account with permission to create VPCs, EC2 instances, EBS volumes, S3
buckets and IAM roles.

## 1. Configure

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
```

Two values need your input:

- `admin_cidr_blocks` — the networks allowed to reach the management plane. The
  configuration rejects `0.0.0.0/0` here, because the honeypot surface is the
  part meant to be open, not the control plane.
- `ssh_public_key` — the key installed for the management account.

## 2. Deploy

```bash
make tf-init
make tf-plan
make tf-apply
```

Sizing defaults to `t3.large` with a 256 GiB data volume. T-Pot runs roughly
twenty containers plus an Elasticsearch node, so 8 GiB of memory is the working
floor; `t3.xlarge` gives Elasticsearch more room once indices grow.

First boot installs T-Pot unattended and takes 15 to 20 minutes. Progress is in
`/var/log/tpot-install.log` on the sensor.

## 3. Provision

```bash
make inventory     # writes ansible/inventory.ini from the Terraform outputs
make ping          # confirms Ansible can reach the sensors
make provision
```

The playbook installs the capture pipeline, the analysis toolkit, the Logstash
definitions, the index templates and the Kibana saved objects. It is safe to
re-run, and re-running it is how a pipeline change is rolled out.

## 4. Confirm

```bash
terraform -chdir=infra/terraform output kibana_urls
terraform -chdir=infra/terraform output management_ssh
```

On the sensor:

```bash
systemctl status deception-capture deception-extractor
ls -lh /data/pcap | tail
journalctl -u deception-extractor -f
```

Within a few minutes of exposure the capture directory begins filling. Internet
background scanning finds a new address quickly, so the first records usually
arrive without any prompting.

## Running the stack locally

The analysis plane runs on a workstation for replaying archived captures:

```bash
cp .env.example .env
make analysis-up
make templates
make dashboards
```

Kibana comes up on `http://localhost:5601`. Then pull captures down and analyse
them:

```bash
export CAPTURE_BUCKET=$(terraform -chdir=infra/terraform output -raw capture_bucket)
./scripts/fetch-captures.sh
make replay CAPTURE=captures
```

## Scaling out

Raising `sensor_count` deploys additional sensors across availability zones.
Every document carries the sensor that observed it, which is what makes comparing
sensors useful: activity that appears on one address but not the others is
targeted, while activity common to all of them is untargeted internet noise.

## Tear down

```bash
make tf-destroy
```

The capture bucket sets `force_destroy = false`, so it survives and must be
emptied deliberately. Collected telemetry is not discarded as a side effect of
tearing down the infrastructure that produced it.
