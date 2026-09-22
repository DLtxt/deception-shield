# T-Pot targets Debian derivatives; the project tracks Ubuntu LTS, so the AMI
# lookup is pinned to the 22.04 server line rather than "latest Ubuntu".
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

resource "aws_key_pair" "management" {
  key_name_prefix = "${local.name_prefix}-mgmt-"
  public_key      = var.ssh_public_key
}

resource "aws_instance" "sensor" {
  count = var.sensor_count

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.sensor[count.index % length(aws_subnet.sensor)].id
  key_name               = aws_key_pair.management.key_name
  iam_instance_profile   = aws_iam_instance_profile.sensor.name
  vpc_security_group_ids = [
    aws_security_group.honeypot.id,
    aws_security_group.management.id,
  ]

  # IMDSv2 only. Token bound metadata prevents an SSRF style probe against a
  # honeypot web listener from reaching the instance credentials.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  root_block_device {
    volume_size           = 64
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/cloud-init.yaml.tftpl", {
    hostname       = "${local.name_prefix}-sensor-${count.index}"
    tpot_edition   = var.tpot_edition
    capture_bucket = aws_s3_bucket.captures.id
    aws_region     = var.aws_region
    sensor_id      = "${local.name_prefix}-${count.index}"
  })

  tags = {
    Name     = "${local.name_prefix}-sensor-${count.index}"
    SensorId = "${local.name_prefix}-${count.index}"
  }

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_eip" "sensor" {
  count = var.sensor_count

  instance = aws_instance.sensor[count.index].id
  domain   = "vpc"

  tags = {
    Name = "${local.name_prefix}-eip-${count.index}"
  }
}
