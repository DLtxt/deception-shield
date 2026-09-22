resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Captures leave the sensor as soon as they are rotated. Keeping the archive off
# the host means the evidence survives even if the honeypot itself is wiped.
resource "aws_s3_bucket" "captures" {
  bucket        = "${local.name_prefix}-captures-${random_id.bucket_suffix.hex}"
  force_destroy = false

  tags = {
    Name        = "${local.name_prefix}-captures"
    DataClass   = "attack-telemetry"
  }
}

resource "aws_s3_bucket_public_access_block" "captures" {
  bucket = aws_s3_bucket.captures.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "captures" {
  bucket = aws_s3_bucket.captures.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "captures" {
  bucket = aws_s3_bucket.captures.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Captures are dense and mostly interesting in the first month. After that they
# move to Glacier so long term retention stays affordable.
resource "aws_s3_bucket_lifecycle_configuration" "captures" {
  bucket = aws_s3_bucket.captures.id

  depends_on = [aws_s3_bucket_versioning.captures]

  rule {
    id     = "archive-then-expire"
    status = "Enabled"

    filter {
      prefix = "pcap/"
    }

    transition {
      days          = var.pcap_retention_days
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = var.pcap_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_ebs_volume" "data" {
  count = var.sensor_count

  availability_zone = aws_subnet.sensor[count.index % length(aws_subnet.sensor)].availability_zone
  size              = var.data_volume_size
  type              = "gp3"
  throughput        = 250
  iops              = 3000
  encrypted         = true

  tags = {
    Name = "${local.name_prefix}-data-${count.index}"
  }
}

resource "aws_volume_attachment" "data" {
  count = var.sensor_count

  device_name = "/dev/xvdf"
  volume_id   = aws_ebs_volume.data[count.index].id
  instance_id = aws_instance.sensor[count.index].id
}
