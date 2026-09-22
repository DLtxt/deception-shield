data "aws_caller_identity" "current" {}

# The sensor holds no long lived credentials. It assumes an instance role whose
# only privileges are writing its own captures to S3 and reporting to SSM, so a
# host compromise yields nothing reusable elsewhere in the account.
resource "aws_iam_role" "sensor" {
  name_prefix = "${local.name_prefix}-sensor-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

data "aws_iam_policy_document" "sensor" {
  statement {
    sid    = "ArchiveCaptures"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:AbortMultipartUpload",
    ]
    resources = ["${aws_s3_bucket.captures.arn}/*"]
  }

  statement {
    sid       = "LocateCaptureBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.captures.arn]
  }

  statement {
    sid    = "PublishSensorMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData",
    ]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["DeceptionShield"]
    }
  }
}

resource "aws_iam_role_policy" "sensor" {
  name_prefix = "${local.name_prefix}-sensor-"
  role        = aws_iam_role.sensor.id
  policy      = data.aws_iam_policy_document.sensor.json
}

# Session Manager replaces inbound SSH for routine administration, which lets the
# management security group stay closed to everything except the operator CIDRs.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.sensor.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "sensor" {
  name_prefix = "${local.name_prefix}-sensor-"
  role        = aws_iam_role.sensor.name
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name_prefix = "${local.name_prefix}-flow-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name_prefix = "${local.name_prefix}-flow-"
  role        = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
    }]
  })
}
