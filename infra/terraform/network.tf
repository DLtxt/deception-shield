data "aws_availability_zones" "available" {
  state = "available"
}

# The sensor network is fully isolated from any production VPC. Nothing here is
# peered, and the only egress path is the internet gateway, so a compromised
# honeypot has no lateral route into other infrastructure.
resource "aws_vpc" "sensor" {
  cidr_block           = "10.90.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "sensor" {
  vpc_id = aws_vpc.sensor.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_subnet" "sensor" {
  count = min(var.sensor_count, length(data.aws_availability_zones.available.names))

  vpc_id                  = aws_vpc.sensor.id
  cidr_block              = cidrsubnet(aws_vpc.sensor.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-subnet-${count.index}"
  }
}

resource "aws_route_table" "sensor" {
  vpc_id = aws_vpc.sensor.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.sensor.id
  }

  tags = {
    Name = "${local.name_prefix}-rt"
  }
}

resource "aws_route_table_association" "sensor" {
  count = length(aws_subnet.sensor)

  subnet_id      = aws_subnet.sensor[count.index].id
  route_table_id = aws_route_table.sensor.id
}

# Flow logs give a connection level record that survives independently of the
# host, which matters when the host is intentionally exposed to attackers.
resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/aws/vpc/${local.name_prefix}/flow-logs"
  retention_in_days = 90
}

resource "aws_flow_log" "sensor" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id               = aws_vpc.sensor.id
  traffic_type         = "ALL"
  iam_role_arn         = aws_iam_role.flow_logs[0].arn
  log_destination      = aws_cloudwatch_log_group.flow_logs[0].arn
  max_aggregation_interval = 60

  tags = {
    Name = "${local.name_prefix}-flow-log"
  }
}
