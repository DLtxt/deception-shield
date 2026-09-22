# Two security groups keep the exposed surface and the administrative surface
# separate. Attack traffic only ever matches the honeypot group; the management
# group is scoped to operator networks and carries no internet-wide rule.

resource "aws_security_group" "honeypot" {
  name_prefix = "${local.name_prefix}-honeypot-"
  description = "Internet facing honeypot listeners"
  vpc_id      = aws_vpc.sensor.id

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-sg-honeypot"
  }
}

resource "aws_vpc_security_group_ingress_rule" "honeypot_tcp" {
  for_each = toset([for p in local.honeypot_tcp_ports : tostring(p)])

  security_group_id = aws_security_group.honeypot.id
  description       = "Honeypot listener tcp/${each.value}"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
}

resource "aws_vpc_security_group_ingress_rule" "honeypot_udp" {
  for_each = toset([for p in local.honeypot_udp_ports : tostring(p)])

  security_group_id = aws_security_group.honeypot.id
  description       = "Honeypot listener udp/${each.value}"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "udp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
}

# Egress is unrestricted because several honeypots emulate outbound behaviour
# during an intrusion, and Docker needs to pull images on first boot.
resource "aws_vpc_security_group_egress_rule" "honeypot_all" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Outbound"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "management" {
  name_prefix = "${local.name_prefix}-mgmt-"
  description = "Operator access to the T-Pot control plane"
  vpc_id      = aws_vpc.sensor.id

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-sg-mgmt"
  }
}

resource "aws_vpc_security_group_ingress_rule" "management" {
  for_each = {
    for pair in setproduct(keys(local.management_ports), var.admin_cidr_blocks) :
    "${pair[0]}-${replace(pair[1], "/[./]/", "-")}" => {
      service = pair[0]
      cidr    = pair[1]
    }
  }

  security_group_id = aws_security_group.management.id
  description       = "T-Pot ${each.value.service} from ${each.value.cidr}"
  cidr_ipv4         = each.value.cidr
  ip_protocol       = "tcp"
  from_port         = local.management_ports[each.value.service]
  to_port           = local.management_ports[each.value.service]
}
