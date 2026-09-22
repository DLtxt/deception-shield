output "sensor_public_ips" {
  description = "Elastic IP addresses of the deployed sensors."
  value       = aws_eip.sensor[*].public_ip
}

output "sensor_instance_ids" {
  description = "EC2 instance identifiers, for Session Manager access."
  value       = aws_instance.sensor[*].id
}

output "capture_bucket" {
  description = "S3 bucket receiving rotated packet captures."
  value       = aws_s3_bucket.captures.id
}

output "management_ssh" {
  description = "SSH command for each sensor. T-Pot relocates sshd to port 64295."
  value = [
    for ip in aws_eip.sensor[*].public_ip :
    "ssh -p 64295 ubuntu@${ip}"
  ]
}

output "kibana_urls" {
  description = "T-Pot web interface, which fronts Kibana behind authentication."
  value = [
    for ip in aws_eip.sensor[*].public_ip :
    "https://${ip}:64297"
  ]
}

output "ansible_inventory" {
  description = "Inventory block ready to paste into ansible/inventory.ini."
  value = join("\n", concat(
    ["[sensors]"],
    [
      for idx, ip in aws_eip.sensor[*].public_ip :
      "${local.name_prefix}-sensor-${idx} ansible_host=${ip} ansible_port=64295 ansible_user=ubuntu sensor_id=${local.name_prefix}-${idx}"
    ],
    ["", "[sensors:vars]", "capture_bucket=${aws_s3_bucket.captures.id}", "aws_region=${var.aws_region}"]
  ))
}
