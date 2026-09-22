variable "project_name" {
  description = "Name prefix applied to every resource in the deployment."
  type        = string
  default     = "deception-shield"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,31}$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric with hyphens, 3-32 characters."
  }
}

variable "environment" {
  description = "Deployment environment used for tagging and resource naming."
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "AWS region hosting the sensor network."
  type        = string
  default     = "us-east-1"
}

variable "sensor_count" {
  description = "Number of honeypot sensors to deploy across the availability zones."
  type        = number
  default     = 1

  validation {
    condition     = var.sensor_count >= 1 && var.sensor_count <= 10
    error_message = "sensor_count must be between 1 and 10."
  }
}

variable "instance_type" {
  description = <<-DESC
    EC2 instance type for each sensor. T-Pot runs the full honeypot suite plus an
    Elasticsearch node in Docker, so the sizing floor is 8 GiB of memory.
  DESC
  type        = string
  default     = "t3.large"
}

variable "data_volume_size" {
  description = "Size in GiB of the EBS volume holding packet captures and Elasticsearch indices."
  type        = number
  default     = 256

  validation {
    condition     = var.data_volume_size >= 128
    error_message = "T-Pot requires at least 128 GiB for its data volume."
  }
}

variable "admin_cidr_blocks" {
  description = <<-DESC
    Source networks permitted to reach the management plane: SSH on 64295, the
    web interface on 64297 and Cockpit on 64294. The honeypot listeners stay open
    to the internet regardless of this value; only administration is restricted.
  DESC
  type        = list(string)

  validation {
    condition     = length(var.admin_cidr_blocks) > 0
    error_message = "At least one administrative CIDR block must be supplied."
  }

  validation {
    condition     = !contains(var.admin_cidr_blocks, "0.0.0.0/0")
    error_message = "The management plane may not be exposed to 0.0.0.0/0."
  }
}

variable "ssh_public_key" {
  description = "OpenSSH format public key installed for the management account."
  type        = string

  validation {
    condition     = can(regex("^(ssh-rsa|ssh-ed25519|ecdsa-sha2-)", var.ssh_public_key))
    error_message = "ssh_public_key must be an OpenSSH format public key."
  }
}

variable "tpot_edition" {
  description = "T-Pot installation profile. STANDARD carries the full sensor and ELK stack."
  type        = string
  default     = "STANDARD"

  validation {
    condition     = contains(["STANDARD", "SENSOR", "HIVE", "MINI"], var.tpot_edition)
    error_message = "tpot_edition must be one of STANDARD, SENSOR, HIVE, MINI."
  }
}

variable "pcap_retention_days" {
  description = "Days a rotated capture stays in S3 Standard before transitioning to Glacier."
  type        = number
  default     = 30
}

variable "pcap_expiration_days" {
  description = "Days after which archived captures are deleted."
  type        = number
  default     = 365
}

variable "enable_flow_logs" {
  description = "Capture VPC flow logs alongside the host level packet captures."
  type        = bool
  default     = true
}
