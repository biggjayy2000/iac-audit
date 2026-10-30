# The same workload, configured properly. This file exists so the test suite can
# prove the rules stay quiet on safe infrastructure, not just that they fire.

variable "db_password" {
  type      = string
  sensitive = true
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "reports" {
  bucket = "company-reports"
  acl    = "private"
}

resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "Remote access from the office range"

  ingress {
    description = "SSH from the corporate network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}

resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
  skip_final_snapshot = true
}

resource "aws_iam_policy" "application" {
  name = "application-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "arn:aws:s3:::company-reports/*"
    }]
  })
}

resource "aws_iam_role" "ci" {
  name = "ci-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_instance" "web" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
}
