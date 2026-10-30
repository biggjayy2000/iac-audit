# Deliberately weak configuration, used by the test suite and the demo.
# Every block here is something that turns up in real repositories.

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "reports" {
  bucket = "company-reports"
  acl    = "public-read"
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowAnyone"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::company-reports/*"
    }]
  })
}

resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "Remote access"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Everything else"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "rdp" {
  security_group_id = aws_security_group.bastion.id
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
}

resource "aws_db_instance" "orders" {
  identifier           = "orders"
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "app"
  password             = "CorrectHorseBatteryStaple"
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
}

resource "aws_iam_policy" "admin" {
  name = "application-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "ci" {
  name = "ci-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_instance" "web" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}
