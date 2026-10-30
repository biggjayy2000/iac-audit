import unittest

from iac_audit.terraform import Opaque, parse_terraform


class ParseResources(unittest.TestCase):
    def test_reads_resource_blocks_and_kinds(self):
        text = """
        resource "aws_s3_bucket" "reports" {
          bucket = "company-reports"
          acl    = "public-read"
        }

        resource "aws_db_instance" "orders" {
          identifier = "orders"
        }
        """
        resources = parse_terraform(text, "main.tf")

        self.assertEqual([r.kind for r in resources], ["s3_bucket", "rds_instance"])
        self.assertEqual(resources[0].name, "reports")
        self.assertEqual(resources[0].body["acl"], "public-read")
        self.assertEqual(resources[0].fmt, "terraform")

    def test_tracks_line_numbers(self):
        text = 'resource "aws_s3_bucket" "a" {\n}\n\nresource "aws_s3_bucket" "b" {\n}\n'
        resources = parse_terraform(text, "main.tf")

        self.assertEqual(resources[0].line, 1)
        self.assertEqual(resources[1].line, 4)

    def test_nested_blocks_become_lists(self):
        text = """
        resource "aws_security_group" "bastion" {
          ingress {
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }

          ingress {
            from_port = 443
            to_port   = 443
            protocol  = "tcp"
            cidr_blocks = ["10.0.0.0/8"]
          }
        }
        """
        resource = parse_terraform(text, "main.tf")[0]

        self.assertIsInstance(resource.body["ingress"], list)
        self.assertEqual(len(resource.body["ingress"]), 2)
        self.assertEqual(resource.body["ingress"][0]["from_port"], 22)
        self.assertEqual(resource.body["ingress"][0]["cidr_blocks"], ["0.0.0.0/0"])

    def test_jsonencode_payload_is_parsed(self):
        text = """
        resource "aws_iam_policy" "p" {
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [{
              Effect   = "Allow"
              Action   = "*"
              Resource = "*"
            }]
          })
        }
        """
        policy = parse_terraform(text, "main.tf")[0].body["policy"]

        self.assertIsInstance(policy, dict)
        self.assertEqual(policy["Statement"][0]["Action"], "*")

    def test_references_stay_opaque(self):
        text = 'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n'
        value = parse_terraform(text, "main.tf")[0].body["password"]

        self.assertIsInstance(value, Opaque)
        self.assertEqual(str(value), "var.db_password")

    def test_heredoc_is_read_as_text(self):
        text = """
        resource "aws_s3_bucket_policy" "p" {
          policy = <<POLICY
        {"Version": "2012-10-17"}
        POLICY
        }
        """
        policy = parse_terraform(text, "main.tf")[0].body["policy"]

        self.assertIn("2012-10-17", policy)

    def test_comments_are_ignored(self):
        text = """
        # a comment
        resource "aws_s3_bucket" "a" { // trailing
          bucket = "x" # inline
          /* block
             comment */
          acl = "private"
        }
        """
        resource = parse_terraform(text, "main.tf")[0]

        self.assertEqual(resource.body["bucket"], "x")
        self.assertEqual(resource.body["acl"], "private")

    def test_non_resource_blocks_are_skipped(self):
        text = """
        provider "aws" {
          region = "us-east-1"
        }

        variable "x" {
          type = string
        }
        """
        self.assertEqual(parse_terraform(text, "main.tf"), [])


if __name__ == "__main__":
    unittest.main()
