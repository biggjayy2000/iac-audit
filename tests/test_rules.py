import unittest

from iac_audit.models import Resource, Severity
from iac_audit.rules import run_rules
from iac_audit.terraform import Opaque


def findings(kind, body, name="example", source_type="aws_example"):
    resource = Resource(
        kind=kind,
        source_type=source_type,
        name=name,
        body=body,
        file="main.tf",
        line=1,
    )
    return list(run_rules(resource, [resource]))


def ids(items):
    return [item.rule_id for item in items]


class S3Tests(unittest.TestCase):
    def test_public_acl(self):
        self.assertIn("IAC001", ids(findings("s3_bucket", {"acl": "public-read"})))

    def test_cloudformation_public_read_spelling(self):
        self.assertIn("IAC001", ids(findings("s3_bucket", {"AccessControl": "PublicRead"})))

    def test_private_acl_is_quiet(self):
        self.assertEqual(findings("s3_bucket", {"acl": "private"}), [])

    def test_website_configuration(self):
        self.assertIn("IAC001", ids(findings("s3_bucket", {"website": [{"index_document": "index.html"}]})))

    def test_bucket_policy_wildcard_principal(self):
        body = {"policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}}
        self.assertIn("IAC010", ids(findings("s3_bucket_policy", body)))

    def test_bucket_policy_condition_is_not_flagged(self):
        body = {
            "policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
                    }
                ]
            }
        }
        self.assertEqual(findings("s3_bucket_policy", body), [])


class SecurityGroupTests(unittest.TestCase):
    def test_ssh_open_to_world_is_high(self):
        items = findings(
            "security_group",
            {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
        )
        self.assertEqual(ids(items), ["IAC002"])
        self.assertEqual(items[0].severity, Severity.HIGH)

    def test_all_protocols_is_critical(self):
        items = findings(
            "security_group",
            {"ingress": [{"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]},
        )
        self.assertEqual(items[0].severity, Severity.CRITICAL)

    def test_database_port_is_high(self):
        items = findings(
            "security_group",
            {"ingress": [{"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]},
        )
        self.assertEqual(items[0].severity, Severity.HIGH)
        self.assertIn("PostgreSQL", items[0].evidence)

    def test_private_range_is_quiet(self):
        body = {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}]}
        self.assertEqual(findings("security_group", body), [])

    def test_standalone_rule_resource(self):
        body = {"from_port": 3389, "to_port": 3389, "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}
        self.assertIn("IAC002", ids(findings("sg_rule", body)))

    def test_cloudformation_ingress(self):
        body = {"SecurityGroupIngress": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}
        self.assertIn("IAC002", ids(findings("security_group", body)))

    def test_ipv6_world_is_covered(self):
        body = {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "ipv6_cidr_blocks": ["::/0"]}]}
        self.assertIn("IAC002", ids(findings("security_group", body)))


class StorageTests(unittest.TestCase):
    def test_unencrypted_volume(self):
        self.assertIn("IAC003", ids(findings("ebs_volume", {"size": 100})))

    def test_encrypted_volume_is_quiet(self):
        self.assertEqual(findings("ebs_volume", {"encrypted": True}), [])

    def test_public_database(self):
        items = findings("rds_instance", {"publicly_accessible": True, "storage_encrypted": True})
        self.assertEqual(ids(items), ["IAC004"])

    def test_unencrypted_database(self):
        items = findings("rds_instance", {"publicly_accessible": False, "storage_encrypted": False})
        self.assertEqual(ids(items), ["IAC005"])


class IamTests(unittest.TestCase):
    def test_wildcard_policy_is_critical(self):
        body = {"policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
        items = findings("iam_policy", body)
        self.assertEqual(items[0].rule_id, "IAC006")
        self.assertEqual(items[0].severity, Severity.CRITICAL)

    def test_scoped_policy_is_quiet(self):
        body = {
            "policy": {
                "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]
            }
        }
        self.assertEqual(findings("iam_policy", body), [])

    def test_deny_wildcard_is_quiet(self):
        body = {"policy": {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}}
        self.assertEqual(findings("iam_policy", body), [])

    def test_trust_any_principal(self):
        body = {"assume_role_policy": {"Statement": [{"Effect": "Allow", "Principal": "*"}]}}
        self.assertIn("IAC007", ids(findings("iam_role", body)))

    def test_trust_named_account_is_quiet(self):
        body = {"assume_role_policy": {"Statement": [{"Principal": {"AWS": "arn:aws:iam::123456789012:root"}}]}}
        self.assertEqual(findings("iam_role", body), [])


class SecretTests(unittest.TestCase):
    def test_literal_password(self):
        items = findings("rds_instance", {"password": "hunter2", "storage_encrypted": True})
        self.assertIn("IAC008", ids(items))

    def test_cloudformation_password_field(self):
        body = {"MasterUserPassword": "hunter2", "StorageEncrypted": True}
        self.assertIn("IAC008", ids(findings("rds_instance", body)))

    def test_reference_is_not_a_secret(self):
        body = {"password": Opaque("var.db_password"), "storage_encrypted": True}
        self.assertNotIn("IAC008", ids(findings("rds_instance", body)))

    def test_report_does_not_echo_the_secret(self):
        items = [item for item in findings("rds_instance", {"password": "hunter2"}) if item.rule_id == "IAC008"]
        self.assertTrue(items)
        self.assertNotIn("hunter2", items[0].evidence)
        self.assertNotIn("hunter2", items[0].detail)


class ComputeTests(unittest.TestCase):
    def test_public_ip(self):
        self.assertIn("IAC009", ids(findings("ec2_instance", {"associate_public_ip_address": True})))

    def test_public_ip_through_network_interface(self):
        body = {"NetworkInterfaces": [{"AssociatePublicIpAddress": True}]}
        self.assertIn("IAC009", ids(findings("ec2_instance", body)))

    def test_private_instance_is_quiet(self):
        self.assertEqual(findings("ec2_instance", {"associate_public_ip_address": False}), [])


if __name__ == "__main__":
    unittest.main()
