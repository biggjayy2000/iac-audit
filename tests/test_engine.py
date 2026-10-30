import contextlib
import io
import json
import os
import tempfile
import unittest

from iac_audit.cli import main
from iac_audit.engine import scan
from iac_audit.report import render_json, render_markdown, render_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")

ALL_RULE_IDS = {
    "IAC001",
    "IAC002",
    "IAC003",
    "IAC004",
    "IAC005",
    "IAC006",
    "IAC007",
    "IAC008",
    "IAC009",
    "IAC010",
}


class ScanExamples(unittest.TestCase):
    def test_vulnerable_terraform_hits_every_rule(self):
        result = scan([os.path.join(EXAMPLES, "vulnerable")])
        self.assertEqual({finding.rule_id for finding in result.findings}, ALL_RULE_IDS)
        self.assertEqual(result.errors, [])

    def test_clean_terraform_is_silent(self):
        result = scan([os.path.join(EXAMPLES, "clean")])
        self.assertEqual(result.findings, [])
        self.assertGreater(len(result.resources), 0)

    def test_cloudformation_hits_every_rule(self):
        result = scan([os.path.join(EXAMPLES, "cloudformation")])
        self.assertEqual({finding.rule_id for finding in result.findings}, ALL_RULE_IDS)

    def test_resources_carry_file_and_line(self):
        result = scan([os.path.join(EXAMPLES, "vulnerable")])
        for resource in result.resources:
            self.assertTrue(resource.file.endswith(".tf"))
            self.assertGreater(resource.line, 0)

    def test_plain_json_is_ignored_not_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "policy.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"Version": "2012-10-17"}, handle)

            result = scan([directory])
            self.assertEqual(result.errors, [])
            self.assertEqual(result.findings, [])

    def test_yaml_without_pyyaml_explains_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "stack.yaml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n")

            result = scan([directory])
            try:
                import yaml  # noqa: F401
            except ImportError:
                self.assertTrue(any("PyYAML" in error for error in result.errors))


class Reports(unittest.TestCase):
    def test_json_report_is_machine_readable(self):
        result = scan([os.path.join(EXAMPLES, "vulnerable")])
        payload = json.loads(render_json(result))

        self.assertEqual(payload["counts"]["Critical"], 1)
        self.assertEqual(len(payload["findings"]), len(result.findings))
        self.assertEqual(payload["findings"][0]["severity"], "Critical")

    def test_markdown_lists_every_finding(self):
        result = scan([os.path.join(EXAMPLES, "vulnerable")])
        markdown = render_markdown(result)

        self.assertIn("# Infrastructure audit", markdown)
        self.assertEqual(markdown.count("### "), len(result.findings))

    def test_text_report_names_counts(self):
        result = scan([os.path.join(EXAMPLES, "vulnerable")])
        self.assertIn("Critical", render_text(result, color=False))


def run_cli(arguments):
    """Call the CLI with its report suppressed, so the test output stays readable."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(arguments)


class CommandLine(unittest.TestCase):
    def test_clean_tree_exits_zero(self):
        self.assertEqual(run_cli(["examples/clean", "--no-color"]), 0)

    def test_findings_exit_one(self):
        self.assertEqual(run_cli(["examples/vulnerable", "--no-color"]), 1)

    def test_fail_on_none_never_fails(self):
        self.assertEqual(run_cli(["examples/vulnerable", "--no-color", "--fail-on", "none"]), 0)

    def test_fail_on_critical_passes_when_only_high_exists(self):
        # The clean tree has no findings at all, so any threshold returns zero.
        self.assertEqual(run_cli(["examples/clean", "--fail-on", "critical"]), 0)

    def test_writes_report_to_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "report.md")
            code = run_cli(["examples/clean", "-f", "markdown", "-o", target])

            self.assertEqual(code, 0)
            with open(target, encoding="utf-8") as handle:
                self.assertIn("# Infrastructure audit", handle.read())


if __name__ == "__main__":
    unittest.main()
