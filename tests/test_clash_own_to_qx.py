import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from clash_own_to_qx import ValidationError, convert_repository


class ClashOwnToQxTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.source_dir = self.root / "Clash" / "own"
        self.output_dir = self.root / "QuantumultX" / "own"
        self.source_dir.mkdir(parents=True)
        self.manifest_path = self.root / "QuantumultX" / "rules-manifest.yaml"
        self.manifest_path.parent.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_manifest(self, content):
        self.manifest_path.write_text(content, encoding="utf-8")

    def write_rule_set(self, relative_path, content):
        path = self.source_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_converts_supported_rules_preserves_actions_and_reports_lossy_options(self):
        self.write_rule_set(
            "AI/OpenAI.yaml",
            """payload:
  # Core service endpoints
  - DOMAIN,api.example.test
  - DOMAIN-SUFFIX,example.test
  - DOMAIN-KEYWORD,example
  - IP-CIDR,192.0.2.0/24,OpenAI,no-resolve
  - IP-CIDR6,2001:db8::/32
  - USER-AGENT,ExampleApp*
  - IP-ASN,64500,no-resolve
""",
        )
        self.write_rule_set(
            "General.yaml",
            """payload:
  - DOMAIN-SUFFIX,manual.example.test
""",
        )
        self.write_manifest(
            """version: 1
base-url: https://raw.githubusercontent.com/example/rules/master/QuantumultX/own
policies:
  - OpenAI
  - Default
rule-sets:
  - source: AI/OpenAI.yaml
    tag: Own-OpenAI
    enabled: true
    update-interval: 172800
  - source: General.yaml
    tag: Own-General
    force-policy: Default
    enabled: false
    update-interval: 86400
""",
        )

        report = convert_repository(self.source_dir, self.manifest_path, self.output_dir)

        self.assertEqual(
            (self.output_dir / "AI" / "OpenAI.list").read_text(encoding="utf-8"),
            """# Generated from Clash/own/AI/OpenAI.yaml. Do not edit.
# Core service endpoints
HOST,api.example.test
HOST-SUFFIX,example.test
HOST-KEYWORD,example
IP-CIDR,192.0.2.0/24,OpenAI
IP6-CIDR,2001:db8::/32
USER-AGENT,ExampleApp*
""",
        )
        self.assertEqual(
            (self.output_dir / "General.list").read_text(encoding="utf-8"),
            """# Generated from Clash/own/General.yaml. Do not edit.
HOST-SUFFIX,manual.example.test
""",
        )
        self.assertEqual(
            (self.output_dir / "filter_remote.conf").read_text(encoding="utf-8"),
            """[filter_remote]
https://raw.githubusercontent.com/example/rules/master/QuantumultX/own/AI/OpenAI.list, tag=Own-OpenAI, update-interval=172800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/example/rules/master/QuantumultX/own/General.list, tag=Own-General, force-policy=Default, update-interval=86400, opt-parser=false, enabled=false
""",
        )
        diagnostics = json.loads((self.output_dir / "diagnostics.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"], diagnostics["summary"])
        self.assertEqual(diagnostics["summary"]["converted_rules"], 7)
        self.assertEqual(diagnostics["summary"]["skipped_rules"], 1)
        self.assertEqual(
            diagnostics["diagnostics"],
            [
                {
                    "code": "option-removed",
                    "line": 6,
                    "message": "QX has no equivalent for no-resolve; the option was removed.",
                    "path": "AI/OpenAI.yaml",
                    "rule_type": "IP-CIDR",
                    "severity": "warning",
                },
                {
                    "code": "unsupported-rule",
                    "line": 9,
                    "message": "IP-ASN has no supported Quantumult X equivalent.",
                    "path": "AI/OpenAI.yaml",
                    "rule_type": "IP-ASN",
                    "severity": "warning",
                },
            ],
        )

    def test_generates_unmapped_lists_without_adding_them_to_filter_remote(self):
        self.write_rule_set("Unmapped.yaml", "payload:\n  - DOMAIN,unmapped.example.test\n")
        self.write_manifest(
            """version: 1
base-url: https://raw.githubusercontent.com/example/rules/master/QuantumultX/own
policies: []
rule-sets: []
""",
        )

        convert_repository(self.source_dir, self.manifest_path, self.output_dir)

        self.assertTrue((self.output_dir / "Unmapped.list").is_file())
        self.assertEqual(
            (self.output_dir / "filter_remote.conf").read_text(encoding="utf-8"),
            "[filter_remote]\n",
        )

    def test_rejects_invalid_mapping_references_and_duplicate_tags(self):
        self.write_rule_set("One.yaml", "payload:\n  - DOMAIN,one.example.test\n")
        self.write_rule_set("Two.yaml", "payload:\n  - DOMAIN,two.example.test\n")
        self.write_manifest(
            """version: 1
base-url: https://raw.githubusercontent.com/example/rules/master/QuantumultX/own
policies:
  - Direct
rule-sets:
  - source: Missing.yaml
    tag: Shared
    force-policy: Direct
  - source: One.yaml
    tag: Shared
    force-policy: Unknown
  - source: Two.yaml
    tag: Another
    output: One.list
    force-policy: Direct
""",
        )

        with self.assertRaises(ValidationError) as error:
            convert_repository(self.source_dir, self.manifest_path, self.output_dir)

        self.assertEqual(
            str(error.exception),
            "rules-manifest.yaml: rule-sets[0].source does not exist: Missing.yaml; "
            "rules-manifest.yaml: duplicate tag: Shared; "
            "rules-manifest.yaml: rule-sets[1].force-policy is not declared: Unknown; "
            "rules-manifest.yaml: duplicate output: One.list",
        )

    def test_rejects_embedded_actions_not_declared_by_the_manifest(self):
        self.write_rule_set("Actions.yaml", "payload:\n  - DOMAIN,action.example.test,MissingPolicy\n")
        self.write_manifest(
            """version: 1
base-url: https://raw.githubusercontent.com/example/rules/master/QuantumultX/own
policies: []
rule-sets:
  - source: Actions.yaml
    tag: Own-Actions
""",
        )

        with self.assertRaises(ValidationError) as error:
            convert_repository(self.source_dir, self.manifest_path, self.output_dir)

        self.assertEqual(
            str(error.exception),
            "Actions.yaml:2: policy is not declared: MissingPolicy",
        )


if __name__ == "__main__":
    unittest.main()
