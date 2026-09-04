"""Convert Clash own rule sets into Quantumult X remote rule lists."""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


RULE_TYPE_MAP = {
    "DOMAIN": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP6-CIDR",
    "USER-AGENT": "USER-AGENT",
}


class ValidationError(Exception):
    """Raised when a rule source or the QX rule-set manifest is invalid."""


def convert_repository(source_dir, manifest_path, output_dir):
    """Convert every YAML rule set below ``source_dir`` into ``output_dir``."""
    source_dir = Path(source_dir)
    manifest_path = Path(manifest_path)
    output_dir = Path(output_dir)

    manifest = _load_manifest(manifest_path, source_dir)
    rule_paths = sorted(source_dir.rglob("*.yaml"))
    parsed_rule_sets = [_parse_rule_set(path, source_dir) for path in rule_paths]
    mapping_by_source = {entry["source"]: entry for entry in manifest["rule_sets"]}
    diagnostics = []
    converted_rules = 0
    skipped_rules = 0

    staged_parent = output_dir.parent
    staged_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="qx-rules-", dir=staged_parent) as temporary_dir:
        staged_output = Path(temporary_dir) / "own"
        staged_output.mkdir()

        for rule_set in parsed_rule_sets:
            mapping = mapping_by_source.get(rule_set["path"])
            output_relative = mapping["output"] if mapping else _default_output(rule_set["path"])
            output_path = staged_output / output_relative
            output_path.parent.mkdir(parents=True, exist_ok=True)
            lines = ["# Generated from Clash/own/{}. Do not edit.".format(rule_set["path"])]
            has_embedded_actions = False

            for rule in rule_set["rules"]:
                rendered, rule_diagnostics, contains_action = _convert_rule(rule, manifest["policies"])
                diagnostics.extend(rule_diagnostics)
                if rendered is None:
                    skipped_rules += 1
                    continue
                lines.extend(rule["comments"])
                lines.append(rendered)
                converted_rules += 1
                has_embedded_actions = has_embedded_actions or contains_action

            if mapping and mapping["force_policy"] and has_embedded_actions:
                raise ValidationError(
                    "{}: configured force-policy conflicts with embedded rule actions".format(rule_set["path"])
                )
            output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        _write_filter_remote(staged_output, manifest)
        report = {
            "summary": {
                "converted_rules": converted_rules,
                "generated_files": len(parsed_rule_sets),
                "mapped_rule_sets": len(manifest["rule_sets"]),
                "skipped_rules": skipped_rules,
                "source_files": len(parsed_rule_sets),
                "warnings": len(diagnostics),
            },
            "diagnostics": diagnostics,
        }
        (staged_output / "diagnostics.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        if output_dir.exists():
            shutil.rmtree(output_dir)
        staged_output.replace(output_dir)

    return report


def _load_manifest(manifest_path, source_dir):
    document = _load_yaml_document(manifest_path)
    if not isinstance(document, dict):
        raise ValidationError("{}: manifest must be a mapping".format(manifest_path.name))

    errors = []
    if document.get("version") != 1:
        errors.append("{}: version must be 1".format(manifest_path.name))
    base_url = document.get("base-url")
    if not isinstance(base_url, str) or not base_url.startswith("https://"):
        errors.append("{}: base-url must be an https URL".format(manifest_path.name))

    policies = document.get("policies", [])
    if not isinstance(policies, list) or not all(isinstance(policy, str) and policy for policy in policies):
        errors.append("{}: policies must be a list of non-empty names".format(manifest_path.name))
        policies = []
    elif len(set(policies)) != len(policies):
        errors.append("{}: policies contains duplicate names".format(manifest_path.name))

    raw_rule_sets = document.get("rule-sets", [])
    if not isinstance(raw_rule_sets, list):
        errors.append("{}: rule-sets must be a list".format(manifest_path.name))
        raw_rule_sets = []

    rule_sets = []
    tags = set()
    outputs = set()
    sources = set()
    for index, raw_entry in enumerate(raw_rule_sets):
        prefix = "{}: rule-sets[{}]".format(manifest_path.name, index)
        if not isinstance(raw_entry, dict):
            errors.append("{} must be a mapping".format(prefix))
            continue

        source = raw_entry.get("source")
        tag = raw_entry.get("tag")
        if not isinstance(source, str) or not source:
            errors.append("{}.source must be a non-empty relative path".format(prefix))
            continue
        if not isinstance(tag, str) or not tag or "," in tag:
            errors.append("{}.tag must be a non-empty name without commas".format(prefix))
            continue

        source_path = source_dir / source
        if Path(source).is_absolute() or ".." in Path(source).parts or not source_path.is_file():
            errors.append("{}.source does not exist: {}".format(prefix, source))
        if tag in tags:
            errors.append("{}: duplicate tag: {}".format(manifest_path.name, tag))
        tags.add(tag)
        if source in sources:
            errors.append("{}: duplicate source: {}".format(manifest_path.name, source))
        sources.add(source)

        output = raw_entry.get("output", _default_output(source))
        if not isinstance(output, str) or not output.endswith(".list") or Path(output).is_absolute() or ".." in Path(output).parts:
            errors.append("{}.output must be a relative .list path".format(prefix))
            output = _default_output(source)
        if output in outputs:
            errors.append("{}: duplicate output: {}".format(manifest_path.name, output))
        outputs.add(output)

        force_policy = raw_entry.get("force-policy")
        if force_policy is not None and (not isinstance(force_policy, str) or force_policy not in policies):
            errors.append("{}.force-policy is not declared: {}".format(prefix, force_policy))

        enabled = raw_entry.get("enabled", True)
        if not isinstance(enabled, bool):
            errors.append("{}.enabled must be true or false".format(prefix))
            enabled = True
        update_interval = raw_entry.get("update-interval", 86400)
        if not isinstance(update_interval, int) or isinstance(update_interval, bool) or update_interval <= 0:
            errors.append("{}.update-interval must be a positive integer".format(prefix))
            update_interval = 86400

        rule_sets.append(
            {
                "source": source,
                "tag": tag,
                "output": output,
                "force_policy": force_policy,
                "enabled": enabled,
                "update_interval": update_interval,
            }
        )

    if errors:
        raise ValidationError("; ".join(errors))
    return {"base_url": base_url.rstrip("/"), "policies": set(policies), "rule_sets": rule_sets}


def _parse_rule_set(path, source_dir):
    text = path.read_text(encoding="utf-8")
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as error:
        raise ValidationError("{}: invalid YAML: {}".format(path.relative_to(source_dir), error)) from error

    payload, payload_line = _payload_node(root, path.relative_to(source_dir))
    lines = text.splitlines()
    rules = []
    previous_line = payload_line
    for item in payload.value:
        if not isinstance(item, ScalarNode):
            raise ValidationError("{}:{}: payload items must be rule strings".format(path.relative_to(source_dir), item.start_mark.line + 1))
        comments = _comments_between(lines, previous_line, item.start_mark.line)
        rules.append(
            {
                "value": item.value,
                "line": item.start_mark.line + 1,
                "path": path.relative_to(source_dir).as_posix(),
                "comments": comments,
            }
        )
        previous_line = item.start_mark.line
    return {"path": path.relative_to(source_dir).as_posix(), "rules": rules}


def _payload_node(root, relative_path):
    if not isinstance(root, MappingNode):
        raise ValidationError("{}: top-level YAML value must be a mapping".format(relative_path))
    for key, value in root.value:
        if isinstance(key, ScalarNode) and key.value == "payload":
            if not isinstance(value, SequenceNode):
                raise ValidationError("{}: payload must be a YAML list".format(relative_path))
            return value, key.start_mark.line
    raise ValidationError("{}: missing payload".format(relative_path))


def _load_yaml_document(path):
    try:
        with path.open(encoding="utf-8") as file_handle:
            return yaml.safe_load(file_handle)
    except OSError as error:
        raise ValidationError("{}: cannot read manifest".format(path.name)) from error
    except yaml.YAMLError as error:
        raise ValidationError("{}: invalid YAML: {}".format(path.name, error)) from error


def _convert_rule(rule, policies):
    parts = [part.strip() for part in rule["value"].split(",")]
    rule_type = parts[0] if parts else ""
    if rule_type not in RULE_TYPE_MAP:
        return None, [
            _diagnostic(
                rule,
                "unsupported-rule",
                "{} has no supported Quantumult X equivalent.".format(rule_type or "empty rule"),
                rule_type or None,
            )
        ], False
    if len(parts) < 2 or not parts[1]:
        return None, [_diagnostic(rule, "invalid-rule", "Rule has no value.", rule_type)], False

    action = None
    diagnostics = []
    for option in parts[2:]:
        if option == "no-resolve":
            diagnostics.append(
                _diagnostic(
                    rule,
                    "option-removed",
                    "QX has no equivalent for no-resolve; the option was removed.",
                    rule_type,
                )
            )
        elif action is None:
            action = option
        else:
            return None, diagnostics + [
                _diagnostic(rule, "unsupported-option", "Rule has an unsupported extra option: {}.".format(option), rule_type)
            ], False

    if action and action not in policies:
        raise ValidationError("{}:{}: policy is not declared: {}".format(rule["path"], rule["line"], action))

    rendered = ",".join([RULE_TYPE_MAP[rule_type], parts[1]] + ([action] if action else []))
    return rendered, diagnostics, bool(action)


def _diagnostic(rule, code, message, rule_type):
    return {
        "code": code,
        "line": rule["line"],
        "message": message,
        "path": rule["path"],
        "rule_type": rule_type,
        "severity": "warning",
    }


def _comments_between(lines, previous_line, current_line):
    comments = []
    for raw_line in lines[previous_line + 1 : current_line]:
        stripped = raw_line.strip()
        if stripped.startswith("#"):
            comments.append(stripped)
    return comments


def _default_output(source):
    return str(Path(source).with_suffix(".list"))


def _write_filter_remote(output_dir, manifest):
    lines = ["[filter_remote]"]
    for entry in manifest["rule_sets"]:
        url = "{}/{}".format(manifest["base_url"], entry["output"])
        fields = [url, "tag={}".format(entry["tag"])]
        if entry["force_policy"]:
            fields.append("force-policy={}".format(entry["force_policy"]))
        fields.extend(
            [
                "update-interval={}".format(entry["update_interval"]),
                "opt-parser=false",
                "enabled={}".format(str(entry["enabled"]).lower()),
            ]
        )
        lines.append(", ".join(fields))
    (output_dir / "filter_remote.conf").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("Clash/own"))
    parser.add_argument("--manifest", type=Path, default=Path("QuantumultX/rules-manifest.yaml"))
    parser.add_argument("--output", type=Path, default=Path("QuantumultX/own"))
    arguments = parser.parse_args(argv)
    try:
        report = convert_repository(arguments.source, arguments.manifest, arguments.output)
    except ValidationError as error:
        print("ERROR: {}".format(error), file=sys.stderr)
        return 2
    print(
        "Generated {generated_files} QX rule lists: {converted_rules} converted, {skipped_rules} skipped, {warnings} warnings.".format(
            **report["summary"]
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
