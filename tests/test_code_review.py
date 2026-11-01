import json

import pytest

from morpheus.code_review import CodeReview, load_code_review_rules
from morpheus.scanner import ProtectedSystemPathError


def test_code_review_reports_actionable_line_findings_without_source_text(tmp_path):
    source = tmp_path / "unsafe.py"
    source.write_text(
        'api_key = "sample-secret-value"\n'
        'eval(user_input)\n'
        'requests.get(url, verify=False)\n'
        'cursor.execute(f"SELECT * FROM users WHERE name={name}")\n',
        encoding="utf-8",
    )

    result = CodeReview().review_path(source)

    assert result["files_scanned"] == 1
    assert {item["rule_id"] for item in result["findings"]} >= {
        "hardcoded-credential",
        "dynamic-evaluation",
        "tls-verification-disabled",
        "sql-interpolation",
    }
    assert [item["line"] for item in result["findings"]] == [1, 2, 3, 4]
    assert all(item["reviewer"] == "Morpheus AST rules" for item in result["findings"])
    assert all("sample-secret-value" not in str(item) for item in result["findings"])


def test_code_review_ignores_comment_only_matches(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text('# eval(user_input)\n# api_key = "example-secret"\n', encoding="utf-8")

    result = CodeReview().review_path(source)

    assert result["findings"] == []


def test_code_review_folder_only_reviews_source_files(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.js").write_text("element.innerHTML = value;\n", encoding="utf-8")
    (root / "image.png").write_bytes(b"not source code")
    dependency = root / "node_modules"
    dependency.mkdir()
    (dependency / "vendor.py").write_text('eval("ignored")\n', encoding="utf-8")

    result = CodeReview().review_path(root)

    assert result["files_scanned"] == 1
    assert [finding["rule_id"] for finding in result["findings"]] == ["unsafe-html"]


def test_code_review_streams_large_files_without_a_per_file_size_limit(tmp_path):
    source = tmp_path / "large.py"
    prior_lines = 500_000
    with source.open("w", encoding="utf-8", newline="") as output:
        output.write("pass\n" * prior_lines)
        output.write("eval(user_input)\n")
    result = CodeReview().review_path(source)

    assert source.stat().st_size > 2 * 1024 * 1024
    assert result["files_scanned"] == 1
    assert result["findings"][0]["rule_id"] == "dynamic-evaluation"
    assert result["findings"][0]["line"] == prior_lines + 1


def test_code_review_rejects_protected_system_path(tmp_path, monkeypatch):
    protected = tmp_path / "Windows"
    protected.mkdir()
    source = protected / "system.py"
    source.write_text("pass\n", encoding="utf-8")
    monkeypatch.setattr("morpheus.code_review.protected_system_roots", lambda: [protected])

    try:
        CodeReview().review_path(source)
    except ProtectedSystemPathError as exc:
        assert "excluded" in str(exc)
    else:
        raise AssertionError("A protected system source file was reviewed")


def test_cpp_review_detects_unsafe_string_and_shell_calls(tmp_path):
    source = tmp_path / "unsafe.cpp"
    source.write_text(
        'strcpy(buffer, input);\n'
        'system(command);\n',
        encoding="utf-8",
    )

    result = CodeReview().review_path(source)

    assert [finding["rule_id"] for finding in result["findings"]] == [
        "cpp-unsafe-string-function",
        "cpp-shell-execution",
    ]


def test_sql_review_detects_dynamic_query_concatenation(tmp_path):
    source = tmp_path / "unsafe.sql"
    source.write_text(
        "EXECUTE IMMEDIATE 'SELECT * FROM users WHERE name=' || user_name;\n",
        encoding="utf-8",
    )

    result = CodeReview().review_path(source)

    assert [finding["rule_id"] for finding in result["findings"]] == [
        "sql-dynamic-concatenation",
    ]


def test_python_ast_traces_untrusted_values_into_sql_and_shell_sinks(tmp_path):
    source = tmp_path / "tainted.py"
    source.write_text(
        "import subprocess as process\n"
        "import sqlite3\n"
        "user_value = input()\n"
        "query = 'SELECT * FROM users WHERE name=' + user_value\n"
        "cursor.execute(query)\n"
        "command = user_value\n"
        "process.run(command, shell=True)\n",
        encoding="utf-8",
    )

    findings = CodeReview().review_path(source)["findings"]

    assert [(item["rule_id"], item["line"]) for item in findings] == [
        ("sql-interpolation", 5),
        ("shell-command", 7),
    ]


def test_python_ast_merges_branch_taint_without_leaking_function_locals(tmp_path):
    source = tmp_path / "flow.py"
    source.write_text(
        "def unsafe(flag):\n"
        "    query = 'SELECT * FROM users'\n"
        "    if flag:\n"
        "        query = input()\n"
        "    cursor.execute(query)\n"
        "\n"
        "def safe():\n"
        "    query = 'SELECT * FROM users'\n"
        "    cursor.execute(query)\n",
        encoding="utf-8",
    )

    findings = CodeReview().review_path(source)["findings"]

    assert [(item["rule_id"], item["line"]) for item in findings] == [
        ("sql-interpolation", 5),
    ]


def test_python_ast_handles_aliases_and_does_not_flag_parameterized_sql(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text(
        "from pickle import loads as deserialize\n"
        "import yaml\n"
        "deserialize(blob)\n"
        "yaml.safe_load(untrusted_text)\n"
        "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))\n",
        encoding="utf-8",
    )

    findings = CodeReview().review_path(source)["findings"]

    assert [item["rule_id"] for item in findings] == ["unsafe-deserialization"]


def test_python_ast_ignores_comments_and_string_examples(tmp_path):
    source = tmp_path / "examples.py"
    source.write_text(
        "# eval(user_input)\n"
        "example = 'cursor.execute(f\"SELECT {value}\")'\n"
        "safe = eval('1 + 1')\n",
        encoding="utf-8",
    )

    findings = CodeReview().review_path(source)["findings"]

    assert [item["rule_id"] for item in findings] == []


def test_python_ast_reports_parse_errors_with_line_number(tmp_path):
    source = tmp_path / "broken.py"
    source.write_text("if True print('broken')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="could not be parsed at line 1"):
        CodeReview().review_path(source)


def test_json_rule_catalog_rejects_invalid_regex_and_duplicate_ids(tmp_path):
    catalog = {
        "schema_version": 1,
        "rules": [{
            "id": "bad-regex",
            "kind": "regex",
            "title": "Bad regex",
            "severity": "high",
            "extensions": [".js"],
            "pattern": "(",
            "remediation": "Fix the rule.",
        }],
    }
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps(catalog), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid regex"):
        load_code_review_rules(rules_path)

    catalog["rules"] = [
        {**catalog["rules"][0], "pattern": "safe"},
        {**catalog["rules"][0], "pattern": "other"},
    ]
    rules_path.write_text(json.dumps(catalog), encoding="utf-8")
    with pytest.raises(ValueError, match="Duplicate code-review rule ID"):
        load_code_review_rules(rules_path)
