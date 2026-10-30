from morpheus.code_review import CodeReview
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
    assert all("sample-secret-value" not in str(item) for item in result["findings"])


def test_code_review_ignores_comment_only_matches(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text('# eval(user_input)\n// api_key = "example-secret"\n', encoding="utf-8")

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
