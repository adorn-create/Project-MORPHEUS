import ast
import json
import os
import re
from pathlib import Path
from typing import Any

from .scanner import (
    ProtectedSystemPathError,
    is_protected_system_path,
    protected_system_roots,
)

CODE_REVIEW_CHUNK_CHARS = 16 * 1024
RULE_SCAN_OVERLAP_CHARS = 2 * 1024
CODE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".sh", ".sql", ".ts",
    ".tsx", ".vue", ".yaml", ".yml",
}
IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "build", "dist", "node_modules",
    "packages", "vendor", "__pycache__",
}
RULES_PATH = Path(__file__).with_name("rules") / "code_review.json"
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_RULE_KINDS = {
    "call",
    "credential_assignment",
    "disabled_tls",
    "dynamic_evaluation",
    "private_key_literal",
    "regex",
    "shell_execution",
    "sql_sink",
    "unsafe_yaml",
}


def load_code_review_rules(path: Path = RULES_PATH) -> list[dict[str, Any]]:
    try:
        catalog = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not load code-review rules from {path}: {exc}") from exc
    if (
        not isinstance(catalog, dict)
        or type(catalog.get("schema_version")) is not int
        or catalog["schema_version"] != 1
    ):
        raise ValueError(f"Unsupported code-review rules schema in {path}.")
    rules = catalog.get("rules")
    if not isinstance(rules, list):
        raise ValueError(f"Code-review rules in {path} must contain a rules list.")

    identifiers = set()
    validated = []
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError(f"Invalid code-review rule in {path}: each rule must be an object.")
        required = ("id", "kind", "title", "severity", "remediation")
        if any(not isinstance(rule.get(key), str) or not rule[key] for key in required):
            raise ValueError(f"Invalid code-review rule in {path}: missing required string fields.")
        if rule["id"] in identifiers:
            raise ValueError(f"Duplicate code-review rule ID {rule['id']!r} in {path}.")
        if rule["kind"] not in VALID_RULE_KINDS or rule["severity"] not in VALID_SEVERITIES:
            raise ValueError(f"Invalid kind or severity for code-review rule {rule['id']!r}.")
        if (
            not isinstance(rule["extensions"], list)
            or not rule["extensions"]
            or any(not isinstance(extension, str) for extension in rule["extensions"])
            or any(extension not in CODE_EXTENSIONS for extension in rule["extensions"])
        ):
            raise ValueError(f"Invalid file extensions for code-review rule {rule['id']!r}.")
        list_fields = {
            "credential_assignment": ("keywords",),
            "private_key_literal": ("markers",),
            "dynamic_evaluation": ("calls",),
            "shell_execution": ("calls",),
            "call": ("calls",),
            "unsafe_yaml": ("calls",),
            "disabled_tls": ("false_keywords", "constant_values"),
            "sql_sink": ("calls", "taint_sources"),
        }.get(rule["kind"], ())
        for field in list_fields:
            values = rule.get(field)
            if (
                not isinstance(values, list)
                or not values
                or any(not isinstance(value, str) or not value for value in values)
            ):
                raise ValueError(
                    f"Code-review rule {rule['id']!r} needs a non-empty string list for {field}."
                )
        if rule["kind"] == "regex":
            pattern = rule.get("pattern")
            if not isinstance(pattern, str):
                raise ValueError(f"Regex rule {rule['id']!r} is missing its pattern.")
            try:
                rule = {**rule, "_compiled_pattern": re.compile(pattern)}
            except re.error as exc:
                raise ValueError(f"Invalid regex for code-review rule {rule['id']!r}: {exc}") from exc
        if rule["kind"] in {"call", "dynamic_evaluation", "shell_execution", "sql_sink", "unsafe_yaml"}:
            if not isinstance(rule.get("calls"), list) or not rule["calls"]:
                raise ValueError(f"Code-review rule {rule['id']!r} is missing call names.")
        identifiers.add(rule["id"])
        validated.append(rule)
    return validated


class _PythonRuleVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, rules: list[dict[str, Any]]):
        self.path = path
        self.rules = [rule for rule in rules if ".py" in rule["extensions"] and rule["kind"] != "regex"]
        self.findings: list[dict[str, Any]] = []
        self.finding_keys: set[tuple[str, int]] = set()
        self.tainted_names: set[str] = set()
        self.dynamic_names: set[str] = set()
        self.aliases: dict[str, str] = {}

    def _record(self, rule: dict[str, Any], node: ast.AST) -> None:
        line = getattr(node, "lineno", 1)
        key = (rule["id"], line)
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        self.findings.append({
            "rule_id": rule["id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "path": str(self.path),
            "line": line,
            "remediation": rule["remediation"],
            "reviewer": "Morpheus AST rules",
        })

    def _name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            prefix = self._name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _matches_call(rule: dict[str, Any], name: str) -> bool:
        return any(name == expected or name.endswith(f".{expected}") for expected in rule["calls"])

    def _is_tainted(self, node: ast.AST | None, rule: dict[str, Any]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted_names
        if isinstance(node, (ast.Call, ast.Attribute)):
            name = self._name(node.func if isinstance(node, ast.Call) else node)
            if any(name == source or name.endswith(f".{source}") for source in rule["taint_sources"]):
                return True
        if isinstance(node, ast.Constant):
            return False
        return any(self._is_tainted(child, rule) for child in ast.iter_child_nodes(node))

    def _is_dynamic_query(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.dynamic_names or node.id in self.tainted_names
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(value, ast.FormattedValue) for value in node.values)
        if isinstance(node, ast.BinOp):
            return isinstance(node.op, (ast.Add, ast.Mod)) and not (
                isinstance(node.left, ast.Constant)
                and isinstance(node.right, ast.Constant)
            )
        return False

    @staticmethod
    def _assigned_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            return set().union(*(_PythonRuleVisitor._assigned_names(item) for item in target.elts))
        return set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        prefix = node.module or ""
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{prefix}.{alias.name}".strip(".")

    def _visit_function_scope(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        outer_tainted = self.tainted_names
        outer_dynamic = self.dynamic_names
        self.tainted_names = set(outer_tainted)
        self.dynamic_names = set(outer_dynamic)
        parameters = {
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
                *([node.args.vararg] if node.args.vararg else []),
                *([node.args.kwarg] if node.args.kwarg else []),
            )
        }
        self.tainted_names.difference_update(parameters)
        self.dynamic_names.difference_update(parameters)
        for statement in node.body:
            self.visit(statement)
        self.tainted_names = outer_tainted
        self.dynamic_names = outer_dynamic

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function_scope(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in (*node.decorator_list, *node.bases, *node.keywords):
            self.visit(expression)
        outer_tainted = self.tainted_names
        outer_dynamic = self.dynamic_names
        self.tainted_names = set(outer_tainted)
        self.dynamic_names = set(outer_dynamic)
        for statement in node.body:
            self.visit(statement)
        self.tainted_names = outer_tainted
        self.dynamic_names = outer_dynamic

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        sql_rules = [rule for rule in self.rules if rule["kind"] == "sql_sink"]
        tainted = any(self._is_tainted(node.value, rule) for rule in sql_rules)
        dynamic = any(self._is_dynamic_query(node.value) for _rule in sql_rules)
        for target in node.targets:
            names = self._assigned_names(target)
            self.tainted_names.difference_update(names)
            self.dynamic_names.difference_update(names)
            if tainted:
                self.tainted_names.update(names)
            if dynamic:
                self.dynamic_names.update(names)
            self._check_credential_target(target, node.value, node)
            self.visit(target)
        self._check_private_key_literal(node.value, node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            names = self._assigned_names(node.target)
            self.tainted_names.difference_update(names)
            self.dynamic_names.difference_update(names)
            sql_rules = [rule for rule in self.rules if rule["kind"] == "sql_sink"]
            if any(self._is_tainted(node.value, rule) for rule in sql_rules):
                self.tainted_names.update(names)
            if any(self._is_dynamic_query(node.value) for _rule in sql_rules):
                self.dynamic_names.update(names)
            self._check_credential_target(node.target, node.value, node)
            self._check_private_key_literal(node.value, node)
        self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        names = self._assigned_names(node.target)
        sql_rules = [rule for rule in self.rules if rule["kind"] == "sql_sink"]
        if any(self._is_tainted(node.value, rule) for rule in sql_rules):
            self.tainted_names.update(names)
        if any(self._is_dynamic_query(node.value) for _rule in sql_rules):
            self.dynamic_names.update(names)
        self.visit(node.target)

    def _visit_branches(self, branches: list[list[ast.stmt]]) -> None:
        original_tainted = self.tainted_names
        original_dynamic = self.dynamic_names
        branch_tainted = []
        branch_dynamic = []
        for statements in branches:
            self.tainted_names = set(original_tainted)
            self.dynamic_names = set(original_dynamic)
            for statement in statements:
                self.visit(statement)
            branch_tainted.append(self.tainted_names)
            branch_dynamic.append(self.dynamic_names)
        self.tainted_names = set.union(original_tainted, *branch_tainted)
        self.dynamic_names = set.union(original_dynamic, *branch_dynamic)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        self._visit_branches([node.body, node.orelse])

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self.visit(node.target)
        self._visit_branches([node.body, node.orelse])

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        self._visit_branches([node.body, node.orelse])

    def visit_Try(self, node: ast.Try) -> None:
        branches = [node.body, *[handler.body for handler in node.handlers], node.orelse]
        self._visit_branches(branches)
        for statement in node.finalbody:
            self.visit(statement)

    def _check_credential_target(self, target: ast.AST, value: ast.AST, node: ast.AST) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or len(value.value) < 4:
            return
        for rule in self.rules:
            if rule["kind"] != "credential_assignment":
                continue
            if any(
                keyword.casefold() in name.casefold().replace("-", "_")
                for name in self._assigned_names(target)
                for keyword in rule["keywords"]
            ):
                self._record(rule, node)

    def _check_private_key_literal(self, value: ast.AST, node: ast.AST) -> None:
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        for rule in self.rules:
            if rule["kind"] == "private_key_literal" and any(
                marker in value.value for marker in rule["markers"]
            ):
                self._record(rule, node)

    def visit_Constant(self, node: ast.Constant) -> None:
        self._check_private_key_literal(node, node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._name(node.func)
        for rule in self.rules:
            kind = rule["kind"]
            if kind == "call" and self._matches_call(rule, call_name):
                self._record(rule, node)
            elif kind == "dynamic_evaluation" and self._matches_call(rule, call_name):
                if node.args and not isinstance(node.args[0], ast.Constant):
                    self._record(rule, node)
            elif kind == "shell_execution" and self._matches_call(rule, call_name):
                if call_name.endswith("os.system") or any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                ):
                    self._record(rule, node)
            elif kind == "sql_sink" and self._matches_call(rule, call_name) and node.args:
                query = node.args[0]
                if self._is_tainted(query, rule) or self._is_dynamic_query(query):
                    self._record(rule, node)
            elif kind == "unsafe_yaml" and self._matches_call(rule, call_name):
                loader = next(
                    (keyword.value for keyword in node.keywords if keyword.arg in {"Loader", "loader"}),
                    node.args[1] if len(node.args) > 1 else None,
                )
                if loader is None or not any(
                    safe_name in self._name(loader)
                    for safe_name in ("SafeLoader", "CSafeLoader")
                ):
                    self._record(rule, node)
            elif kind == "disabled_tls":
                for keyword in node.keywords:
                    if keyword.arg in rule["false_keywords"] and (
                        isinstance(keyword.value, ast.Constant) and keyword.value.value is False
                    ):
                        self._record(rule, node)
                    if self._name(keyword.value) in rule["constant_values"]:
                        self._record(rule, node)
        self.generic_visit(node)


def _python_findings(path: Path, source: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise ValueError(f"Python source could not be parsed at line {exc.lineno}: {exc.msg}") from exc
    visitor = _PythonRuleVisitor(path, rules)
    visitor.visit(tree)
    return visitor.findings


class CodeReview:
    def __init__(self, rules_path: Path = RULES_PATH):
        self.rules = load_code_review_rules(rules_path)
        self._rules_by_extension = {
            extension: [
                rule for rule in self.rules
                if extension in rule["extensions"]
            ]
            for extension in CODE_EXTENSIONS
        }

    def review_path(self, path: str | Path) -> dict:
        target = Path(path).expanduser()
        try:
            target = target.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise FileNotFoundError(f"Could not find the selected file or folder: {path}") from exc

        if is_protected_system_path(target):
            raise ProtectedSystemPathError("Windows system and protected application files are excluded from code review.")
        if target.is_file():
            return self._review_one(target)
        if target.is_dir():
            return self._review_folder(target)
        raise FileNotFoundError(f"The selected path is not a file or folder: {target}")

    def _review_one(self, path: Path) -> dict:
        if path.suffix.casefold() not in CODE_EXTENSIONS:
            raise ValueError(f"Unsupported source-code file type: {path.suffix or '(no extension)'}")
        findings = self._review_file(path)
        return {
            "path": str(path),
            "files_scanned": 1,
            "findings": findings,
            "failures": [],
            "truncated": False,
            "ruleset": self._ruleset(),
        }

    def _review_folder(self, root: Path) -> dict:
        roots = protected_system_roots()
        files_scanned = 0
        findings = []
        failures = []

        def record_walk_error(error: OSError) -> None:
            failures.append({
                "path": str(getattr(error, "filename", None) or root),
                "message": str(error),
            })

        for current, directories, filenames in os.walk(root, followlinks=False, onerror=record_walk_error):
            current_path = Path(current)
            directories[:] = [
                name for name in directories
                if name.casefold() not in IGNORED_DIRECTORIES
                and not (current_path / name).is_symlink()
                and not (
                    hasattr(current_path / name, "is_junction")
                    and (current_path / name).is_junction()
                )
                and not is_protected_system_path(current_path / name, protected_roots=roots)
            ]
            for filename in filenames:
                candidate = current_path / filename
                if candidate.suffix.casefold() not in CODE_EXTENSIONS:
                    continue
                if candidate.is_symlink() or (
                    hasattr(candidate, "is_junction") and candidate.is_junction()
                ):
                    continue
                try:
                    findings.extend(self._review_file(candidate))
                    files_scanned += 1
                except (OSError, UnicodeError, ValueError, MemoryError) as exc:
                    failures.append({"path": str(candidate), "message": str(exc)})

        return {
            "path": str(root),
            "files_scanned": files_scanned,
            "findings": findings,
            "failures": failures,
            "truncated": False,
            "ruleset": self._ruleset(),
        }

    @staticmethod
    def _ruleset() -> str:
        return "Morpheus offline AST and JSON rules v2"

    def _review_file(self, path: Path) -> list[dict]:
        if path.suffix.casefold() == ".py":
            source = path.read_text(encoding="utf-8-sig")
            return _python_findings(path, source, self.rules)

        findings = []
        finding_keys = set()
        rules = [
            rule for rule in self._rules_by_extension[path.suffix.casefold()]
            if rule["kind"] == "regex"
        ]
        line_number = 1
        overlap = ""
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as source:
            while chunk := source.read(CODE_REVIEW_CHUNK_CHARS):
                scan_text = overlap + chunk
                scan_line_number = line_number - overlap.count("\n")
                for offset, line in enumerate(scan_text.splitlines()):
                    if line.lstrip().startswith(("//", "/*", "*", "--", "#")):
                        continue
                    for rule in rules:
                        if not rule["_compiled_pattern"].search(line):
                            continue
                        absolute_line = scan_line_number + offset
                        key = (rule["id"], absolute_line)
                        if key in finding_keys:
                            continue
                        finding_keys.add(key)
                        findings.append({
                            "rule_id": rule["id"],
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "path": str(path),
                            "line": absolute_line,
                            "remediation": rule["remediation"],
                            "reviewer": "Morpheus JSON rules",
                        })
                line_number += chunk.count("\n")
                overlap = scan_text[-RULE_SCAN_OVERLAP_CHARS:]
        return findings
