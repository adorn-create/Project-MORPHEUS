import os
import re
from pathlib import Path

from .scanner import (
    ProtectedSystemPathError,
    is_protected_system_path,
    protected_system_roots,
)

MAX_CODE_FILE_SIZE = 2 * 1024 * 1024
MAX_CODE_REVIEW_FILES = 2_000
MAX_CODE_REVIEW_BYTES = 100 * 1024 * 1024
CODE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".sh", ".sql", ".ts",
    ".tsx", ".vue", ".yaml", ".yml",
}
IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "build", "dist", "node_modules",
    "packages", "vendor", "__pycache__",
}
MAX_FINDINGS = 500

RULES = (
    (
        "hardcoded-credential",
        "Potential hard-coded credential",
        "high",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)\b\s*[:=]\s*['"][^'"]{4,}['"]"""
        ),
        "Move credentials to a protected secret store or environment-based configuration, and rotate any real credential.",
        CODE_EXTENSIONS,
    ),
    (
        "private-key-material",
        "Private key material in source",
        "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Remove the key from source control, revoke or rotate it, and load it from a protected secret store.",
        CODE_EXTENSIONS,
    ),
    (
        "dynamic-evaluation",
        "Dynamic code evaluation",
        "high",
        re.compile(r"\b(?:eval|exec)\s*\("),
        "Avoid evaluating untrusted text as code; use a constrained parser or explicit operation mapping.",
        {".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"},
    ),
    (
        "shell-command",
        "Subprocess uses a command shell",
        "high",
        re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\([^)]{0,1000}\bshell\s*=\s*True", re.I),
        "Pass an argument list with shell=False and validate each argument; avoid building commands from user input.",
        {".py"},
    ),
    (
        "unsafe-deserialization",
        "Unsafe pickle deserialization",
        "high",
        re.compile(r"\bpickle\.(?:loads?|Unpickler)\s*\("),
        "Do not deserialize pickle data from untrusted sources; use a data-only format and validate its schema.",
        {".py"},
    ),
    (
        "unsafe-yaml",
        "Potentially unsafe YAML loading",
        "high",
        re.compile(r"\byaml\.load\s*\("),
        "Use yaml.safe_load for untrusted YAML, or explicitly configure a safe loader.",
        {".py"},
    ),
    (
        "tls-verification-disabled",
        "TLS certificate verification disabled",
        "high",
        re.compile(r"\b(?:verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False)\b", re.I),
        "Keep certificate and hostname verification enabled; fix the certificate chain instead of bypassing validation.",
        CODE_EXTENSIONS - {".sql", ".yaml", ".yml"},
    ),
    (
        "weak-hash",
        "Weak cryptographic hash",
        "medium",
        re.compile(r"\bhashlib\.(?:md5|sha1)\s*\(", re.I),
        "Use SHA-256 or a modern password-hashing scheme as appropriate; MD5 and SHA-1 are not suitable for security decisions.",
        {".py"},
    ),
    (
        "unsafe-html",
        "Potentially unsafe HTML insertion",
        "high",
        re.compile(r"\.innerHTML\s*="),
        "Prefer textContent or a vetted HTML sanitizer when inserting data that may contain user-controlled content.",
        {".js", ".jsx", ".ts", ".tsx", ".vue"},
    ),
    (
        "sql-interpolation",
        "Potential SQL string interpolation",
        "high",
        re.compile(r"\.execute\s*\(\s*(?:f['\"]|['\"][^'\"]*(?:%s|\\?\{))", re.I),
        "Use parameterized SQL queries instead of interpolating values into query strings.",
        {".py"},
    ),
    (
        "cpp-unsafe-string-function",
        "Unsafe C/C++ string function",
        "high",
        re.compile(r"\b(?:strcpy|strcat|sprintf|gets)\s*\("),
        "Use bounded operations and validate buffer sizes; prefer safer abstractions such as std::string where practical.",
        {".c", ".cc", ".cpp", ".h", ".hpp"},
    ),
    (
        "cpp-shell-execution",
        "C/C++ shell execution",
        "high",
        re.compile(r"\b(?:system|popen|_popen)\s*\("),
        "Avoid passing constructed strings to a shell. Use a constrained process API with fixed executable and validated arguments.",
        {".c", ".cc", ".cpp", ".h", ".hpp"},
    ),
    (
        "sql-dynamic-concatenation",
        "Potential dynamic SQL concatenation",
        "high",
        re.compile(
            r"(?i)(?:\bEXECUTE\s+IMMEDIATE\b[^\n]*(?:\|\||\+)\s*[A-Za-z_]"
            r"|\bEXEC(?:UTE)?\s*\([^)]*(?:\|\||\+)\s*[A-Za-z_])"
        ),
        "Avoid constructing executable SQL with string concatenation; use parameterized statements and validated identifiers.",
        {".sql"},
    ),
)


class CodeReview:
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
            "ruleset": "Morpheus local rules v1",
        }

    def _review_folder(self, root: Path) -> dict:
        roots = protected_system_roots()
        files_scanned = 0
        candidates_seen = 0
        total_bytes = 0
        findings = []
        failures = []
        truncated = False

        def record_walk_error(error: OSError) -> None:
            failures.append({
                "path": str(getattr(error, "filename", None) or root),
                "message": str(error),
            })

        for current, directories, filenames in os.walk(
            root, followlinks=False, onerror=record_walk_error
        ):
            current_path = Path(current)
            retained = []
            for name in directories:
                candidate = current_path / name
                if (
                    name.casefold() in IGNORED_DIRECTORIES
                    or candidate.is_symlink()
                    or (hasattr(candidate, "is_junction") and candidate.is_junction())
                    or is_protected_system_path(candidate, protected_roots=roots)
                ):
                    continue
                retained.append(name)
            directories[:] = retained

            for filename in filenames:
                candidate = current_path / filename
                if candidate.suffix.casefold() not in CODE_EXTENSIONS:
                    continue
                if candidate.is_symlink() or (hasattr(candidate, "is_junction") and candidate.is_junction()):
                    continue
                if candidates_seen >= MAX_CODE_REVIEW_FILES:
                    truncated = True
                    break
                candidates_seen += 1
                try:
                    size = candidate.stat().st_size
                    if size > MAX_CODE_FILE_SIZE:
                        failures.append({"path": str(candidate), "message": "File exceeds the 2 MB per-file code-review limit."})
                        continue
                    if total_bytes + size > MAX_CODE_REVIEW_BYTES:
                        truncated = True
                        break
                    total_bytes += size
                    findings.extend(self._review_file(candidate))
                    files_scanned += 1
                except (OSError, UnicodeError, ValueError) as exc:
                    failures.append({"path": str(candidate), "message": str(exc)})
                if len(findings) >= MAX_FINDINGS:
                    findings = findings[:MAX_FINDINGS]
                    truncated = True
                    break
            if truncated:
                break

        return {
            "path": str(root),
            "files_scanned": files_scanned,
            "findings": findings,
            "failures": failures,
            "truncated": truncated,
            "ruleset": "Morpheus local rules v1",
        }

    @staticmethod
    def _review_file(path: Path) -> list[dict]:
        try:
            with path.open("rb") as source:
                content = source.read(MAX_CODE_FILE_SIZE + 1)
        except OSError:
            raise
        if len(content) > MAX_CODE_FILE_SIZE:
            raise ValueError("File exceeds the 2 MB per-file code-review limit.")
        if b"\0" in content:
            raise ValueError("File appears to be binary and was not reviewed as source code.")

        findings = []
        for line_number, line in enumerate(content.decode("utf-8-sig", errors="replace").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "/*", "*", "--")):
                continue
            for rule_id, title, severity, pattern, remediation, extensions in RULES:
                if path.suffix.casefold() not in extensions:
                    continue
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "title": title,
                        "severity": severity,
                        "path": str(path),
                        "line": line_number,
                        "remediation": remediation,
                    })
                    if len(findings) >= MAX_FINDINGS:
                        return findings
        return findings
