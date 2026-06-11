"""The auditable no-phone-home claims, enforced.

1. AST scan: the verifier package may import only zkage_core and pure stdlib
   data modules — no sockets, files, clocks, environment, or subprocesses.
2. Dependency graph: zkage-verifier depends on zkage-core only; zkage-core
   depends on cryptography only. An auditor can re-check both claims here.
"""

import ast
from importlib import metadata
from pathlib import Path

import zkage_verifier

ALLOWED_IMPORT_ROOTS = {
    "__future__",
    "dataclasses",
    "enum",
    "typing",
    "zkage_core",
    "zkage_verifier",
}
FORBIDDEN_BUILTIN_CALLS = {"open", "exec", "eval", "__import__", "input", "compile"}


def test_verifier_package_is_pure() -> None:
    package_dir = Path(zkage_verifier.__file__).parent
    files = sorted(package_dir.rglob("*.py"))
    assert files, "verifier package sources not found"
    for path in files:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root in ALLOWED_IMPORT_ROOTS, f"{path.name}: import {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert node.level == 0, f"{path.name}: relative import"
                assert root in ALLOWED_IMPORT_ROOTS, f"{path.name}: from {node.module} import ..."
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_BUILTIN_CALLS, (
                    f"{path.name}: forbidden builtin call {node.func.id}()"
                )


def _runtime_dependency_roots(distribution: str) -> set[str]:
    requires = metadata.requires(distribution) or []
    roots = set()
    for spec in requires:
        if "extra ==" in spec:
            continue
        name = spec.split(";")[0].strip()
        for sep in ("<", ">", "=", "!", "~", "[", "("):
            name = name.split(sep)[0]
        roots.add(name.strip().lower())
    return roots


def test_dependency_graph_is_minimal() -> None:
    assert _runtime_dependency_roots("zkage-verifier") == {"zkage-core"}
    assert _runtime_dependency_roots("zkage-core") == {"cryptography"}
