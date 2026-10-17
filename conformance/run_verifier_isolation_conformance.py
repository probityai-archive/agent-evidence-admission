"""Measure the verifier isolation family and refuse a claim the measurement does not support.

    python3 conformance/run_verifier_isolation_conformance.py            # check
    python3 conformance/run_verifier_isolation_conformance.py --write    # rewrite the map
    python3 conformance/run_verifier_isolation_conformance.py --skip-mutations

The family is `registry/verifier-isolation.json`: nine obligations, one per reward-tampering
vector of terminal-bench issue 2086, and the seven hardening steps that issue lists. The only
rail is the rego module. This driver reads nothing the module did not produce, and an
obligation is `enforced` only when all of these hold:

1. The baseline vector admits, so a refusal is not a module that refuses everything.
2. The module answers every vector with exactly the refusal set the vector declares.
3. At least one vector opens the obligation, and the module's answer to it names a `vi-N:` reason.
4. The module has at least one refusal rule for the obligation, and deleting each one in turn
   turns the module's own tests red. A rule no test exercises is found here and named.
5. Every hardening step in the registry is claimed by an obligation, and every step an
   obligation claims is in the registry.
6. The obligations table in docs/VERIFIER-ISOLATION.md lists, for each obligation, exactly the
   refusal reasons the module can return and the hardening steps the registry claims.

Anything less is `unreachable` with the obstruction named, never `enforced`. The result is
written to `verifier-isolation/PROFILE-MAP.json`, and without `--write` the committed file must
equal what this run measured. The map lives outside `profiles/` on purpose: `profile-map-gate.py`
reads every map there as a rail over the 93 adversarial-execution-evidence obligations.

Needs `opa` on the path (or OPA_BIN). Exit 0 when the claim holds, 1 on a disagreement, 2 when
the run could not happen.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "rego" / "verifier_isolation.rego"
TESTS = ROOT / "rego" / "verifier_isolation_test.rego"
VECTORS = ROOT / "rego" / "verifier_isolation_vectors.json"
REGISTRY = ROOT / "registry" / "verifier-isolation.json"
MAP = ROOT / "verifier-isolation" / "PROFILE-MAP.json"
PAGE = ROOT / "docs" / "VERIFIER-ISOLATION.md"

RULE_RE = re.compile(r"^errors contains (?:sprintf\()?\"(?P<reason>[^\"]+)\"[^\n]*\{\n.*?\n\}\n", re.M | re.S)
BASELINE = "baseline-admitted"


class CouldNotRun(Exception):
    """A check could not run. Never reported as a pass."""


def opa_bin() -> str:
    found = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not found:
        raise CouldNotRun("opa was not found; install it or set OPA_BIN")
    return found


def answer(opa: str, case: dict[str, Any], work: Path) -> list[str]:
    (work / "in.json").write_text(json.dumps(case["input"]), encoding="utf-8")
    (work / "data.json").write_text(json.dumps({"verifier_isolation_consumer": case["consumer"]}), encoding="utf-8")
    proc = subprocess.run(
        [opa, "eval", "-f", "json", "-d", str(MODULE), "-d", str(work / "data.json"), "-i", str(work / "in.json"),
         "data.verifier_isolation.reasons"],
        capture_output=True, text=True, check=False,
    )
    try:
        return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise CouldNotRun(f"opa returned no value: {proc.stderr.strip()[:300]}") from exc


def rules_by_obligation(source: str, ids: list[str]) -> dict[str, list[tuple[int, int, str]]]:
    found: dict[str, list[tuple[int, int, str]]] = {i: [] for i in ids}
    for m in RULE_RE.finditer(source):
        reason = m.group("reason")
        head = reason.split(":", 1)[0]
        if head in found:
            found[head].append((m.start(), m.end(), reason))
    return found


def survives(opa: str, source: str, span: tuple[int, int, str]) -> bool:
    """True when deleting this rule leaves the module's own tests green."""
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        shutil.copy(TESTS, work / TESTS.name)
        shutil.copy(VECTORS, work / VECTORS.name)
        (work / MODULE.name).write_text(source[: span[0]] + source[span[1]:], encoding="utf-8")
        proc = subprocess.run([opa, "test", "--timeout", "120s", str(work)], capture_output=True, text=True, check=False)
    return proc.returncode == 0


def page_rows() -> dict[str, tuple[set[str], set[str]]]:
    """Per obligation, the reasons and hardening steps the docs page lists."""
    text = PAGE.read_text(encoding="utf-8").split("## The obligations", 1)[1].split("\n## ", 1)[0]
    rows: dict[str, tuple[set[str], set[str]]] = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 4 and re.fullmatch(r"`vi-[0-9]+`", cells[0]):
            steps = {f"H{n}" for n in re.findall(r"[1-7]", cells[2])}
            rows[cells[0].strip("`")] = (set(re.findall(r"`([^`]+)`", cells[3])), steps)
    return rows


def page_disagreements(rules: dict[str, list[tuple[int, int, str]]], obligations: list[dict[str, Any]]) -> list[str]:
    try:
        rows = page_rows()
    except (OSError, IndexError) as exc:
        raise CouldNotRun(f"cannot read the obligations table in {PAGE.name}: {exc}") from exc
    out: list[str] = []
    for o in obligations:
        oid = o["id"]
        shown = {r.replace("%s", "<name>") for r in (x[2] for x in rules[oid])}
        want = {r.split(":", 1)[1] for r in shown}
        got, steps = rows.get(oid, (set(), set()))
        if got != want:
            out.append(f"{PAGE.name} lists {sorted(got)} for {oid}; the module can return {sorted(want)}")
        if steps != set(o["hardening"]):
            out.append(f"{PAGE.name} lists hardening {sorted(steps)} for {oid}; the registry claims {sorted(o['hardening'])}")
    return out


def measure(skip_mutations: bool) -> tuple[dict[str, Any], list[str]]:
    opa = opa_bin()
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    obligations = registry["obligations"]
    ids = [o["id"] for o in obligations]
    hardening = set(registry["hardening"])
    cases: dict[str, Any] = json.loads(VECTORS.read_text(encoding="utf-8"))["verifier_isolation_vectors"]["cases"]
    source = MODULE.read_text(encoding="utf-8")
    failures: list[str] = []

    if BASELINE not in cases or cases[BASELINE]["reasons"]:
        raise CouldNotRun(f"the vectors carry no admitting baseline named {BASELINE}")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        got: dict[str, list[str]] = {}
        for name in sorted(cases):
            got[name] = answer(opa, cases[name], work)
            if got[name] != sorted(cases[name]["reasons"]):
                failures.append(f"vector {name}: expected {sorted(cases[name]['reasons'])}, module returned {got[name]}")

    claimed = {h for o in obligations for h in o["hardening"]}
    for missing in sorted(hardening - claimed):
        failures.append(f"hardening step {missing} is claimed by no obligation")
    for stray in sorted(claimed - hardening):
        failures.append(f"an obligation claims {stray}, which the registry does not list")

    rules = rules_by_obligation(source, ids)
    module_heads = {m.group("reason").split(":", 1)[0] for m in RULE_RE.finditer(source) if m.group("reason").startswith("vi-")}
    for stray in sorted(module_heads - set(ids)):
        failures.append(f"the module refuses with {stray}, which the registry does not list")

    failures += page_disagreements(rules, obligations)

    out: dict[str, Any] = {}
    for o in obligations:
        oid = o["id"]
        opening = sorted(n for n, c in cases.items() if c.get("opens") in (oid, "all"))
        exercising = [n for n in opening if any(r.startswith(f"{oid}:") for r in got.get(n, []))]
        row: dict[str, Any] = {"vector": o["vector"], "name": o["name"], "hardening": o["hardening"],
                               "rules": sorted(r for _, _, r in rules[oid]), "vectors_opening": len(exercising)}
        obstruction = None
        if not rules[oid]:
            obstruction = "no-refusal-rule"
        elif not exercising:
            obstruction = "no-vector-opens-it"
        elif not skip_mutations:
            alive = [r for s, e, r in rules[oid] if survives(opa, source, (s, e, r))]
            row["rules_deleted"] = len(rules[oid])
            row["rules_surviving"] = len(alive)
            if alive:
                obstruction = "rule-survives-deletion"
                failures.append(f"{oid}: deleting the rule for {alive} leaves the module's tests green")
        if any(f.startswith(f"vector {n}:") for n in opening for f in failures):
            obstruction = "module-diverges-from-vector"
        if obstruction:
            row["disposition"] = "unreachable"
            row["obstruction"] = obstruction
        else:
            row["disposition"] = "enforced"
        out[oid] = row

    doc = {
        "family": registry["family"],
        "rail": "rego",
        "artifact": "rego/verifier_isolation.rego",
        "vectors": len(cases),
        "obligations": out,
    }
    return doc, failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--write", action="store_true", help="rewrite verifier-isolation/PROFILE-MAP.json")
    parser.add_argument("--skip-mutations", action="store_true", help="skip the rule deletion sweep (a map written this way is refused)")
    args = parser.parse_args(argv[1:])
    if args.write and args.skip_mutations:
        print("a map is not written without the mutation sweep", file=sys.stderr)
        return 2
    try:
        doc, failures = measure(args.skip_mutations)
    except CouldNotRun as exc:
        print(f"could not run: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    enforced = sum(1 for r in doc["obligations"].values() if r["disposition"] == "enforced")
    print(f"{enforced} of {len(doc['obligations'])} obligations enforced over {doc['vectors']} vectors")
    if not args.skip_mutations and not failures:
        if args.write:
            MAP.parent.mkdir(parents=True, exist_ok=True)
            MAP.write_text(rendered, encoding="utf-8")
            print(f"wrote {MAP}")
        elif not MAP.is_file() or MAP.read_text(encoding="utf-8") != rendered:
            failures.append(f"{MAP.relative_to(ROOT)} is not what this run measured; rerun with --write and commit")
    for f in failures:
        print(f, file=sys.stderr)
    print(f"{len(failures)} disagreement(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
