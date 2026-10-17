# Verifier isolation

Refuse a done verdict whose verifier was not isolated from the code it graded. The [README](../README.md) is the short version of the repository; this page covers the third rule set it carries.

A coding agent says it is done. A verifier runs the contract's acceptance commands on the agent's final tree and returns a verdict. The verdict is worth what the verifier's isolation is worth. [Terminal-bench issue 2086](https://github.com/harbor-framework/terminal-bench/issues/2086) lists nine ways submitted code reaches into a verifier (V1 to V9) and seven hardening steps that close most of them. This rule set turns the nine into nine obligations, `vi-1` to `vi-9`, and refuses a done receipt whose own isolation report leaves one open.

## Try it

Evaluate a receipt whose verifier left the result directory world-writable, the way Harbor's default does:

```bash
python3 - <<'PY' > leaky.json
import json
v = json.load(open("rego/verifier_isolation_vectors.json"))["verifier_isolation_vectors"]["cases"]
print(json.dumps(v["vi3-result-dir-777"]["input"]))
PY
echo '{"verifier_isolation_consumer": {"signature_verified_upstream": true}}' > pins.json
opa eval -f raw -d rego/verifier_isolation.rego -d pins.json -I 'data.verifier_isolation.reasons' < leaky.json
```

It prints `["vi-3:result_dir_open_to_worker"]`. The same command on `baseline-admitted` prints `[]`.

## Files

| path | what it is |
|---|---|
| `rego/verifier_isolation.rego` | The rule set, package `verifier_isolation`. |
| `rego/verifier_isolation_vectors.json` | The vectors: a baseline that closes all nine vectors, and cases that each open one fact. Written by `rego/gen_verifier_isolation_vectors.py`; never edit it by hand. |
| `rego/verifier_isolation_test.rego` | One test per vector, written by the same generator. |
| `registry/verifier-isolation.json` | The family: the nine obligations, the seven hardening steps and the source capture they were read from. |
| `conformance/run_verifier_isolation_conformance.py` | Measures the family and writes `verifier-isolation/PROFILE-MAP.json`. |
| `PROFILE-REGISTRY.md` | Renders the family beside the adversarial-execution-evidence obligations. |

## The input

An in-toto Statement v1, after the engine's key authority verified its envelope. Its predicate type is the done receipt's, `https://probityai.github.io/probity/predicate/v1/done-receipt`, and the isolation facts sit in `predicate.verifier_isolation`. The verifier harness writes them at the end of the grading run.

| field | type | read by |
|---|---|---|
| `contract_sha256` | 64 lowercase hex | all; compared with the consumer pin when one is set |
| `trusted_tree.expected_sha256`, `trusted_tree.measured_sha256` | 64 lowercase hex, equal | `vi-1` |
| `trusted_tree.excluded_names_reset` | `true` | `vi-1` |
| `worker.uid`, `verifier.uid` | numbers, different, the worker's not 0 | `vi-2` |
| `worker.supplementary_groups` | empty array | `vi-2` |
| `verifier.assertions_in_parent`, `verifier.python_isolated` | `true` | `vi-2` |
| `result.dir_mode` | octal string with no group or other bits | `vi-3` |
| `result.precleared`, `result.written_by`, `result.files_read` | `true`, `"verifier"`, an array of exactly one name | `vi-3` |
| `tests.expected`, `tests.collected`, `tests.skipped`, `tests.exit_status_alone_accepted` | positive number, equal number, `0`, `false` | `vi-4` |
| `processes.worker_killed`, `processes.remaining`, `processes.killed_step`, `processes.result_read_step` | `true`, `0`, kill step before read step | `vi-5` |
| `staging.nofollow`, `staging.destination_removed_first`, `staging.special_files_rejected` | `true` | `vi-6` |
| `evidence_from_worker` | empty array | `vi-7` |
| `worker.env_scrubbed`, `worker.scratch_copy` | `true` | `vi-7` |
| `reference.dir_mode`, `reference.inside_artifact_dir` | octal string with no group or other bits, `false` | `vi-8` |
| `loaders` | non-empty array of `{name, safe}`, every `safe` true | `vi-9` |

A fact that is absent, or of the wrong type, counts as open. A string `"true"` closes nothing.

## The obligations

| obligation | vector | hardening step | refusal reasons |
|---|---|---|---|
| `vi-1` | V1 Overwrite | none | `trusted_tree_not_reset_to_contract`, `excluded_names_not_reset` |
| `vi-2` | V2 Patch | 2, 4 | `worker_not_unprivileged`, `worker_supplementary_groups_kept`, `assertions_not_in_parent`, `trusted_python_not_isolated` |
| `vi-3` | V3 Reward | 1 | `result_dir_open_to_worker`, `result_not_precleared`, `result_not_written_by_verifier`, `result_source_ambiguous` |
| `vi-4` | V4 Fail-open | 7 | `no_tests_expected`, `test_count_mismatch`, `tests_skipped`, `verdict_from_exit_status_alone` |
| `vi-5` | V5 Sleeper | 5 | `worker_processes_not_killed`, `worker_processes_remain`, `result_read_before_kill` |
| `vi-6` | V6 Staging | 6 | `links_followed`, `destination_not_removed_first`, `special_files_admitted` |
| `vi-7` | V7 Forgery | 2 | `evidence_taken_from_worker`, `environment_not_scrubbed`, `no_scratch_copy` |
| `vi-8` | V8 Disclosure | 3 | `reference_readable_by_worker`, `reference_inside_artifact` |
| `vi-9` | V9 Exploit | none | `loaders_undeclared`, `unsafe_loader:<name>` |

Each reason is returned as `vi-N:<reason>`. Statement-level reasons are `signature_verification_undeclared`, `unsupported_statement_type`, `unsupported_predicate`, `isolation_report_missing`, `contract_digest_invalid` and `contract_digest_mismatch`.

The issue's hardening steps do not close V2 where agent code is imported into the process that runs the assertions. `vi-2` asks for the issue's second pattern as well: the worker is unprivileged, and the assertions run in the parent.

## Consumer pins

The module reads `data.verifier_isolation_consumer`.

| pin | meaning | absent |
|---|---|---|
| `signature_verified_upstream` | `true` when a verifier checked the envelope signature before this rule ran. | Every input is refused with `signature_verification_undeclared`. |
| `expected_contract_sha256` | The contract digest this deployment grades against. | Not compared. |

## What this does not establish

The report is the verifier's account of itself. The rules check that the account closes each vector. They do not check that the account is true, and Rego has no signature check. A consumer that needs more than the verifier's word pins an independent observation of the grading run as well. The done receipt's observation record carries the vantage for that.

## How a disposition is measured

`conformance/run_verifier_isolation_conformance.py` runs the module over every vector and compares each answer with the reasons the vector declares. It then deletes each refusal rule in turn and requires the module's own tests to fail. An obligation is `enforced` only when its baseline admits, a vector opens it, the module refuses that vector with a reason for that obligation, and no rule for it survives deletion. Otherwise the row is `unreachable` with the obstruction named. The result is `verifier-isolation/PROFILE-MAP.json`, and without `--write` the committed file must equal the run.

```bash
python3 rego/gen_verifier_isolation_vectors.py --check
opa test --timeout 300s rego/
python3 conformance/run_verifier_isolation_conformance.py
python3 scripts/gen_profile_registry.py --check
```

The rego module is the only rail. The Kyverno and CUE rails do not carry this family.
