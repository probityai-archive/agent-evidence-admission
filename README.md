<!-- moved-to-monorepo -->
> **Moved to [probityai/agent-evidence-vectors/packages/admission](https://github.com/probityai/agent-evidence-vectors/tree/main/packages/admission). Star and follow it there.** This repository is archived and has no planned delete date; its tags and releases keep working.

# agent-evidence-admission

Admission checks for artifact bytes and workload evidence: a Python digest checker plus OPA,
Kyverno and sigstore policy-controller policies.

For integrators who bind a document to release bytes, and platform engineers who gate workloads
on declared execution evidence.

## Check an artifact digest

Start in a new directory with Python 3.10 or newer and [uv](https://github.com/astral-sh/uv).
Install the checker in its own environment, then check a synthetic in-toto statement:

```sh
uv venv admission-env
uv pip install --python admission-env/bin/python agent-evidence-admission==0.1.0
printf 'abc' > artifact.txt
cat > statement.json <<'JSON'
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "artifact.txt", "digest": {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}],
  "predicateType": "https://example.org/digest-demo/v1",
  "predicate": {}
}
JSON
admission-env/bin/agent-evidence-admission digest-check statement.json artifact.txt
```

It prints:

```text
PASS artifact.txt has sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad, named in statement.json
```

Exit 0 means a named digest matches. Exit 1 means a mismatch or no named digest; exit 2 means a read error.
A match binds the document to bytes. It does not verify a signature or admit a workload.
See the [package guide](https://github.com/probityai/agent-evidence-admission/blob/main/python/README.md) for supported documents.

## Quick start

For Kubernetes, pin the policies to a commit and evaluate the sample statement with OPA:

```bash
git clone https://github.com/probityai/agent-evidence-admission && cd agent-evidence-admission
git checkout 1ded5b8d1ae4d13b8a2c3b61fc18f6a2d9d40119
opa eval -f raw -d rego/execution_evidence.rego \
  -I 'count(data.sigstore.errors)' < samples/adversarial-execution-evidence.pass.statement.json
```

It prints `3`: a deployment that has pinned nothing, and has not declared that it runs unpinned,
admits nothing. Pin the corpus, the substrate
and the classes you demand, and the policy admits the same statement:

```bash
cat > pins.json <<'JSON'
{"consumer": {
  "expected_corpus_digest": "cc1bdef2ffca96d86a636e5a9fb27a4a111836773e0dd1368d8de94f413979be",
  "expected_substrate_digest": "018bbaf3710e526b0653abafbd3bd3c3356150d747db166021f1e107446c85bb",
  "demanded_classes": ["XA"]
}}
JSON
opa eval -f raw -d rego/execution_evidence.rego -d pins.json \
  -I 'data.sigstore.isCompliant' < samples/adversarial-execution-evidence.pass.statement.json
```

It prints `true`. `opa test --timeout 120s rego/` runs the oracle's own test suite.

## Status

The Python digest checker is version 0.1.0.
The policies follow the in-toto Adversarial Execution Evidence predicate v0.7, proposed in
[in-toto/attestation#570](https://github.com/in-toto/attestation/pull/570). The profile registry
measures them against the [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors) corpus
at tag v0.10.1. The rails evaluate a statement whose envelope signature your engine's key
authority has already verified; they don't verify signatures themselves. Until you pin them, or
declare that you run unpinned, the policies refuse every statement that depends on a consumer
setting with no safe default.

## Documentation

| page | read it for |
| --- | --- |
| [Start a project](https://github.com/new?template_name=evidence-starter&template_owner=probityai) | a template with the evidence packages pinned and the conformance Action in CI |
| <a name="verify-the-claim-in-four-commands"></a><a name="what-is-here"></a><a name="why-the-rails-are-published"></a><a name="the-trust-ceiling-stated-before-you-rely-on-any-of-it"></a><a name="the-profile-registry"></a><a name="the-adversarial-ratchet"></a><a name="running-the-conformance-harness"></a><a name="continuous-integration"></a><a name="citation-and-provenance"></a>[Design, trust ceiling and evidence](https://github.com/probityai/agent-evidence-admission/blob/main/docs/DESIGN.md) | the file map, the trust ceiling, how each obligation's disposition is measured, and how to re-run the measurement |
| [Consumer policy](https://github.com/probityai/agent-evidence-admission/blob/main/docs/CONSUMER-POLICY.md) | the pins, what each one decides, and what an absent value means |
| [Agent change admission](https://github.com/probityai/agent-evidence-admission/blob/main/docs/AGENT-CHANGE-ADMISSION.md) | admit an agent harness version only on a signed decision that admitted it, on OPA, Kyverno CEL and policy-controller |
| [Verifier isolation](https://github.com/probityai/agent-evidence-admission/blob/main/docs/VERIFIER-ISOLATION.md) | refuse a done verdict whose verifier left one of the nine reward-tampering vectors of terminal-bench issue 2086 open, on OPA, Kyverno CEL and CUE (<!-- vi-enforced -->enforced: `cue` 0 of 9, `kyverno-cel` 9 of 9, `rego` 9 of 9<!-- /vi-enforced -->) |
| [Model report gate](https://github.com/probityai/agent-evidence-admission/blob/main/consumers/policy-vocabulary/README.md) | install a selected reader, repeat the native report and enforce separate publication and quality decisions |
| [Pre-call budget](https://github.com/probityai/agent-evidence-admission/blob/main/consumers/spend-reservation/README.md) | reserve the maximum cost before dispatch and retain signed local effects |
| [Profile registry](https://github.com/probityai/agent-evidence-admission/blob/main/PROFILE-REGISTRY.md) | the enforced, approximated and unreachable obligations per rail |
| [Maturity model mapping](https://github.com/probityai/agent-evidence-admission/blob/main/docs/AUTOMATED-GOVERNANCE-MATURITY-MODEL.md) | each item of the CNCF Automated Governance Maturity Model and the file that serves it |
| [Adversarial ratchet](https://github.com/probityai/agent-evidence-admission/blob/main/docs/ADVERSARIAL-RATCHET.md) | the open adversarial-mutation findings against these rails |
| [Contributing](https://github.com/probityai/agent-evidence-admission/blob/main/CONTRIBUTING.md) and [provenance](https://github.com/probityai/agent-evidence-admission/blob/main/PROVENANCE.md) | how to propose a change, and where each policy file came from |

## License

Apache-2.0. Cite with [CITATION.cff](https://github.com/probityai/agent-evidence-admission/blob/main/CITATION.cff).
