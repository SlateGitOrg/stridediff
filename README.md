# stridediff

> Architecture-as-code with a STRIDE delta on every pull request, so the threat model stops being a document written once.

`COMPACT` · **Cybersecurity** · Intermediate · ~5 days · Regulated software teams

**Primary language:** TypeScript
**Tags:** `threat-modelling`, `stride`, `ci`, `architecture-as-code`, `cli`

---

## The problem

Threat models are written once during design review, then the architecture changes forty times and the document is never touched. Security review becomes a calendar event rather than a property of the change - so the review happens when nothing is being built, and the building happens when nobody is reviewing.

## ⭐ The differentiator

Treats **architecture as code** - a C4-style YAML model of components, trust boundaries and data flows - and emits a **STRIDE delta on each pull request**: 'this change adds a flow crossing the internet trust boundary carrying PII; new threats: spoofing, tampering, information disclosure.' A generic approach produces a static threat-model document. This one fails CI when a new boundary crossing has no recorded mitigation, which is what makes it a control rather than a artefact.

This is the sentence to lead with when someone asks you to walk through the
project. Everything else in this repo exists to make it true and to prove it.

## Data

Self-contained. Three realistic reference architectures ship as fixtures, with **documented expected STRIDE deltas** for 25 mutations - so the rule engine is verifiable rather than merely opinionated.

> No paid API key is required to run or demo this project. Where a paid
> service would add value it is wired as an optional enhancement behind an
> interface with an offline mock as the default implementation.

## Stack

- TypeScript
- YAML + Zod for the architecture schema
- Mermaid for generated data-flow diagrams
- Node CLI + GitHub Action, Vitest

## Core capabilities

- Architecture-as-code schema: components, flows, data classifications, trust boundaries
- STRIDE rule engine deriving applicable threats per flow and per boundary crossing
- Diff engine producing added / removed / changed threats between two model versions
- Mitigation registry - an unmitigated new threat fails the gate with a named owner
- Auto-generated data-flow diagram rendered directly in the PR comment

## Repository layout

```
src/model/
src/stride/
src/diff/
fixtures/
test/
```

## Build plan

1. Design the YAML schema against a real architecture you know well. Schemas designed in the abstract are always wrong.
2. Rule engine, then the diff. The diff is what makes it a gate.
3. Mermaid rendering in the PR comment - this is the artefact a recruiter sees.

## Testing strategy

For each of 25 fixture mutations, assert the **exact** expected threat delta. Assert unmitigated new threats fail the gate, and - equally important - that a mutation with a recorded mitigation does *not* fail, because a gate that fires on everything gets disabled.

Tests assert **correctness**, not merely that the code runs. A green suite on
this repo is a claim about behaviour under adversarial conditions; treat any
test that would pass against a deliberately broken implementation as a bug in
the test.

## Measurable outcome

> Every architecture change arrives at review with its threat delta already computed, and no new trust-boundary crossing merges without a named mitigation owner.

State it in these terms — business units, not technical ones — in your CV
bullet and in the first thirty seconds of describing the project.

## Interview questions this project answers

- **Walk me through STRIDE on this data flow.**
- **How do you keep a threat model current?**
- **What is a trust boundary, exactly?**

## What this deliberately is *not*

- Not an automated security review. It surfaces the questions; humans answer them.


## Run it now

```bash
npm test        # runs the suite; no install step needed
npm run demo    # the 60-second artefact
```

Requires Node 22.6+ (24 recommended). TypeScript runs natively via
type stripping - there is no build step and no `node_modules`.

## Getting started

```bash
git clone <your-fork-url> stridediff
cd stridediff
npm install
npx stridediff diff --base fixtures/v1.yaml --head fixtures/v2.yaml
npx stridediff render fixtures/v2.yaml > dfd.md
npm test
```

Docker is supported but optional — every path above works on a plain
Windows/macOS/Linux laptop without a cloud account.

## Definition of done

- [ ] The differentiator above is implemented, and a test proves it
- [ ] The measurable outcome is produced by a command anyone can run
- [ ] `README` explains the one decision a generic version gets wrong
- [ ] CI runs the full suite on every push and is green on `main`
- [ ] A recruiter can see the headline artefact in under 60 seconds

## Licence

MIT — see [LICENSE](LICENSE).
