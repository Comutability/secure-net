# How Secure Net is governed

**Status: draft proposal. Not yet ratified.** It takes effect only when the authorised human
decision-maker's approval is recorded in Comutability's decision register. Merging this file, or
a comment on it, is not ratification by itself. Until then it describes how we intend to work.

It sits under the Founding Charter v1.1 and the organisational proposal ORG-001 (community-led
organisation, human-controlled operations). Where it disagrees with either, they win.

Secure Net is a protocol other people build on, so changes to it follow their own process,
separate from any application's release process. Commonveil and Veil Social are users of the
protocol like anyone else: their teams can propose changes, and can be turned down.

## Changing the protocol: Secure Net Improvement Proposals (SNIPs)

Any change to what two implementations must agree on (a specification in `spec/`, a wire format,
an algorithm, a rule for accepting or refusing something) goes through a numbered proposal in
[`snips/`](snips/).

1. **A public proposal** describes the problem and the intended solution
   ([template](snips/SNIP-TEMPLATE.md)). Anyone may write one.
2. **Maintainers and independent developers examine it** for security and for compatibility
   with existing sites and applications. Discussion happens in the open, on the pull request.
3. **A reference implementation and tests** demonstrate the change. A proposal without them
   can be discussed but not accepted.
4. **The Technical Steering Committee records a decision**: accepted or rejected, with reasons,
   in the proposal itself.
5. **It becomes part of a versioned specification only after the required review.** Until
   then, code for it is marked experimental and must not be the only option between sites.

**Breaking changes** (anything an up-to-date site and a site one version behind would disagree
about) need a higher approval threshold and a **published migration plan**: who has to update,
by when, what happens to those who haven't, and how to go back.

Changes to security-sensitive parts (cryptography, key handling, signatures, federation
checks) also need review by a qualified human security reviewer, whatever else has approved
them.

## Who decides

- **The Technical Steering Committee (TSC)** decides on SNIPs. It starts as the founding
  maintainer and grows to include independent contributors. It can reject changes proposed by
  Comutability's own product teams.
- **Thresholds.** While the TSC has one member, that member decides, and says so in the record.
  Voting eligibility, quorum and the exact thresholds are for a separately approved governance
  policy to set, not this file. As a starting suggestion for that policy: from three members, a
  majority to accept; two thirds, and no unresolved objection from a security reviewer, for a
  breaking change.
- **Conflicts of interest.** A member with a material interest in a proposal says so, and
  doesn't decide it alone.
- **AI can prepare proposals, write implementations and tests, and review. It cannot be a
  voting member of the committee**, and its approval never stands in for a human's. An AI
  doesn't approve its own security-sensitive changes, merge protected changes or publish
  releases without the required human authorisation, or give itself more access. Work an AI
  prepared says so, and has a named human responsible for it.

## Accountability

Governance combines maintainer expertise with community representation. Contributors have
routes to:

- **challenge a decision**: open an appeal on the proposal; the TSC must answer in writing, and
  a rejected appeal can be taken to the Community Council once there is one;
- **remove ineffective representatives**: a recall can be proposed by contributors and is
  decided by the body that elected or appointed them;
- **propose leadership changes**, by the same proposal process as anything else.

Comutability starts with **founder stewardship** and moves towards **elections** as a genuine
contributor community emerges. The steps, and what counts as "emerged", are for the Founding
Charter and its supplementary decisions to set, not for this file.

## Releases

Versions follow semantic versioning. A release notes which SNIPs it contains and the status of
each. Applications that keep a copy (Commonveil's `packages/secure-net`) check it against
`secure-net.manifest.json`.
