# Using SunLit Security Libraries with coding agents

Use the [sunlit-rust-security skill](../../skills/sunlit-rust-security/SKILL.md) to choose and integrate a
published package. Its [bundled usage reference](../../skills/sunlit-rust-security/references/usage.md)
is the canonical task-to-package map, with registry links and versioned examples.
The reference currently targets **0.4.0**. Check a newer release before changing
versions; repository main may contain unfinished work.

## Install without an installer

Review `SKILL.md` and its `references/usage.md` from a trusted checkout at a reviewed
commit. Record that commit with `git rev-parse HEAD`. Copy just the skill directory
into the consumer project's `.agents/skills/` for Codex, or `.claude/skills/` for
Claude Code. Replace `/path/to/reviewed/rust` below with your reviewed checkout.
The guard avoids overwriting an existing skill:

```sh
mkdir -p .agents/skills
test ! -e .agents/skills/sunlit-rust-security &&
  cp -R /path/to/reviewed/rust/skills/sunlit-rust-security .agents/skills/sunlit-rust-security
```

For Claude Code, use `.claude/skills` in both places. Follow your host's skill
installation documentation for other agents. This copies Markdown only: it does
not install dependencies, run hooks, change global configuration, or start a model.
Keep the skill and bundled reference together when updating them.

Invoke `$sunlit-rust-security` in Codex or `/sunlit-rust-security` in Claude Code. A supported agent can also
select an installed skill from its description. Installation does not guarantee
selection; inspect your host's trace or explain which skill should be used.

## Example requests

- “Use SunLit crates to add deny-by-default authorization to this Rust service; test a cross-tenant denial.”
- “Use secure_data to encrypt application state; distinguish the local test provider from the production key provider.”

## Optional consumer instructions

If this fits your project, add the following sentence to your **existing**
`AGENTS.md`, `CLAUDE.md` or Copilot instructions after reviewing it. Do not replace
those files:

> For relevant Rust security tasks, consult the installed
> `sunlit-rust-security` skill, check the published version, and follow this project's
> dependency-admission and deployment rules. Preserve user choice and report gaps.

Instructions in this library's own AGENTS.md do not automatically apply to consumer
projects. The skill is portable and does not depend on the library checkout being
available after installation.

## Discovery and documentation

`context7.json` selects the curated consumer guide and bundled usage reference.
Internal plans, maintainer analytics and root README summaries of unreleased work
are excluded. `llms.txt` is an additional index for tools that support it; it does
not guarantee discovery by every agent. Maintainers must submit/refresh the public
repository in Context7 after these files land; presence of a config is not proof
of indexing. Skills.sh counts installs made through its tooling, so manual copying
will not necessarily appear there. Never manufacture installs to improve rankings.

## Tell us what worked

Feedback is optional. Share success and general usage in [Discussions](https://github.com/kerberosmansour/SunLitSecurityLibraries/discussions).
Use an [integration report](https://github.com/kerberosmansour/SunLitSecurityLibraries/issues/new?template=integration_feedback.yml)
for a concrete blocker or documentation gap. Search existing issues first.
Follow the [feedback policy and local draft helper](feedback.md); it records exact
versions/features, actual checks, consulted docs and duplicate evidence. The
[sunlit-upstream-feedback skill](../../skills/sunlit-upstream-feedback/SKILL.md)
can be installed by the same reviewed-copy procedure above. Its bundled Python
script is optional and never sends data or executes reproduction commands.

Reports are public and associated with the submitting account. An agent must
obtain operator authorization before posting. Suspected vulnerabilities go to
[private reports](https://github.com/kerberosmansour/SunLitSecurityLibraries/security/advisories/new).
No library telemetry or automatic reporting is added.

See [task contracts](tasks.md), [evaluation protocol](evaluation.md),
[adoption measurement](adoption-measurement.md), and [distribution readiness](distribution.md).
