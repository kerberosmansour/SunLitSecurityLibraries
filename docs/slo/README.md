# `docs/slo/` - runbooks and milestone artifacts

Everything under this directory is work/task information produced by the
SunLitOrchestrate `/slo-*` flow: runbooks, milestone outputs, research dossiers,
lessons, completion summaries, and critique notes. Product and developer
documentation stays one level up under `docs/`.

## Layout

| Path | What lives here |
|---|---|
| [`current/`](current/) | Runbooks for work currently in progress. |
| [`completed/`](completed/) | Runbooks whose milestones are closed. |
| [`future/`](future/) | Runbooks queued but not started. |
| [`templates/`](templates/) | Runbook templates and supporting reference templates. |
| [`idea/`](idea/) | `/slo-ideate` outputs. |
| [`research/`](research/) | `/slo-research` dossiers and supporting analysis. |
| [`design/`](design/) | `/slo-architect` outputs. |
| [`critique/`](critique/) | `/slo-critique` adversarial reviews. |
| [`completion/`](completion/) | Per-milestone completion summaries. |
| [`lessons/`](lessons/) | Per-milestone lessons learned. |
| [`verify/`](verify/) | `/slo-verify` smoke, runtime QA, and evidence reports. |

## Runbook lifecycle

```text
future/  ->  current/  ->  completed/
   ^           |             |
   |           |             |
idea/      plan +         retro M_last
research/  execute +      moves it here
design/    verify
critique/
```

A runbook moves between `future/`, `current/`, and `completed/` based on its
Milestone Tracker. Supporting artifacts stay in their own flat directories and
are indexed by slug or milestone name.
