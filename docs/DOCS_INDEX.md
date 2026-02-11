# WICAP Assistant Documentation Index

## Primary Sources of Truth
- `ASSISTANT_MISSION.md`: project contract, scope, and hard guardrails.
- `ASSISTANT_ROADMAP.md`: implementation phases and engineering priorities.
- `AGENT_ALIGNMENT.md`: role boundaries, authority hierarchy, and change-control rules.
- `HANDOFF_PLAN.md`: concrete remaining milestones, work slices, and CI gate plan.
- `QUALITY_GATES.md`: enforceable reliability thresholds and release gate checklist.

## Supporting Engineering Documents
- `archive/ARCHITECT_REVIEW.md`: historical architecture audit snapshot.
- `archive/REVIEW_WALKTHROUGH.md`: historical validation walkthrough snapshot.
- `LIVE_CONTROL_RESEARCH.md`: external controller/automation pattern survey mapped to WICAP live control design.

## Documentation Rules
- Update `ASSISTANT_MISSION.md` first when scope/guardrails change.
- Keep `ASSISTANT_ROADMAP.md` aligned with actual implementation status.
- Keep `README.md` aligned with current CLI surface and canonical workflow.
- Avoid duplicating policy text across files; reference the mission/roadmap/alignment chain instead.
