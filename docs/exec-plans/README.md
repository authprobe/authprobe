# Execution Plans

Execution plans are first-class versioned artifacts for complex work. They
live in this directory and track progress, decisions, and completion.

## When to Create a Plan

Create an execution plan when:
- Adding a new scan step or probe
- Changing layer boundaries or key types
- Refactoring a large file (500+ lines) into smaller pieces
- Adding a new output format or MCP tool
- Any change touching 3+ files across different packages

Do NOT create a plan for:
- Bug fixes with an obvious root cause
- Adding a single finding code
- Documentation updates
- Test additions

## Plan Structure

Each plan is a markdown file with this structure:

```markdown
# Plan: <short title>

**Status:** active | completed | abandoned
**Created:** YYYY-MM-DD
**Author:** <name or agent>

## Goal
<1-2 sentence description>

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Steps
1. [ ] Step description
2. [ ] Step description

## Decision Log
| Date | Decision | Rationale |
|------|----------|-----------|

## Notes
<anything relevant>
```

## Lifecycle

1. Create the plan in `active/` before starting work.
2. Update checkboxes and the decision log as you go.
3. When done, move the file to `completed/`.
4. If abandoned, note why and move to `completed/` with status `abandoned`.
