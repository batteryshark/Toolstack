# Coding Standards

Use this project-specific summary instead of keeping a large external clean-code
reference in the active workspace.

## Priorities

- Readability first.
- Minimal code.
- One component at a time.
- One responsibility per module.
- Small public interfaces.
- Explicit names over shorthand.
- Boring control flow over clever abstraction.

## Python Rules

- Use descriptive names.
- Keep functions small and focused.
- Avoid functions with more than three arguments; introduce a small data object when needed.
- Avoid boolean flag arguments; split behavior into separate functions.
- Return values instead of mutating arguments as hidden output.
- Delete dead code immediately.
- Avoid redundant comments.
- Use comments only to explain non-obvious intent or constraints.
- Keep dependencies physical and obvious through imports.
- Keep configuration at component boundaries, not scattered through inner logic.
- Use type hints on public component boundaries.

## Test Rules

- Tests should be fast and deterministic.
- Test component boundaries and behavior, not implementation trivia.
- Each test should prove one idea.
- Add boundary tests where bugs are likely: missing resources, denied access,
  expired state, unavailable dependency, malformed input.
- Do not keep skipped tests unless the reason is concrete and still useful.

## Documentation Rules

- Docs should explain current decisions, not preserve every past branch.
- Prefer short restart-friendly docs over long historical essays.
- Keep stale diagrams, scratch plans, and external reference dumps out of the active workspace.
