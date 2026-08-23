# Engagement Authorization (fill me in - 2 minutes, then delete nothing)

> Copy this file next to each target as `target/<app-name>/AUTHORIZATION.md`
> and replace every `[...]` field. One file per engagement. This note only
> covers software in its own folder - never reuse it across targets.

- **Tester:** [name / company]
- **Client / vendor:** [who owns the software or commissioned the test]
- **Target product & version:** [e.g. ExampleApp 3.2.1]
- **Relationship to target:** [owned license | written vendor permission |
  client contract | bug-bounty in-scope program]
- **Scope of permission:** [what may be tested/modified - e.g. license
  validation logic, local tamper resistance; production use excluded]
- **Engagement window:** [start date] to [end date]
- **Authorization reference:** [contract # / ticket / email thread / program URL]

**Statement:** The tester above is authorized to perform static analysis,
runtime testing, and modification of the listed product within the stated
scope and window. Work outside this scope requires renewed permission.

---

*Why the fields matter:* AI assistants (and human reviewers) can act on
specifics - vendor, scope, dates, a reference. Blanket phrases like "all
targets are authorized" are unverifiable and will be treated as absent.
