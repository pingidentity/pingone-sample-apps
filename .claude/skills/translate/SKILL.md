---
name: translate
description: Port a PingOne Go sample app to JS, Python, React, and Angular in parallel
---

Translate the Go sample app named in the user's argument (e.g. `/translate p1-oidc-pkce-go`) into all four language variants: JS, Python, React, and Angular.

## How to invoke

The user will call this as `/translate <go-app-directory-name>`, for example:
```
/translate p1-oidc-pkce-go
```

## What you must do

1. **Read the Go source** (`<go-app>/main.go`) and the workspace `CLAUDE.md` translation guide before spawning any agents. Understand the workflow fully.

2. **Derive the target directory names** by replacing the `-go` suffix:
   - `<name>-go` → `<name>-js`
   - `<name>-go` → `<name>-python`
   - `<name>-go` → `<name>-react`
   - `<name>-go` → `<name>-angular`

3. **Spawn all four translation agents in a single message** (parallel). Each agent prompt must be self-contained and include:
   - The full path to the Go `main.go` to port
   - The target directory path
   - An explicit instruction to read `CLAUDE.md` for all conventions (file layout, env vars, step shape, HTML style, language-specific rules)
   - The target language and its specific requirements from CLAUDE.md
   - Which existing reference app to study for structural patterns (e.g. `p1-create-assign-custom-admin-role-js` for the JS agent)

4. **After all four agents complete**, run a validation checklist:
   - `node --check` on each JS/Node file
   - `python3 -m py_compile` on each Python file
   - Verify Angular `angular.json` has `polyfills: ["zone.js"]`
   - Verify Angular `tsconfig.json` does NOT have `outDir`
   - Verify Angular `app.component.ts` uses `@switch`/`@case` (grep for it)
   - Verify `canBeAssignedBy` is present in all backends if the Go source contains it

5. **Report results** — list all four new directories, how to run each, and note any validation failures that need fixing.

## Agent prompt template

Use this as the base for each language agent, filling in the specifics:

```
Port the PingOne Go sample app at /Users/nicocheong/pingidentity/<go-dir>/main.go
to <LANGUAGE> at /Users/nicocheong/pingidentity/<target-dir>/.

Before writing anything:
1. Read the Go source fully.
2. Read /Users/nicocheong/pingidentity/CLAUDE.md — it contains all conventions for
   file layout, env vars, step shape, HTML styling, and language-specific rules.
3. Study /Users/nicocheong/pingidentity/<reference-app>/ for the structural pattern
   to follow for this language.

The port must:
- Match the Go workflow steps exactly (same ordering, titles, detail strings, early-return pattern)
- Follow every rule in the CLAUDE.md section for <LANGUAGE>
- Produce: <list files for this language>
- README must cover: what it does, PingOne config required, how to run, env var table
```

## Reference apps by language

| Language | Reference app to study |
|----------|----------------------|
| JS | `p1-create-assign-custom-admin-role-js` |
| Python | `p1-create-assign-custom-admin-role-python` |
| React | `p1-create-assign-custom-admin-role-react` |
| Angular | `p1-create-assign-custom-admin-role-angular` |

## Important

- Do not translate apps that already have a `-js`, `-python`, `-react`, or `-angular` counterpart unless the user explicitly asks for a re-port.
- If the Go app is a management-API-only workflow (no end-user login), the React/Angular backends do not need session/cookie handling — just `POST /api/run` returning `{ success, steps[] }`.
- If the Go app is a user-facing flow (registration, MFA, OIDC), the React/Angular backends need session management (`cookie-parser`, `sid` cookie, session store).
