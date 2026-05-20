# PingOne Sample Apps — CLAUDE.md

This workspace contains PingOne integration sample apps in multiple languages. Each app demonstrates a specific workflow against the PingOne API.

---

## Repository layout

Each app is a self-contained directory:

```
p1-<workflow>-go/        ← canonical Go implementation
p1-<workflow>-js/        ← Node.js/Express single-file port
p1-<workflow>-python/    ← Python/Flask single-file port
p1-<workflow>-react/     ← React (Vite) + Node/Express
p1-<workflow>-angular/   ← Angular 18 + Node/Express
```

The **Go app is always the canonical source of truth.** All other language ports must match its workflow steps exactly: same ordering, same step titles, same early-return-on-error pattern, same detail strings.

---

## Postman collections

Before designing a new sample app, consult `POSTMAN_COLLECTIONS.md` in this directory (gitignored, local only). It lists all available collections and their paths under `/Users/nicocheong/docs/forks/devdocs-pingone/resources/`. Read the relevant collection JSON to get authoritative request shapes, URL templates, and required parameters for the workflow you're implementing.

---

## Translating a Go app to other languages

When given a Go app to port, read its `main.go` fully before writing anything. Then apply the rules below for each target language.

### Shared conventions (all languages)

#### Environment variables
- Load from `.env` at startup (dotenv / python-dotenv / godotenv).
- Exit with a clear error message if any required var is missing.
- `.env.example` must list every var with empty values and a comment about regional auth paths.

#### Step result shape
Every workflow step produces a result object/struct with these fields:
```
title     string   — human-readable step name
ok        bool     — true = success, false = failure
detail    string   — one-line summary (e.g. "HTTP 201 — id=abc123")
body      string   — pretty-printed JSON response body (may be empty)
url       string   — "METHOD https://full/url" (may be empty for derived steps)
collapsed bool     — if true, the response <details> starts closed
```

The **"List platform roles"** step always sets `collapsed: true` because the response is long. All other steps default to `collapsed: false`.

#### Results page HTML
All apps render results as cards using this CSS palette:
- OK color: `#0a7a0a`
- Error color: `#b00020`
- Success banner background: `#e6f7e6`
- Error banner background: `#fde8ea`
- URL badge: monospace, `color:#555`, `background:#f0f0f0`, `padding:4px 8px`, `border-radius:3px`
- Response body: `<details open>` / `<details>` (collapsed) wrapping `<pre>` with `background:#f4f4f4`, `border-left:3px solid #888`

#### API helper pattern
Every language implements a generic `apiCall(method, path, token, payload)` helper that:
1. Builds `fullURL = apiPath + path`
2. Sets `Authorization: Bearer <token>`, `Accept: application/json`, `Content-Type: application/json` (when payload present)
3. Returns `(fullURL, statusCode, rawBody, parsedJSON)`

Token acquisition uses `client_credentials` grant with HTTP Basic auth (`base64(clientID:clientSecret)`).

---

### Go

- Single `main.go`, `go.mod`, `go.sum`, `.env.example`, `README.md`
- Uses `html/template` for auto-escaping
- `stepResult` struct with `Title`, `OK`, `Detail`, `Body`, `URL`, `Collapsed` fields
- `apiCall` returns `(string, int, []byte, map[string]interface{}, error)`

### Node.js / Express (JS)

- Single `index.js`, `package.json`, `.env.example`, `README.md`
- `require('dotenv').config()` at top; validate env vars with `process.exit(1)`
- Uses Node 18+ global `fetch` — **no `node-fetch` dependency**
- HTML built with template literals; `escapeHTML()` helper for all user-supplied values inserted into HTML
- `apiCall` is `async`, returns `{ fullURL, status, rawText, parsed }`
- `package.json` scripts: `"start": "node index.js"`; engine `"node": ">=18"`
- Dependencies: `express`, `dotenv` only

### Python / Flask

- Single `app.py`, `requirements.txt`, `.env.example`, `README.md`
- `load_dotenv()` at top; `raise SystemExit(...)` on missing vars
- Uses `requests` for HTTP; `html.escape()` for all user values inserted into HTML
- `StepResult` is a `@dataclass` mirroring the field list above
- `api_call(method, path, token, payload=None)` returns `(full_url, status_code, raw_bytes, parsed_dict)`
- `app.run(host="0.0.0.0", port=3000, debug=False)`
- `requirements.txt`: `flask`, `requests`, `python-dotenv`
- README run instructions: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && python app.py`

### React (Vite + Node/Express backend)

Directory layout:
```
p1-<workflow>-react/
  README.md
  server/
    index.js          ← Express backend, port 3000
    package.json      ← deps: express, dotenv
    .env.example
  client/
    package.json      ← deps: react, react-dom; devDeps: vite, @vitejs/plugin-react
    vite.config.js    ← port 5173, proxy /api → http://localhost:3000
    index.html
    src/
      main.jsx        ← createRoot mount
      App.jsx         ← all UI logic
```

**Backend** (`server/index.js`):
- Same pattern as JS single-file, but exposes `POST /api/run` returning JSON `{ success, steps[] }`
- Also serves the built React dist in production: `app.use(express.static(path.join(__dirname, '../client/dist')))`

**Frontend** (`client/src/App.jsx`):
- Three stages: `idle` → `loading` → `results`
- `StepCard` component renders a card with URL badge, detail, and `<details open={!step.collapsed}>`
- All styles as inline JS objects (no separate CSS file)
- `fetch('/api/run', { method: 'POST' })` — no credentials/body needed for workflow runners
- "Run Again" button resets to `idle`

**`vite.config.js`**:
```js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': 'http://localhost:3000' } },
});
```

### Angular 18 + Node/Express backend

Directory layout:
```
p1-<workflow>-angular/
  README.md
  server/
    index.js          ← same as React backend
    package.json
    .env.example
  client/
    angular.json
    package.json
    proxy.conf.json   ← { "/api": { "target": "http://localhost:3000", "secure": false, "changeOrigin": true } }
    tsconfig.json     ← NO outDir here
    tsconfig.app.json ← outDir goes here
    src/
      index.html
      main.ts         ← bootstrapApplication with provideHttpClient()
      app/
        app.component.ts   ← standalone component, all logic here
        app.config.ts      ← ApplicationConfig with provideHttpClient(withFetch())
```

**Critical Angular 18 requirements** (these are the ones that break most often):
1. **`polyfills: ["zone.js"]`** must be in `angular.json` build options — without it the page is blank
2. **`outDir` must NOT be in `tsconfig.json`** root — only in `tsconfig.app.json`
3. **Use `@switch`/`@case` built-in control flow** — NOT `*ngSwitchCase` (requires CommonModule which is not imported)
4. **Standalone components** — `standalone: true`, no NgModule
5. **`HttpClient`** injected via `inject(HttpClient)`, provided via `provideHttpClient(withFetch())` in `app.config.ts`

**`app.component.ts` pattern**:
```typescript
@Component({
  selector: 'app-root',
  standalone: true,
  imports: [],          // HttpClientModule NOT needed when using inject(HttpClient)
  template: `
    @switch (stage) {
      @case ('idle')    { ... }
      @case ('loading') { ... }
      @case ('results') { ... }
    }
  `
})
export class AppComponent {
  private http = inject(HttpClient);
  stage: Stage = 'idle';
  response: WorkflowResponse | null = null;

  async runWorkflow() {
    this.stage = 'loading';
    try {
      this.response = await firstValueFrom(this.http.post<WorkflowResponse>('/api/run', {}));
      this.stage = 'results';
    } catch (err: any) {
      this.response = { success: false, steps: [{ title: 'Network error', ok: false, detail: err.message, body: '', url: '', collapsed: false }] };
      this.stage = 'results';
    }
  }

  reset() { this.stage = 'idle'; this.response = null; }
}
```

**`package.json` start script**:
```json
"start": "ng serve --proxy-config proxy.conf.json --port 4200"
```

**`angular.json` build options** (minimum required):
```json
{
  "outputPath": "dist/<project-name>",
  "index": "src/index.html",
  "browser": "src/main.ts",
  "polyfills": ["zone.js"],
  "tsConfig": "tsconfig.app.json"
}
```

---

## README conventions

Every app's README must include:

1. **What it does** — bullet list of the workflow steps
2. **PingOne configuration** — app type, grant types, redirect URIs, required roles, env settings (MFA policy, populations, etc.)
3. **Run instructions** — exact commands to start the app
4. **Environment variables table** — var name + purpose

For apps that require an admin worker app, always note which role is required and why (e.g. "Organization Admin — required because `canBeAssignedBy` must reference a role held by the assigning actor").

---

## Two-app pattern (MFA / admin workflows)

Some workflows require two PingOne applications:
1. **End-user OIDC app** — what users authenticate against
2. **Admin worker app** — used to obtain a management API bearer token

When this pattern is needed, the env vars are prefixed:
- `PINGONE_ENV_ID` / `PINGONE_CLIENT_ID` / `PINGONE_CLIENT_SECRET` — end-user app
- `PINGONE_ADMIN_ENV_ID` / `PINGONE_ADMIN_CLIENT_ID` / `PINGONE_ADMIN_CLIENT_SECRET` — worker app

Workflows that only need a management API (no end-user login) use only the `PINGONE_ADMIN_*` vars plus `PINGONE_TARGET_ENV_ID`.

---

## Known PingOne API nuances

These are the details that are easy to get wrong:

- **`/flows/{id}` calls require `Accept: */*`** (not `application/json`) — vendor content types like `application/vnd.pingidentity.*+json` will 406 otherwise
- **Flow API requires bearer token** — session cookies alone are insufficient; the admin worker app token must be sent on every `/flows/{id}` call
- **Cookie path scoping** — PingOne session cookies (`ST`, `ST-NO-SS`) must be replayed verbatim across requests; RFC 6265 `cookiejar` path scoping silently drops them — capture/replay manually
- **Custom admin role permissions** use `<service>:<action>:<resource>` format (e.g. `applications:read:application`), not `p1:read:application`
- **Custom roles endpoint** is `POST /environments/{envID}/roles` — not `/roles` (read-only) or `/customAdminRoles`
- **`canBeAssignedBy`** must be set on a custom role to allow delegation — even Organization Admin cannot assign the role without it
- **Group role assignment scope** — PingOne has no literal "assign group to population" API; scoping is expressed on the role assignment via `scope.type=POPULATION`
- **PKCE `code_challenge`** must be `base64url-no-pad(SHA-256(verifier))` — `base64url` (not standard base64), with no `=` padding
- **PKCE `code_challenge_method`** must be exactly `S256` (uppercase)
