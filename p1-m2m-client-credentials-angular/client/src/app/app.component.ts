// app.component.ts — Angular UI for the M2M Client Credentials + PingOne Protect demo.
//
// This component is a thin display shell. All PingOne protocol logic lives in
// the Express backend (server/index.js). The frontend's only job is to:
//   1. Present a "Run Flow" button.
//   2. POST to /api/run (no body needed — the server uses its own credentials).
//   3. Receive { success, steps[] } and render each step as a card.
//
// /api/run response shape:
//   {
//     success: boolean,       // true if all non-divider steps passed
//     steps:   Step[]         // ordered list of workflow steps
//   }
//
// Step shape:
//   {
//     title:     string,      // displayed as the card heading
//     ok:        boolean,     // green (ok) or red (failed) heading
//     detail:    string,      // explanation text; may contain \n but no HTML
//     body:      string,      // pretty-printed JSON response (may be empty)
//     url:       string,      // "METHOD https://..." shown as monospace badge
//     collapsed: boolean,     // if true, <details> starts closed
//     divider?:  boolean      // if true, render as a section separator
//   }
//
// UI stages:
//   idle     — landing page with description and "Run Flow" button.
//   loading  — spinner shown while POST /api/run is in flight.
//   results  — step cards plus a "Run Again" button.

import { Component, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

// Stage drives the @switch control flow in the template.
type Stage = 'idle' | 'loading' | 'results';

// Step mirrors the shape of each element in the steps array returned by
// POST /api/run. The divider flag is optional — when true, the step renders
// as a dark-red section header rather than a regular result card.
interface Step {
  title: string;
  ok: boolean;
  detail: string;
  body: string;
  url: string;
  collapsed: boolean;
  divider?: boolean;
}

// WorkflowResponse is the full shape returned by POST /api/run.
interface WorkflowResponse {
  success: boolean;
  steps: Step[];
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [],   // HttpClient is provided via inject() + app.config.ts — no module import needed.
  template: `
    <div>
      <!-- Branded header bar shown on every stage. -->
      <header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
        <img [src]="logoSrc" style="height:35px;width:auto;" alt="Ping Identity">
      </header>

      <div style="padding:32px 40px;max-width:980px;margin:0 auto;">

        @switch (stage) {

          <!-- ── idle: landing page ───────────────────────────────────────── -->
          @case ('idle') {
            <h2 style="margin-top:0;">OAuth 2.0 Client Credentials (M2M) + PingOne Protect</h2>
            <p>
              This sample walks through the OAuth 2.0 <strong>client_credentials</strong> grant. There is no user,
              no browser redirect, and no PKCE. The client authenticates directly with the PingOne token endpoint
              using its own credentials, receives an access token, and calls <strong>PingOne Protect</strong> for
              two risk evaluations:
            </p>
            <ul>
              <li><strong>User A — trusted:</strong> real client IP, <code>type=EXTERNAL</code> — expected to score LOW or MEDIUM, API call proceeds.</li>
              <li><strong>User B — suspicious:</strong> Tor exit node IP (<code>185.220.101.1</code>), <code>type=ANONYMOUS</code> — expected to score HIGH via Anonymous Network Detection, API call blocked.</li>
            </ul>
            <p>
              Both paths are rendered side-by-side so you can compare what PingOne Protect returns and see how
              the application gates the downstream call differently in each case.
            </p>
            <!-- Clicking this button calls runWorkflow() which posts to /api/run. -->
            <button
              (click)="runWorkflow()"
              style="font-size:16px;padding:10px 20px;cursor:pointer;background:#E1003B;color:#fff;border:none;border-radius:4px;">
              Run Flow
            </button>
            <p style="color:#666;font-size:13px;margin-top:30px;">
              PingOne config required: Worker application with Token Endpoint Auth Method = Client Secret Basic.
              The Worker app must have roles for Identity Data (read) and PingOne Protect (risk evaluation).
              A Protect risk policy set must exist with Anonymous Network Detection enabled and scored above
              the HIGH threshold; its ID goes in <code>PINGONE_RISK_POLICY_SET_ID</code>.
            </p>
          }

          <!-- ── loading: shown while the server runs the workflow ────────── -->
          @case ('loading') {
            <div style="display:flex;align-items:center;gap:12px;color:#444;">
              <!-- CSS spinner — no external dependency needed. -->
              <div style="
                width:22px;height:22px;
                border:3px solid #ccc;
                border-top-color:#E1003B;
                border-radius:50%;
                animation:spin 0.8s linear infinite;">
              </div>
              <span>Running workflow&hellip;</span>
            </div>
            <style>
              @keyframes spin { to { transform: rotate(360deg); } }
            </style>
          }

          <!-- ── results: render step cards returned by /api/run ──────────── -->
          @case ('results') {
            @if (response) {
              @for (step of response.steps; track $index) {

                <!-- Dividers (step.divider=true) are section headers, not cards.
                     They visually separate the "User A" and "User B" blocks. -->
                @if (step.divider) {
                  <div style="
                    margin-top:30px;
                    margin-bottom:4px;
                    padding:8px 14px;
                    background:#B8002F;
                    color:#fff;
                    border-radius:4px;
                    font-weight:600;
                    font-size:15px;">
                    {{ step.title }}
                  </div>
                } @else {
                  <!-- Regular result card: heading color reflects ok/failed status. -->
                  <div style="
                    margin-top:16px;
                    border:1px solid #ddd;
                    border-radius:6px;
                    padding:14px 16px;
                    background:#fff;">

                    <h3 style="
                      margin:0 0 8px 0;
                      font-size:15px;
                      color:{{ step.ok ? '#0a7a0a' : '#b00020' }};">
                      {{ step.title }}&nbsp;{{ step.ok ? '(ok)' : '(failed)' }}
                    </h3>

                    <!-- URL badge: monospace pill showing "METHOD url". -->
                    @if (step.url) {
                      <div style="
                        font-family:monospace;
                        font-size:12px;
                        color:#555;
                        background:#f0f0f0;
                        padding:4px 8px;
                        border-radius:3px;
                        display:inline-block;
                        margin-bottom:8px;
                        word-break:break-all;">
                        {{ step.url }}
                      </div>
                    }

                    <!-- Detail text: plain text, line breaks preserved via pre-wrap. -->
                    @if (step.detail) {
                      <p style="margin:6px 0 0 0;font-size:14px;color:#333;white-space:pre-wrap;">{{ step.detail }}</p>
                    }

                    <!-- Response body: collapsible <details>. collapsed=true means
                         the <details> starts closed; used on verbose responses like
                         the JWKS to keep the page readable without hiding the data. -->
                    @if (step.body) {
                      <details [attr.open]="!step.collapsed ? '' : null" style="margin-top:8px;">
                        <summary style="cursor:pointer;font-size:13px;color:#444;user-select:none;padding:2px 0;">
                          Response
                        </summary>
                        <pre style="
                          background:#f4f4f4;
                          padding:12px;
                          border-left:3px solid #888;
                          white-space:pre-wrap;
                          word-wrap:break-word;
                          margin:6px 0 0 0;
                          font-size:12px;
                          border-radius:0 4px 4px 0;">{{ step.body }}</pre>
                      </details>
                    }
                  </div>
                }
              }

              <div style="margin-top:24px;">
                <!-- "Run Again" resets state to idle, clearing the previous results. -->
                <button
                  (click)="reset()"
                  style="font-size:14px;padding:8px 18px;cursor:pointer;border:1px solid #aaa;border-radius:4px;background:#f5f5f5;">
                  Run Again
                </button>
              </div>
            }
          }

        }
      </div>
    </div>
  `,
})
export class AppComponent {
  // HttpClient is injected via Angular's inject() function rather than through
  // a constructor parameter. HttpClient must be provided in app.config.ts via
  // provideHttpClient(withFetch()) — the withFetch() adapter makes Angular use
  // the native browser Fetch API instead of XHR, which is required for zone.js
  // compatibility in this standalone component setup.
  private http = inject(HttpClient);

  // logoSrc points to the Ping Identity logo served from Angular's assets/
  // directory. Angular CLI copies files from src/assets/ to the dist output.
  logoSrc = 'assets/logo.png';

  stage: Stage = 'idle';
  response: WorkflowResponse | null = null;

  // runWorkflow posts to /api/run and stores the result for rendering.
  // No body is required — the server uses its own environment variables.
  // The browser never sees PingOne credentials.
  async runWorkflow() {
    this.stage = 'loading';
    this.response = null;
    try {
      // firstValueFrom converts the Observable returned by HttpClient.post to a
      // Promise so we can use async/await. The generic type parameter tells
      // TypeScript the expected shape of the response body.
      this.response = await firstValueFrom(
        this.http.post<WorkflowResponse>('/api/run', {})
      );
      this.stage = 'results';
    } catch (err: unknown) {
      // Network-level errors (server unreachable) or non-2xx responses are
      // caught here and surfaced as a synthetic failed step so the UI remains
      // consistent with the happy-path results layout.
      const message =
        (err as { error?: { message?: string }; message?: string })?.error?.message ??
        (err as { message?: string })?.message ??
        'Request failed';
      this.response = {
        success: false,
        steps: [{ title: 'Request failed', ok: false, detail: message, body: '', url: '', collapsed: false }],
      };
      this.stage = 'results';
    }
  }

  // reset clears the previous run result and returns to the idle landing page.
  reset() {
    this.stage = 'idle';
    this.response = null;
  }
}
