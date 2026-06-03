/**
 * app.component.ts — Angular UI shell for the PingOne DaVinci Sign-On demo.
 *
 * All PingOne API calls are handled by the Express backend (server/index.js).
 * This standalone component collects username + password, POSTs to /api/run
 * via Angular's HttpClient, and renders the three-step results returned as JSON.
 *
 * Three render stages controlled by the `stage` property:
 *   idle    — shows the login form with username + password inputs.
 *   loading — shows a "Signing in…" message while the backend drives the flow.
 *   results — renders step cards using @for and the success/failure banner.
 *
 * The template uses Angular 18 built-in control flow (@switch / @case / @for /
 * @if) instead of *ngIf / *ngFor directives, which require CommonModule.
 * FormsModule is imported to enable [(ngModel)] two-way binding on form inputs.
 */
import { Component, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { firstValueFrom } from 'rxjs';

type Stage = 'idle' | 'loading' | 'results';

/** Matches the step object shape returned by the Express backend. */
interface StepResult {
  title: string;
  ok: boolean;
  detail: string;
  body: string;       // pretty-printed JSON response body, or empty string
  url: string;        // "METHOD https://full/url", or empty string
  collapsed: boolean; // if true, the response <details> starts closed
}

/** Top-level shape returned by POST /api/run. */
interface WorkflowResponse {
  success: boolean;
  steps: StepResult[];
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div>
      <header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
        <img src="/logo.png" style="height:35px;width:auto;" alt="Ping Identity">
      </header>
      <div style="padding:32px 40px;max-width:900px;margin:0 auto;">
        <h2 style="margin-top:0;">DaVinci Sign-On Flow with PingOne Auth</h2>
        <p style="color:#555;margin-bottom:24px;">
          Sign in with credentials. The PingOne authorize endpoint hands the request to the
          assigned DaVinci flow policy; this app drives the flow to completion and exchanges
          the resulting code for a token.
        </p>

        @switch (stage) {
          @case ('idle') {
            <form (ngSubmit)="runWorkflow()" #loginForm="ngForm">
              <label style="font-size:14px;font-weight:600;">Username:</label><br>
              <input
                type="text"
                [(ngModel)]="username"
                name="username"
                required
                style="font-size:15px;padding:6px 8px;min-width:280px;margin-top:4px;"><br><br>
              <label style="font-size:14px;font-weight:600;">Password:</label><br>
              <input
                type="password"
                [(ngModel)]="password"
                name="password"
                required
                style="font-size:15px;padding:6px 8px;min-width:280px;margin-top:4px;"><br><br>
              <button
                type="submit"
                style="font-size:16px;padding:10px 24px;cursor:pointer;background:#E1003B;color:#fff;border:none;border-radius:4px;">
                Sign On
              </button>
            </form>
          }

          @case ('loading') {
            <div style="display:flex;align-items:center;gap:12px;color:#444;">
              <div style="
                width:22px;height:22px;
                border:3px solid #ccc;
                border-top-color:#E1003B;
                border-radius:50%;
                animation:spin 0.8s linear infinite;">
              </div>
              <span>Signing in&hellip;</span>
            </div>
            <style>
              @keyframes spin { to { transform: rotate(360deg); } }
            </style>
          }

          @case ('results') {
            @if (response) {
              <div style="
                padding:10px 14px;
                margin-bottom:20px;
                border-radius:4px;
                font-weight:600;
                background:{{ response.success ? '#e6f7e6' : '#fde8ea' }};
                color:{{ response.success ? '#0a7a0a' : '#b00020' }};">
                {{ response.success ? 'Sign-on completed successfully.' : 'Sign-on failed.' }}
              </div>

              @for (step of response.steps; track step.title) {
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

                  @if (step.detail) {
                    <p style="margin:6px 0 0 0;font-size:14px;color:#333;">{{ step.detail }}</p>
                  }

                  @if (step.body) {
                    <details [attr.open]="step.collapsed ? null : ''" style="margin-top:8px;">
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

              <div style="margin-top:24px;">
                <button
                  (click)="reset()"
                  style="font-size:14px;padding:8px 18px;cursor:pointer;border:1px solid #aaa;border-radius:4px;background:#f5f5f5;">
                  Sign In Again
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
  // HttpClient is provided via provideHttpClient(withFetch()) in main.ts.
  // inject() is the Angular 18 idiomatic approach for standalone components.
  private http = inject(HttpClient);

  stage: Stage = 'idle';
  response: WorkflowResponse | null = null;
  username = '';
  password = '';

  /**
   * Trigger the server-side DaVinci sign-on flow via POST /api/run.
   * The Angular dev-server proxy (proxy.conf.json) forwards /api/* to the
   * Express backend on port 3000, so no CORS configuration is needed in
   * development.
   * firstValueFrom converts the Observable returned by HttpClient.post into a
   * Promise, enabling straightforward async/await error handling.
   */
  async runWorkflow() {
    this.stage = 'loading';
    this.response = null;
    try {
      this.response = await firstValueFrom(
        this.http.post<WorkflowResponse>('/api/run', {
          username: this.username,
          password: this.password,
        })
      );
      this.stage = 'results';
    } catch (err: unknown) {
      // HttpClient wraps HTTP errors in an HttpErrorResponse; the actual message
      // may be in err.error.message (server JSON body) or err.message (network).
      const message =
        (err as { error?: { message?: string }; message?: string })?.error?.message ??
        (err as { message?: string })?.message ??
        'Request failed';
      this.response = {
        success: false,
        steps: [{
          title: 'Request failed',
          ok: false,
          detail: message,
          body: '',
          url: '',
          collapsed: false,
        }],
      };
      this.stage = 'results';
    }
  }

  /** Reset to the idle stage so the user can sign in again. */
  reset() {
    this.stage = 'idle';
    this.response = null;
    this.username = '';
    this.password = '';
  }
}
