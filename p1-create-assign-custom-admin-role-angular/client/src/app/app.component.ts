import { Component, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

type Stage = 'idle' | 'loading' | 'results';

interface StepResult {
  title: string;
  ok: boolean;
  detail: string;
  body: string;
  url: string;
  collapsed: boolean;
}

interface WorkflowResponse {
  success: boolean;
  steps: StepResult[];
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [],
  template: `
    <h2 style="margin-top: 0;">Custom Admin Role Workflow</h2>
    <p style="color: #555; margin-bottom: 24px;">
      Creates a trimmed-down application admin role, assigns it to a group scoped to a
      population, registers a user into that population, and verifies the inherited role
      assignment.
    </p>

    @switch (stage) {
      @case ('idle') {
        <button
          (click)="runWorkflow()"
          style="font-size: 16px; padding: 10px 24px; cursor: pointer; background: #1a6bbf; color: #fff; border: none; border-radius: 4px;">
          Run Workflow
        </button>
      }

      @case ('loading') {
        <div style="display: flex; align-items: center; gap: 12px; color: #444;">
          <div style="
            width: 22px; height: 22px;
            border: 3px solid #ccc;
            border-top-color: #1a6bbf;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;">
          </div>
          <span>Running workflow&hellip;</span>
        </div>
        <style>
          @keyframes spin { to { transform: rotate(360deg); } }
        </style>
      }

      @case ('results') {
        @if (response) {
          <div style="
            padding: 10px 14px;
            margin-bottom: 20px;
            border-radius: 4px;
            font-weight: 600;
            background: {{ response.success ? '#e6f7e6' : '#fde8ea' }};
            color: {{ response.success ? '#0a7a0a' : '#b00020' }};">
            {{ response.success ? 'All steps completed successfully.' : 'Workflow halted on error.' }}
          </div>

          @for (step of response.steps; track $index) {
            <div style="
              margin-top: 16px;
              border: 1px solid #ddd;
              border-radius: 6px;
              padding: 14px 16px;
              background: #fff;">

              <h3 style="
                margin: 0 0 8px 0;
                font-size: 15px;
                color: {{ step.ok ? '#0a7a0a' : '#b00020' }};">
                {{ step.title }}&nbsp;{{ step.ok ? '(ok)' : '(failed)' }}
              </h3>

              @if (step.url) {
                <div style="
                  font-family: monospace;
                  font-size: 12px;
                  color: #444;
                  background: #f0f0f0;
                  padding: 4px 8px;
                  border-radius: 3px;
                  display: inline-block;
                  margin-bottom: 8px;
                  word-break: break-all;">
                  {{ step.url }}
                </div>
              }

              @if (step.detail) {
                <p style="margin: 6px 0 0 0; font-size: 14px; color: #333;">{{ step.detail }}</p>
              }

              @if (step.body) {
                <details [open]="!step.collapsed" style="margin-top: 8px;">
                  <summary style="cursor: pointer; font-size: 13px; color: #444; user-select: none; padding: 2px 0;">
                    Response
                  </summary>
                  <pre style="
                    background: #f4f4f4;
                    padding: 12px;
                    border-left: 3px solid #888;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    margin: 6px 0 0 0;
                    font-size: 12px;
                    border-radius: 0 4px 4px 0;">{{ step.body }}</pre>
                </details>
              }
            </div>
          }

          <div style="margin-top: 24px;">
            <button
              (click)="reset()"
              style="font-size: 14px; padding: 8px 18px; cursor: pointer; border: 1px solid #aaa; border-radius: 4px; background: #f5f5f5;">
              Run Again
            </button>
          </div>
        }
      }
    }
  `,
})
export class AppComponent {
  private http = inject(HttpClient);

  stage: Stage = 'idle';
  response: WorkflowResponse | null = null;
  error = '';

  async runWorkflow() {
    this.stage = 'loading';
    this.response = null;
    try {
      this.response = await firstValueFrom(
        this.http.post<WorkflowResponse>('/api/run', {})
      );
      this.stage = 'results';
    } catch (err: unknown) {
      const message = (err as { error?: { message?: string }; message?: string })?.error?.message
        ?? (err as { message?: string })?.message
        ?? 'Request failed';
      this.response = {
        success: false,
        steps: [{ title: 'Request failed', ok: false, detail: message, body: '', url: '', collapsed: false }],
      };
      this.stage = 'results';
    }
  }

  reset() {
    this.stage = 'idle';
    this.response = null;
    this.error = '';
  }
}
