import { Component, OnInit, inject } from '@angular/core';
import { NgIf, NgFor } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

interface Card {
  title: string;
  ok: boolean;
  url?: string | null;
  detail?: string | null;
  body?: string | null;
  collapsed?: boolean;
}

interface PrepareResponse {
  prepareCards: Card[];
  authorizeURL: string;
}

interface CallbackResultResponse {
  prepareCards: Card[];
  callbackCards: Card[];
  hasRefreshToken: boolean;
}

interface RefreshResponse {
  refreshCards: Card[];
}

type Stage =
  | 'start'
  | 'preparing'
  | 'prepared'
  | 'loading-callback'
  | 'callback-done'
  | 'refreshing'
  | 'refresh-done'
  | 'error';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [NgIf, NgFor],
  template: `
    @switch (stage) {

      @case ('start') {
        <div>
          <h2>OIDC Authorization Code + PKCE (confidential client)</h2>
          <p>
            This sample walks through every artifact in the OIDC Authorization Code flow with PKCE
            so you can see exactly what each value is, how it's derived, and how it's validated.
          </p>
          <p>
            The client is <strong>confidential</strong> — the token endpoint is called with HTTP
            Basic auth (client ID + secret) AND the PKCE <code>code_verifier</code>.
          </p>
          <button (click)="beginLogin()">Begin Login</button>
          <p style="color:#666; font-size:13px; margin-top:30px;">
            PingOne config required: OIDC Web App with PKCE Enforcement = REQUIRED,
            Token Endpoint Auth Method = Client Secret Basic,
            redirect URI = http://localhost:3000/callback
          </p>
        </div>
      }

      @case ('preparing') {
        <p>Preparing PKCE artifacts...</p>
      }

      @case ('prepared') {
        <div>
          <h3>Prepare</h3>
          @for (card of prepareCards; track $index) {
            <div style="margin-top: 18px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 4px;">
              <h3 [style.color]="card.ok ? '#0a7a0a' : '#b00020'" style="margin: 0 0 6px 0">
                {{ card.title }} {{ card.ok ? '(ok)' : '(failed)' }}
              </h3>
              @if (card.url) {
                <div style="font-family: monospace; font-size: 13px; color: #555; background: #eef; padding: 4px 8px; border-radius: 3px; margin: 6px 0; word-break: break-all;">
                  {{ card.url }}
                </div>
              }
              @if (card.detail) {
                <div [innerHTML]="card.detail"></div>
              }
              @if (card.body) {
                <details [open]="!card.collapsed" style="margin-top: 6px;">
                  <summary style="cursor: pointer; font-size: 13px; color: #444; user-select: none;">
                    {{ card.collapsed ? 'Show response' : 'Hide' }}
                  </summary>
                  <pre style="background: #f4f4f4; padding: 12px; border-left: 3px solid #888; white-space: pre-wrap; word-break: break-all; margin: 0;">{{ card.body }}</pre>
                </details>
              }
            </div>
          }
          <p style="margin-top: 20px;">
            <button (click)="navigateToPingOne()">Continue to PingOne &#x2192;</button>
          </p>
        </div>
      }

      @case ('loading-callback') {
        <p>Loading callback results...</p>
      }

      @case ('callback-done') {
        <div>
          <h3>Prepare</h3>
          @for (card of prepareCards; track $index) {
            <div style="margin-top: 18px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 4px;">
              <h3 [style.color]="card.ok ? '#0a7a0a' : '#b00020'" style="margin: 0 0 6px 0">
                {{ card.title }} {{ card.ok ? '(ok)' : '(failed)' }}
              </h3>
              @if (card.url) {
                <div style="font-family: monospace; font-size: 13px; color: #555; background: #eef; padding: 4px 8px; border-radius: 3px; margin: 6px 0; word-break: break-all;">
                  {{ card.url }}
                </div>
              }
              @if (card.detail) {
                <div [innerHTML]="card.detail"></div>
              }
              @if (card.body) {
                <details [open]="!card.collapsed" style="margin-top: 6px;">
                  <summary style="cursor: pointer; font-size: 13px; color: #444; user-select: none;">
                    {{ card.collapsed ? 'Show response' : 'Hide' }}
                  </summary>
                  <pre style="background: #f4f4f4; padding: 12px; border-left: 3px solid #888; white-space: pre-wrap; word-break: break-all; margin: 0;">{{ card.body }}</pre>
                </details>
              }
            </div>
          }

          <h3 style="margin-top: 32px;">Callback</h3>
          @for (card of callbackCards; track $index) {
            <div style="margin-top: 18px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 4px;">
              <h3 [style.color]="card.ok ? '#0a7a0a' : '#b00020'" style="margin: 0 0 6px 0">
                {{ card.title }} {{ card.ok ? '(ok)' : '(failed)' }}
              </h3>
              @if (card.url) {
                <div style="font-family: monospace; font-size: 13px; color: #555; background: #eef; padding: 4px 8px; border-radius: 3px; margin: 6px 0; word-break: break-all;">
                  {{ card.url }}
                </div>
              }
              @if (card.detail) {
                <div [innerHTML]="card.detail"></div>
              }
              @if (card.body) {
                <details [open]="!card.collapsed" style="margin-top: 6px;">
                  <summary style="cursor: pointer; font-size: 13px; color: #444; user-select: none;">
                    {{ card.collapsed ? 'Show response' : 'Hide' }}
                  </summary>
                  <pre style="background: #f4f4f4; padding: 12px; border-left: 3px solid #888; white-space: pre-wrap; word-break: break-all; margin: 0;">{{ card.body }}</pre>
                </details>
              }
            </div>
          }

          @if (hasRefreshToken) {
            <p style="margin-top: 20px;">
              <button (click)="useRefreshToken()">Use refresh token &#x2192;</button>
            </p>
          }
          <p style="margin-top: 12px;">
            <button (click)="reset()">Start over</button>
          </p>
        </div>
      }

      @case ('refreshing') {
        <p>Refreshing...</p>
      }

      @case ('refresh-done') {
        <div>
          @for (card of refreshCards; track $index) {
            <div style="margin-top: 18px; padding: 14px 16px; border: 1px solid #ddd; border-radius: 4px;">
              <h3 [style.color]="card.ok ? '#0a7a0a' : '#b00020'" style="margin: 0 0 6px 0">
                {{ card.title }} {{ card.ok ? '(ok)' : '(failed)' }}
              </h3>
              @if (card.url) {
                <div style="font-family: monospace; font-size: 13px; color: #555; background: #eef; padding: 4px 8px; border-radius: 3px; margin: 6px 0; word-break: break-all;">
                  {{ card.url }}
                </div>
              }
              @if (card.detail) {
                <div [innerHTML]="card.detail"></div>
              }
              @if (card.body) {
                <details [open]="!card.collapsed" style="margin-top: 6px;">
                  <summary style="cursor: pointer; font-size: 13px; color: #444; user-select: none;">
                    {{ card.collapsed ? 'Show response' : 'Hide' }}
                  </summary>
                  <pre style="background: #f4f4f4; padding: 12px; border-left: 3px solid #888; white-space: pre-wrap; word-break: break-all; margin: 0;">{{ card.body }}</pre>
                </details>
              }
            </div>
          }
          <p style="margin-top: 20px;">
            <button (click)="reset()">Start over</button>
          </p>
        </div>
      }

      @case ('error') {
        <div>
          <h2 style="color: #b00020;">Error</h2>
          <p>{{ error }}</p>
          <button (click)="reset()">Start over</button>
        </div>
      }

    }
  `,
})
export class AppComponent implements OnInit {
  private http = inject(HttpClient);

  stage: Stage = 'start';
  prepareCards: Card[] = [];
  authorizeURL = '';
  callbackCards: Card[] = [];
  refreshCards: Card[] = [];
  hasRefreshToken = false;
  error = '';

  ngOnInit(): void {
    const params = new URLSearchParams(window.location.search);
    if (params.get('callbackDone') === '1') {
      this.stage = 'loading-callback';
      history.replaceState(null, '', window.location.pathname);
      this.loadCallbackResult();
    }
  }

  private async loadCallbackResult(): Promise<void> {
    try {
      const result = await firstValueFrom(
        this.http.get<CallbackResultResponse>('/api/callback-result', { withCredentials: true })
      );
      this.prepareCards    = result.prepareCards;
      this.callbackCards   = result.callbackCards;
      this.hasRefreshToken = result.hasRefreshToken;
      this.stage = 'callback-done';
    } catch (err: any) {
      this.error = err?.error?.error || err?.message || 'Failed to load callback result';
      this.stage = 'error';
    }
  }

  async beginLogin(): Promise<void> {
    this.error = '';
    this.stage = 'preparing';
    try {
      const result = await firstValueFrom(
        this.http.post<PrepareResponse>('/api/prepare', {}, { withCredentials: true })
      );
      this.prepareCards = result.prepareCards;
      this.authorizeURL = result.authorizeURL;
      this.stage = 'prepared';
    } catch (err: any) {
      this.error = err?.error?.error || err?.message || 'Failed to prepare login';
      this.stage = 'error';
    }
  }

  navigateToPingOne(): void {
    window.location.href = this.authorizeURL;
  }

  async useRefreshToken(): Promise<void> {
    this.error = '';
    this.stage = 'refreshing';
    try {
      const result = await firstValueFrom(
        this.http.post<RefreshResponse>('/api/refresh', {}, { withCredentials: true })
      );
      this.refreshCards = result.refreshCards;
      this.stage = 'refresh-done';
    } catch (err: any) {
      this.error = err?.error?.error || err?.message || 'Failed to refresh token';
      this.stage = 'error';
    }
  }

  reset(): void {
    this.stage = 'start';
    this.prepareCards = [];
    this.authorizeURL = '';
    this.callbackCards = [];
    this.refreshCards = [];
    this.hasRefreshToken = false;
    this.error = '';
  }
}
