// app.component.ts — Angular UI shell for the PingOne MFA demo.
//
// This component manages the full user-facing flow through four stages:
//   login   — username/password form; posts to POST /api/login
//   mfa     — OTP entry form shown when the server responds MFA_REQUIRED;
//             posts to POST /api/mfa-verify
//   done    — success screen displaying the access token returned by the server
//   error   — error screen with a retry option
//
// All PingOne API logic lives in the Express backend (server/index.js). This
// component only drives the UI and interprets the two JSON responses:
//
//   POST /api/login returns:
//     { status: 'COMPLETED',   accessToken: '<jwt>' }  — no MFA, token ready
//     { status: 'MFA_REQUIRED' }                       — OTP sent, show mfa stage
//     { status: 'ERROR',       message: '...' }         — show error stage
//
//   POST /api/mfa-verify returns:
//     { status: 'COMPLETED',   accessToken: '<jwt>' }  — OTP accepted, token ready
//     { status: 'ERROR',       message: '...' }         — OTP rejected or expired
//
// withCredentials: true is required on both HTTP calls so the browser sends
// the httpOnly `sid` cookie that ties this client to its server-side session.
// Without it the server cannot look up the PingOne flow state between the
// login and MFA steps.
//
// The /api prefix is proxied to the Express backend (port 3000) during
// development via proxy.conf.json. In production the Angular build is served
// by the same Express process, so no proxy is needed.

import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

// Stage represents the current UI screen. Transitions:
//   login → mfa    (server returns MFA_REQUIRED)
//   login → done   (server returns COMPLETED without MFA)
//   mfa   → done   (server returns COMPLETED after OTP)
//   any   → error  (server returns ERROR or network failure)
//   any   → login  (user clicks "Log Out" or "Try Again")
type Stage = 'login' | 'mfa' | 'done' | 'error';

// ApiResponse is the shape returned by both /api/login and /api/mfa-verify.
interface ApiResponse {
  status: 'COMPLETED' | 'MFA_REQUIRED' | 'ERROR';
  accessToken?: string; // present only when status === 'COMPLETED'
  message?: string;     // present only when status === 'ERROR'
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [FormsModule],
  template: `
    <div>
      <header style="background:#B8002F;padding:12px 24px;display:flex;align-items:center;margin-bottom:0;">
        <img [src]="logoSrc" style="height:35px;width:auto;" alt="Ping Identity">
      </header>
      <div style="padding:32px 40px;max-width:900px;margin:0 auto;">
    @switch (stage) {
      @case ('login') {
        <div>
          <h2>Secure Login</h2>
          <form (ngSubmit)="login()">
            <label>Username:</label><br>
            <input [(ngModel)]="username" name="username" required><br><br>
            <label>Password:</label><br>
            <input type="password" [(ngModel)]="password" name="password" required><br><br>
            <button type="submit">Log In</button>
          </form>
        </div>
      }
      @case ('mfa') {
        <div>
          <h2>Two-Factor Authentication</h2>
          <p>Please enter the verification code sent to your email.</p>
          <form (ngSubmit)="verifyMfa()">
            <label>MFA Code:</label><br>
            <input [(ngModel)]="otp" name="otp" required><br><br>
            <button type="submit">Verify</button>
          </form>
        </div>
      }
      @case ('done') {
        <div>
          <h2 style="color: green;">Login Successful!</h2>
          <p>You have securely authenticated. Here is your Access Token:</p>
          <pre style="background:#eee; padding:15px; white-space: pre-wrap; word-wrap: break-word;">{{ accessToken }}</pre>
          <button (click)="reset()">Log Out</button>
        </div>
      }
      @case ('error') {
        <div>
          <h2 style="color: red;">Authentication Error</h2>
          <pre>{{ error }}</pre>
          <button (click)="reset()">Try Again</button>
        </div>
      }
    }
      </div>
    </div>
  `,
})
export class AppComponent {
  // HttpClient is provided via provideHttpClient(withFetch()) in app.config.ts.
  // Injecting it here (rather than via the constructor) is the Angular 17+
  // standalone pattern; no HttpClientModule import is needed.
  private http = inject(HttpClient);

  logoSrc = 'assets/logo.png';
  stage: Stage = 'login';
  username = '';
  password = '';
  otp = '';
  accessToken = '';
  error = '';

  // login() submits the username/password to the backend and transitions the
  // stage based on the response status.
  async login() {
    this.error = '';
    try {
      const resp = await firstValueFrom(
        this.http.post<ApiResponse>('/api/login',
          { username: this.username, password: this.password },
          // withCredentials: true sends the httpOnly `sid` cookie so the server
          // can store PingOne flow state between the login and MFA steps.
          { withCredentials: true }
        )
      );
      if (resp.status === 'COMPLETED') {
        this.accessToken = resp.accessToken || '';
        this.stage = 'done';
      } else if (resp.status === 'MFA_REQUIRED') {
        // PingOne has sent an OTP to the user's registered email device.
        // Show the OTP form while keeping the server-side session alive.
        this.stage = 'mfa';
      } else {
        this.error = resp.message || 'Login failed';
        this.stage = 'error';
      }
    } catch (err: any) {
      this.error = err?.error?.message || err?.message || 'Login failed';
      this.stage = 'error';
    }
  }

  // verifyMfa() submits the OTP to the backend. withCredentials: true sends
  // the `sid` cookie so the server can correlate this submission with the
  // PingOne flow that was started in the login step.
  async verifyMfa() {
    this.error = '';
    try {
      const resp = await firstValueFrom(
        this.http.post<ApiResponse>('/api/mfa-verify',
          { otp: this.otp },
          { withCredentials: true }
        )
      );
      if (resp.status === 'COMPLETED') {
        this.accessToken = resp.accessToken || '';
        this.stage = 'done';
      } else {
        this.error = resp.message || 'MFA failed';
        this.stage = 'error';
      }
    } catch (err: any) {
      this.error = err?.error?.message || err?.message || 'MFA failed';
      this.stage = 'error';
    }
  }

  // reset() returns the component to the initial login state, clearing all
  // transient fields so the next login attempt starts fresh.
  reset() {
    this.stage = 'login';
    this.username = '';
    this.password = '';
    this.otp = '';
    this.accessToken = '';
    this.error = '';
  }
}
