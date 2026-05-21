import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

type Stage = 'login' | 'mfa' | 'done' | 'error';

interface ApiResponse {
  status: 'COMPLETED' | 'MFA_REQUIRED' | 'ERROR';
  accessToken?: string;
  message?: string;
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
  private http = inject(HttpClient);

  logoSrc = 'assets/logo.png';
  stage: Stage = 'login';
  username = '';
  password = '';
  otp = '';
  accessToken = '';
  error = '';

  async login() {
    this.error = '';
    try {
      const resp = await firstValueFrom(
        this.http.post<ApiResponse>('/api/login',
          { username: this.username, password: this.password },
          { withCredentials: true }
        )
      );
      if (resp.status === 'COMPLETED') {
        this.accessToken = resp.accessToken || '';
        this.stage = 'done';
      } else if (resp.status === 'MFA_REQUIRED') {
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

  reset() {
    this.stage = 'login';
    this.username = '';
    this.password = '';
    this.otp = '';
    this.accessToken = '';
    this.error = '';
  }
}
