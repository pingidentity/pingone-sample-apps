import { Component, inject } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

type Stage = 'signup' | 'verify' | 'login' | 'success' | 'dashboard' | 'error';

interface ApiResponse {
  status: 'VERIFICATION_REQUIRED' | 'COMPLETED' | 'ERROR';
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
      @case ('signup') {
        <div>
          <h2>Sign Up</h2>
          <form (ngSubmit)="register()">
            <label>Username:</label><br>
            <input [(ngModel)]="username" name="username" required><br><br>
            <label>Email:</label><br>
            <input type="email" [(ngModel)]="email" name="email" required><br><br>
            <label>Password:</label><br>
            <input type="password" [(ngModel)]="password" name="password" required><br><br>
            <button type="submit">Register</button>
          </form>
          <br><hr><br>
          <p>Already have an account? <a href="#" (click)="goLogin($event)">Log in here</a></p>
        </div>
      }
      @case ('verify') {
        <div>
          <h2>Check Your Email</h2>
          <p>We've sent a 6-digit verification code to your email address.</p>
          <form (ngSubmit)="verify()">
            <label>Verification Code:</label><br>
            <input [(ngModel)]="code" name="code" required><br><br>
            <button type="submit">Verify &amp; Complete</button>
          </form>
        </div>
      }
      @case ('login') {
        <div>
          <h2>Login</h2>
          <form (ngSubmit)="login()">
            <label>Username:</label><br>
            <input [(ngModel)]="username" name="username" required><br><br>
            <label>Password:</label><br>
            <input type="password" [(ngModel)]="password" name="password" required><br><br>
            <button type="submit">Log In</button>
          </form>
        </div>
      }
      @case ('success') {
        <div>
          <h2 style="color: green;">Registration Complete!</h2>
          <p>Your account has been successfully created and verified via PingOne.</p>
          <a href="#" (click)="goLogin($event)">Click here to Log In</a>
        </div>
      }
      @case ('dashboard') {
        <div>
          <h2 style="color: blue;">Welcome to your Dashboard!</h2>
          <p>You have successfully authenticated. Here is your Access Token:</p>
          <pre style="background:#eee; padding:15px; white-space: pre-wrap; word-wrap: break-word;">{{ accessToken }}</pre>
          <button (click)="reset()">Log Out (Return to Home)</button>
        </div>
      }
      @case ('error') {
        <div>
          <h2 style="color: red;">Something went wrong</h2>
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
  stage: Stage = 'signup';
  username = '';
  email = '';
  password = '';
  code = '';
  accessToken = '';
  error = '';

  private async post(path: string, body: object): Promise<ApiResponse> {
    try {
      return await firstValueFrom(
        this.http.post<ApiResponse>(path, body, { withCredentials: true })
      );
    } catch (err: any) {
      return { status: 'ERROR', message: err?.error?.message || err?.message || 'Request failed' };
    }
  }

  async register() {
    this.error = '';
    const resp = await this.post('/api/register',
      { username: this.username, email: this.email, password: this.password });
    if (resp.status === 'VERIFICATION_REQUIRED') this.stage = 'verify';
    else if (resp.status === 'COMPLETED') this.stage = 'success';
    else { this.error = resp.message || 'Registration failed'; this.stage = 'error'; }
  }

  async verify() {
    this.error = '';
    const resp = await this.post('/api/verify', { code: this.code });
    if (resp.status === 'COMPLETED') this.stage = 'success';
    else { this.error = resp.message || 'Verification failed'; this.stage = 'error'; }
  }

  async login() {
    this.error = '';
    const resp = await this.post('/api/login',
      { username: this.username, password: this.password });
    if (resp.status === 'COMPLETED') {
      this.accessToken = resp.accessToken || '';
      this.stage = 'dashboard';
    } else {
      this.error = resp.message || 'Login failed';
      this.stage = 'error';
    }
  }

  goLogin(event: Event) {
    event.preventDefault();
    this.password = '';
    this.code = '';
    this.stage = 'login';
  }

  reset() {
    this.stage = 'signup';
    this.username = '';
    this.email = '';
    this.password = '';
    this.code = '';
    this.accessToken = '';
    this.error = '';
  }
}
