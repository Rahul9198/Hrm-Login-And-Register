import { Component } from '@angular/core';
import { AuthService } from '../auth.service';
import { Router } from '@angular/router';
@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent {
  email: string = '';
  password: string = '';
  message: string = '';
  constructor(private authService: AuthService, private router:Router) {}
  onSubmit() {
    this.authService.login(this.email, this.password)
      .subscribe(
        data => {
          console.log(data);
          this.message = 'Login successful!';
          //After login go to the dashboard
          this.router.navigate(['/dashboard'],{ state: { email: this.email } });
        },
        error => {
          console.log(error);
          this.message = 'Invalid email or password.';
        });
  }
}
