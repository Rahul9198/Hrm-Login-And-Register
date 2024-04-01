import { Component } from '@angular/core';
import { AuthService } from '../auth.service';
@Component({
  selector: 'app-registration',
  templateUrl: './registration.component.html',
  styleUrl: './registration.component.css'
})
export class RegistrationComponent {

  firstname: string ='';
  lastname: string ='';
  email: string = '';
  password: string = '';
  message: string = '';
  department:string = '';
  position:string = '';
  phonenumber:string = '';
  constructor(private authService: AuthService) {}
  onSubmit() {
    this.authService.register(this.firstname, this.lastname, this.email, this.password, this.department,this.position, this.phonenumber)
      .subscribe(
        data => {
          console.log(data);
          this.message = 'Registration successful!';
        },
        error => {
         console.log(error);
          this.message = 'Something Wrong.';
        });
  }

}
