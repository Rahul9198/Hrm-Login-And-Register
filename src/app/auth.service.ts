import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private baseURL = 'http://localhost:3000';
  constructor(private http: HttpClient) {}
  register(firstname: string, lastname:string, email: string, password: string, department: string, position:string,phonenumber:string) {
    return this.http.post(`${this.baseURL}/register`, { firstname,lastname, email, password, department, position, phonenumber });
  }
  login(email: string, password: string) {
    return this.http.post(`${this.baseURL}/login`, { email, password });
  }

}
