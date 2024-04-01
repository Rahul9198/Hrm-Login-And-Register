import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { RegistrationComponent } from './registration/registration.component';
import { LoginComponent } from './login/login.component';

import { DashboardComponent } from './dashboard/dashboard.component'
const routes: Routes = [
  

{
  path:'login',
  component:LoginComponent
},
{
  path:'register',
  component:RegistrationComponent
},
{
  path:'dashboard',
  component:DashboardComponent
},

{ path: '', redirectTo: '/register', pathMatch: 'full' },
  // Redirect to dashboard after login
  { path: 'login', redirectTo: '/dashboard', pathMatch: 'full' },
  // Redirect to login if route not found
  { path: '**', redirectTo: '/login', pathMatch: 'full' },

];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
