import { Component,OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent implements OnInit {
  

  userEmail: string = '';

  constructor(private route: ActivatedRoute) {}

  ngOnInit() {
    // Retrieve user email from router state
    const state = history.state;
    this.userEmail = state.email || '';

    // this.route.paramMap.subscribe(params => {
    //   // Retrieve the email parameter from the route
    //   this.userEmail = params.get('email') || '';
    // });

   

    
  }

 

}
