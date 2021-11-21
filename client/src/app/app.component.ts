import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  title = 'the Dating app';
  users :any;

  constructor(private http: HttpClient){}
  
  
  
  ngOnInit(){
    this.getUsers();
  }

  getUsers(){
    this.http.get('http://localhost:5000/api/users').subscribe(response => {
      this.users =response;
      console.log(this.users);
    }, error =>{
      console.log(error);
    })
  }
  
}
