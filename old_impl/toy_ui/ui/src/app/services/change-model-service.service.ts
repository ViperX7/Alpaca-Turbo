import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import {HttpClient} from "@angular/common/http";
import { environment } from '../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class ChangeModelServiceService {
  constructor(private http: HttpClient) {}

  loadModels(): Observable<any> {
    return this.http.get<string>(environment.socketUrl + '/list_models');
  }

  changeModel(modelIndex: any): Observable<any> {
    return this.http.get<string>(environment.socketUrl + '/load_model/' + modelIndex);
  }


}
