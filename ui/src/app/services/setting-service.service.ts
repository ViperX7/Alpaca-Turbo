import { Injectable } from '@angular/core';
import { SocketService } from './SocketService';
import {HttpClient} from "@angular/common/http";
import {Observable} from "rxjs";
import {environment} from "../environments/environment";

@Injectable({
  providedIn: 'root'
})
export class SettingServiceService {
  constructor(private http: HttpClient, private socketService: SocketService) {}

  getSetting(): Observable<any> {
    return this.http.get<string>(environment.socketUrl + '/config');
  }

  postSetting(body:any) {
    return this.http.post<any>(environment.socketUrl + '/config', body);
  }

  onloadModel(): Observable<any> {
    return this.http.get<string>(environment.socketUrl + '/unload');
  }

  reloadModelAfterChanges(): Observable<any> {
    return this.http.get<string>(environment.socketUrl + '/reload_model');
  }
}
