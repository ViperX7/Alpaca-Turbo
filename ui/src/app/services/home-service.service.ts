import { Injectable } from '@angular/core';
import {Observable} from 'rxjs';
import { SocketService } from './SocketService';
import {HttpClient} from "@angular/common/http";
import {environment} from "../environments/environment";
@Injectable({
  providedIn: 'root'
})
export class HomeServiceService {
  constructor(private socketService: SocketService, private http: HttpClient) {}

  public sendPrompt(body: any): void {
    this.socketService.send('send_input', body);
  }

  public ReceiveResponse(): Observable<string> {
    return this.socketService.onEvent<string>('data');
  }

  public checkStatus(): Observable<any> {
    return this.http.get<string>(environment.socketUrl + '/status');
  }

  public stopGenerating() {
    return this.http.get<string>(environment.socketUrl + '/stop');
  }

  public getPersonas() {
    return this.http.get<any>(environment.socketUrl + '/personas');
  }

  public getPersonaByName(name: string){
    return this.http.get<any>(environment.socketUrl + '/personas/' + name);
  }

  saveChat(){
    return this.http.get<any>(environment.socketUrl + '/save_chat');
  }

  clearChat(){
    return this.http.get<any>(environment.socketUrl + '/clear_chat');
  }

  getHistoryChat() {
    return this.http.get<any>(environment.socketUrl + '/get_conv_logs');
  }

  removeHistory() {
    return this.http.get<any>(environment.socketUrl + '/remove_all_chat');
  }
}
