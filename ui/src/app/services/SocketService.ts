import { Injectable } from '@angular/core';
import { io, Socket } from 'socket.io-client';
import { environment } from '../environments/environment';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class SocketService {
  private socket: Socket;

  constructor() {
    this.socket = io(environment.socketUrl);
  }

  public send(eventName: string, data: any): void {
    this.socket.emit(eventName, data);
  }

  public onEvent<T>(eventName: string): Observable<T> {
    return new Observable<T>(observer => {
      this.socket.on(eventName, (data: T) => {
        observer.next(data);
      });
    });
  }
}
