import {Component, Input} from '@angular/core';
import {HttpClient} from "@angular/common/http";
import {ChangeModelServiceService} from "../../services/change-model-service.service";
import {SettingServiceService} from "../../services/setting-service.service";
import {Observable} from "rxjs";
import {environment} from "../../environments/environment";
import {HomeServiceService} from "../../services/home-service.service";
import {ChangeModelComponent} from "../change-model/change-model.component";

@Component({
  selector: 'app-setting',
  templateUrl: './setting.component.html',
  styleUrls: ['./setting.component.css']
})
export class SettingComponent {

  n_predict: number = 200;
  repeat_last_n: number = 64;
  repeat_penalty: number = 1.3;
  seed: number = 888777;
  temp: number = 0.1;
  threads: number = 4;
  top_k: number = 40;
  top_p: number = 0.9;
  @Input()
  model_loaded: string = "";
  models: [] = [];
  constructor(private http: HttpClient, private SettingService: SettingServiceService,
              private homeService: HomeServiceService, private changeModelService: ChangeModelServiceService) {}

  ngOnInit(): void {
    this.getSetting();
    // @ts-ignore
    document.getElementById("setting-page").style.display = "none";
  }

  closeSetting() {
    // @ts-ignore
    document.getElementById("setting-page").style.display = "none";
  }

  getSetting() {
    this.SettingService.getSetting().subscribe((response) => {
      this.n_predict = response.n_predict;
      this.repeat_last_n= response.repeat_last_n;
      this.repeat_penalty = response.repeat_penalty;
      this.seed = response.seed;
      this.temp = response.temp;
      this.threads = response.threads;
      this.top_k = response.top_k;
      this.top_p = response.top_p;
    });
  }

  resetSetting() {

  }

  changeSetting() {
    let body = {
      "n_predict": this.n_predict,
      "repeat_last_n": this.repeat_last_n,
      "repeat_penalty": this.repeat_penalty,
      "seed": this.seed,
      "temp": this.temp,
      "threads": this.threads,
      "top_k": this.top_k,
      "top_p": this.top_p
    }

    this.SettingService.postSetting(body).subscribe((response) => {
      if (response.success) {
        // @ts-ignore
        document.querySelector('.notification').innerText = "Setting has been changed successfully !";
      }
    });

    this.SettingService.getSetting().subscribe((oldSetting) => {
      if (oldSetting.seed !== this.seed || oldSetting.n_predict !== this.n_predict || oldSetting.repeat_last_n !== this.repeat_last_n) {
        this.homeService.stopGenerating().subscribe();
        this.SettingService.onloadModel().subscribe();
        this.changeModelService.loadModels().subscribe((res) => {
          this.models = res;
          //@ts-ignore
          document.querySelector('.notification').innerText = "Setting has been changed successfully, Waiting to reload the model !";
          // @ts-ignore
          this.changeModelService.changeModel(this.models.indexOf(this.model_loaded)).subscribe((res) => {
            //@ts-ignore
            document.querySelector('.notification').innerText = "Setting has been changed successfully !";
          })
        })
      }
    });

  }
}
