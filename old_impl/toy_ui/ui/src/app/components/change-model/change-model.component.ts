import {AfterViewInit, Component, Injectable, Input, OnInit} from '@angular/core';
import {ChangeModelServiceService} from "../../services/change-model-service.service";
@Component({
  selector: 'app-change-model',
  templateUrl: './change-model.component.html',
  styleUrls: ['./change-model.component.css']
})

@Injectable({
  providedIn: 'root'
})
export class ChangeModelComponent implements OnInit {
  model: number | undefined;
  @Input()
  model_loaded: string = "";
  notification: string = "";
  constructor(private changeModelService: ChangeModelServiceService) { }

  ngOnInit(): void {
    this.loadModels();
    setTimeout(() => {
      if (this.model_loaded !== "") this.closeModel();
    }, 2000);
  }

  loadModels(): void {
    this.changeModelService.loadModels().subscribe((response: []) => {
      const mySelect = document.getElementById('modelType') as HTMLSelectElement;

      response.forEach(model => {
        const newOption = document.createElement('option');
        newOption.value = model;
        newOption.text = model;
        mySelect.appendChild(newOption);
      });
    });
  }
  changeModel(): void {
    this.notification = "Loading the model, please wait ...";
    this.changeModelService.changeModel(this.model).subscribe((response) => {
      this.notification = response.status;
    });
  }

  closeModel(): void {
    // @ts-ignore
    document.getElementById("changeModelPage").style.transform = "translateY(-200%)"
  }

  openChangeModel() {
    // @ts-ignore
    document.getElementById("changeModelPage").style.transform = "translateY(0)"
  }

  selectedModel(event: Event): void {
    // @ts-ignore
    this.model = event.target.selectedIndex - 1;
  }
}
