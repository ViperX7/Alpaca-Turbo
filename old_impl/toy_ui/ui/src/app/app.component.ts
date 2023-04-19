import {AfterViewInit, Component} from '@angular/core';
import {HomeServiceService} from "./services/home-service.service";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements AfterViewInit{
  title = 'Angular-Turbo';
  private advancedMode = false;
  private sendButton: HTMLElement | undefined;
  private mainHero: HTMLElement | undefined;
  private sideBar: HTMLElement | undefined;
  private chatInput: HTMLElement | undefined;
  private chatHistory: HTMLElement | undefined;
  private chatSection: HTMLElement | undefined;
  private outputText: string = "";
  private personas: [] = [];

  //information variables
  public model_loaded: string = "";
  public server_status: string = "";
  public cpu_percent: number = 0;
  public ram_usage: number = 0;
  public total_ram: number = 0;
  public total_cores: number = 0;
  public threads_above_80: number = 0;
  public total_threads: number = 0;
  private pre: string = "chat transcript between human and a bot named devil and the bot remembers everything from previous response Below is an instruction that describes a task. Write a response that appropriately completes the request.";
  private fmt: string = "### Instruction:{instruction}### Response:{response}";
  private timer: number = 0;
  chatHistoryData: { name: string; data: any; }[] = [];
  //information variables


  constructor(private homeService: HomeServiceService) {}

  ngOnInit(): void {
    this.ReceiveResponseStream();
    this.checkServerStatus();
  }

  ngAfterViewInit(){
    this.sendButton = document.getElementById('send-chat') as HTMLElement;
    this.mainHero = document.querySelector('.hero-section') as HTMLElement;
    this.sideBar = document.querySelector('.sidebar') as HTMLElement;
    this.chatInput = document.getElementById('chat-input') as HTMLElement;
    this.chatHistory = document.querySelector('.recent-chats') as HTMLElement;
    this.chatSection = document.querySelector('.chat-section') as HTMLElement;
    this.getAllPersonas();
    this.getHistoryChat();

    this.chatInput.addEventListener('keydown', (event) => {
      if (event.keyCode === 13 && !event.shiftKey) {
        event.preventDefault();
        this.sendPrompt();
      }
    });
    this.loadDarkModeSetting();

  }

  openSettingPage() {
    // @ts-ignore
    document.getElementById("setting-page").style.display = "block";
  }
  openAdvancedMode() {
    if (this.advancedMode) {
      // @ts-ignore
      document.querySelector(".recent-chats").style.display = "block";
      // @ts-ignore
      document.querySelector(".advanced-mode").style.display = "none";
      this.advancedMode = false;
    }else {
      // @ts-ignore
      document.querySelector(".recent-chats").style.display = "none";
      // @ts-ignore
      document.querySelector(".advanced-mode").style.display = "block";
      this.advancedMode = true;
    }
  }

  samplePrompt($event: MouseEvent) {
    // @ts-ignore
    this.chatInput.innerText = $event.target.innerText;
  }

  sendPrompt() {
    this.timer = 0;
    if (this.server_status !== "prompt") return;
    this.showConversation();
    // @ts-ignore
    let text = this.chatInput.value;
    this.createChatNode(text, 'prompt');
    this.createChatNode("Waiting for response ...", 'waiting');
    let body = { inp: text, fmt: null, pre: null };
    if (this.advancedMode) { // @ts-ignore
      body = { inp: text, fmt: this.fmt, pre: this.pre };
    }

    this.homeService.sendPrompt(body);
    this.outputText = "";
  }

  ReceiveResponseStream() {
    this.outputText = '';
    
    const subscription = this.homeService.ReceiveResponse().subscribe(
      data => {
        this.outputText += data;
        // @ts-ignore
        let waiting_icon = document.querySelector('.jawn');
        if(waiting_icon) waiting_icon.remove();
        // @ts-ignore
        document.getElementById('waiting_prompt').innerHTML = this.outputText;
        // @ts-ignore
        document.getElementById('waiting_prompt').style.whiteSpace = "pre-wrap";

      },
      error => {
        console.log(error);
      },
      () => {
        subscription.unsubscribe();
      }
    );
  }

  showConversation() {
    // @ts-ignore
    if (this.chatInput.value === "") return;
    if (this.mainHero && this.chatSection) {
      this.mainHero.style.display = 'none';
      this.chatSection.style.display = 'block';
    }
  }

  createChatNode(text: string, type: string){
    let mainNod = document.createElement('div');
    let img = document.createElement('img');
    let h4 = document.createElement('h4');
    let chatToolsDiv = document.createElement('div');

    let copyDiv = document.createElement('div');

    mainNod.style.position = "relative";
    chatToolsDiv.classList.add('chatTools');

    copyDiv.classList.add('copy');
    copyDiv.textContent = 'copy';

    copyDiv.addEventListener('click', (event) => this.copyTheText(event));


    // @ts-ignore
    let waiting_prompt = document.getElementById('waiting_prompt');
    if(waiting_prompt) waiting_prompt.id = '';

    if (type === 'prompt') {
      chatToolsDiv.style.width = "auto";
      
      mainNod.className = 'prompt';
      img.src = '/assets/imgs/circle-user-solid.svg';
      img.alt = 'user logo';
      h4.innerHTML = text;
    }else if ('response') {
      let infoDiv = document.createElement('div');
      infoDiv.classList.add('infoDiv');
      infoDiv.textContent = '0 words / 0s';
      chatToolsDiv.appendChild(infoDiv);

      mainNod.className = 'response';
      img.src = '/assets/imgs/alpaca.png';
      img.alt = 'alpaca logo';
      img.classList.add("chatlogo");
      h4.innerHTML = text;
      h4.id = 'waiting_prompt';
    }

    chatToolsDiv.appendChild(copyDiv);

    mainNod.appendChild(img);
    mainNod.appendChild(h4);
    mainNod.appendChild(chatToolsDiv);
    if (type === 'waiting') {
      let div = document.createElement('div');
      div.className = 'jawn';
      mainNod.appendChild(div);
    }

    // @ts-ignore
    this.chatSection.appendChild(mainNod);
  }

  loadDarkModeSetting() {
    this.lightMode();
    if (localStorage.getItem('isDarkMode') === 'true') this.darkMode();
  }

  turnDarkMode() {
    if (localStorage.getItem('isDarkMode') === 'true') {
      this.lightMode();
      localStorage.setItem('isDarkMode', 'false');
    } else{
      this.darkMode();
      localStorage.setItem('isDarkMode', 'true');
    }
  }

  darkMode(){
    let images = document.querySelectorAll('img');
    // @ts-ignore
    document.querySelector('.container').style.backgroundColor = "var(--dark-mode-main-bg-color)";
    // @ts-ignore
    document.querySelector('.container').style.color = "var(--dark-mode-text-color)";
    // @ts-ignore
    document.querySelector('.sidebar').style.backgroundColor = "var(--dark-mode-sidebar-bg-color)";
    images.forEach(image => {
      if (image.classList.contains('logo') || image.classList.contains('sendChat') || image.classList.contains('chatlogo')) return;
      image.classList.add("darkMode");
    });
  }

  lightMode() {
    let images = document.querySelectorAll('img');
    // @ts-ignore
    document.querySelector('.container').style.backgroundColor = "var(--main-bg-color)";
    // @ts-ignore
    document.querySelector('.container').style.color = "var(--light-mode-text-color)";
    // @ts-ignore
    document.querySelector('.sidebar').style.backgroundColor = "var(--sidebar-bg-color)";
    images.forEach(image => {
      if (image.classList.contains('logo') || image.classList.contains('sendChat') || image.classList.contains('chatlogo')) return;
      image.classList.remove("darkMode");
    });
  }

  clearConversation(){
    // @ts-ignore
    while (this.chatSection.firstChild) this.chatSection.firstChild.remove();
  }

  public openChangeModel() {
    // @ts-ignore
    document.getElementById("changeModelPage").style.transform = "translateY(0)"
  }

  checkServerStatus() {
    setInterval(()=> {
      this.homeService.checkStatus().subscribe((response) => {
        this.server_status = response.turbo_status;
        this.cpu_percent = response.cpu_percent.toFixed(2);
        this.ram_usage = response.ram_usage.toFixed(2);
        this.total_ram = response.total_ram.toFixed(2);
        this.total_cores = response.total_cores;
        this.total_threads = response.total_threads;
        this.model_loaded = response.is_model_loaded;
        if(this.server_status === 'generating') this.timer += 1;
        // @ts-ignore
        document.querySelector('.ram').style.width =  this.ram_usage + '%';
        // @ts-ignore
        document.querySelector('.cpu').style.width =  this.cpu_percent + '%';
        if(this.server_status == 'input')  { // @ts-ignore
          this.chatInput.innerText = "";
        }

        // @ts-ignore
        let lastResponse = document.querySelectorAll('.infoDiv')[document.querySelectorAll('.infoDiv').length - 1] as HTMLElement;
        if(lastResponse) lastResponse.innerText = `${this.outputText.split(' ').length - 1} words / ${this.timer}s!`;
        
      });
    },1000);
  }

  stopGenerating() {
    this.homeService.stopGenerating().subscribe();
  }

  getAllPersonas() {
    this.homeService.getPersonas().subscribe((res) => {
      this.personas = res;
      this.createPersonasOptions();
    });
  }

  createPersonasOptions() {
    let select = document.querySelector('.savedPersona');

    this.personas.forEach((persona) => {
      const newOption = document.createElement('option');
      newOption.value = persona;
      newOption.textContent = persona;
      // @ts-ignore
      select.appendChild(newOption);
    });
  }

  changePersona($event: Event) {
    // @ts-ignore
    let name = $event.target.value;
    this.homeService.getPersonaByName(name).subscribe((res) => {
      this.pre = res[0] + " " + res[1];
      this.fmt = res[2];
      // @ts-ignore
      document.getElementById('persona-box').innerText = this.pre;
      // @ts-ignore
      document.getElementById('format-box').innerText = this.fmt;
    });
  }

  openNewChat() {
    if (this.server_status === 'generating') this.homeService.stopGenerating().subscribe();
    this.homeService.saveChat().subscribe();
    this.homeService.clearChat().subscribe();
    this.clearConversation()
    // @ts-ignore
    document.querySelector('.chat-input').disabled = false;
  }

  getHistoryChat() {
    this.homeService.getHistoryChat().subscribe((res) => {
      let helper: { name: string; data: any; }[] = [];
      Object.keys(res).forEach(function(key) {
        let chat = {
          "name": key,
          "data" : res[key]
        }
        helper.push(chat);
      });
      this.chatHistoryData = helper;
      this.loadHistoryData(this.chatHistoryData);
    });
  }

  loadHistoryData(history: { name: string; data: any; }[]) {
    this.chatHistoryData.forEach((chat) => {
      let chatHistoryDiv = document.querySelector('.recent-chats');

      let recentChat = document.createElement('div');
      recentChat.classList.add('recent-chat');

      let img = document.createElement('img');
      img.src = '/assets/imgs/comment-dots-regular.svg';

      let h4 = document.createElement('h4');
      if (!chat.data[0]) return;
      h4.textContent = chat.data[0].instruction;
      h4.setAttribute('data-name', chat.name);

      recentChat.appendChild(img);
      recentChat.appendChild(h4);
      // @ts-ignore
      chatHistoryDiv.appendChild(recentChat);
      h4.addEventListener('click', (e) => {
        // @ts-ignore
        let name = e.target.getAttribute('data-name');
        let chats: [] = history.filter(h => h.name === name)[0].data;
        this.clearConversation();
        // @ts-ignore
        document.querySelector('.hero-section').style.display = "none";
        // @ts-ignore
        document.querySelector('.chat-section').style.display = "block";
        // @ts-ignore
        document.querySelector('.chat-input').disabled = true;

        this.homeService.stopGenerating().subscribe();
        chats.forEach((chat) => {
          // @ts-ignore
          this.createChatNode(chat.instruction, 'prompt');
          // @ts-ignore
          this.createChatNode(chat.response, 'response');
        });
      })
    });
  }

  private copyTheText(event: MouseEvent) {
    // @ts-ignore
    let parentElement = (event.target as HTMLElement).parentElement.parentElement;
    // @ts-ignore
    let textToCopy = parentElement.children[1].innerText;

    if (textToCopy) {
      navigator.clipboard.writeText(textToCopy)
        .then(() => {
          document.querySelectorAll('.copy').forEach((copy) => {
            // @ts-ignore
            copy.style.backgroundColor = "#2b2e2e";
          });
          // @ts-ignore
          event.target.style.backgroundColor = "green";
        })
        .catch((error) => {
          console.error('Error copying text to clipboard:', error);
        });
    }

  }

  removeHistory() {
    this.homeService.removeHistory().subscribe();
    this.chatHistoryData = [];
    let recentChats = document.querySelectorAll('.recent-chat');
    recentChats.forEach((history) => history.remove());
  }

  openSideBarMenu() {
    // @ts-ignore
    this.sideBar.classList.toggle('toggleSideBar');
  }
}
