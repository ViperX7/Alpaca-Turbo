"""
Alpaca Turbo
"""
import json
import os
import platform
import signal

from interact import Process as process
from rich.progress import track

# Add code.
import string
from transformers import pipeline

# from pwn import  process

# pylint: disable=C0103
# pylint: disable=C0114
# pylint: disable=C0116


class AssistantSettings:
    """Settings handler for assistant"""

    def __init__(self, assistant):
        self.assistant = assistant
        self.load_settings()
        self.assistant.prep_model()

    def load_settings(self):
        if os.path.exists("settings.dat"):
            with open("settings.dat", "r", encoding="utf-8") as file:
                settings = json.load(file)
            self.update(*settings)
        else:
            print("can't load the settings file continuing with defaults")

    def reload(self):
        self.assistant.program.kill(signal.SIGTERM)
        self.assistant.is_ready = False
        self.assistant.prep_model()



    def update(self, *settings):
        old_settings = self.get()
        (
            self.assistant.enable_history,
            self.assistant.seed,
            self.assistant.top_k,
            self.assistant.top_p,
            self.assistant.temp,
            self.assistant.threads,
            self.assistant.repeat_penalty,
            self.assistant.repeat_last_n,
            self.assistant.model_path,
            self.assistant.persona,
            self.assistant.prompt,
            self.assistant.format,
        ) = settings

        self.assistant.enable_history = int(self.assistant.enable_history)
        self.assistant.seed = int(self.assistant.seed)
        self.assistant.top_k = int(self.assistant.top_k)
        self.assistant.top_p = float(self.assistant.top_p)
        self.assistant.temp = float(self.assistant.temp)
        self.assistant.threads = int(self.assistant.threads)
        self.assistant.repeat_penalty = float(self.assistant.repeat_penalty)
        self.assistant.repeat_last_n = int(self.assistant.repeat_last_n)

        new_settings = self.get()

        if not os.path.exists(self.assistant.model_path):
            print("Error Saving Settings")
            print(f"Can't locate the model @ {self.assistant.model_path}")

        with open("settings.dat", "w") as file:
            json.dump(settings, file)

        if old_settings[:-3] != new_settings[:-3] and self.assistant.is_ready:
            self.reload()

    def get(self, n=None):
        order = [
            self.assistant.enable_history,
            self.assistant.seed,
            self.assistant.top_k,
            self.assistant.top_p,
            self.assistant.temp,
            self.assistant.threads,
            self.assistant.repeat_penalty,
            self.assistant.repeat_last_n,
            self.assistant.model_path,
            self.assistant.persona,
            self.assistant.prompt,
            self.assistant.format,
        ]

        result = order if n is None else order[n]
        return result


class Assistant:
    """Alpaca Assistant"""

    def __init__(self) -> None:
        self.seed = 888777
        self.threads = 4
        self.n_predict = 200
        self.top_k = 40
        self.top_p = 0.9
        self.temp = 0.5
        self.repeat_last_n = 64
        self.repeat_penalty = 1.3
        self.model_path = "~/dalai/alpaca/models/7B/ggml-model-q4_0.bin"
        self.model_path = os.path.expanduser(self.model_path)

        self.persona = "chat transcript between human and a bot named devil and the bot remembers everything from previous response"

        self.prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request."""

        self.format = """\n### Instruction:\n{instruction}\n\n### Response:\n{response}"""
        self.enable_history = True
        self.is_ready = False

        self.settings = AssistantSettings(self)

        self.end_marker = b"[end of text]"

        self.chat_history = []

        # Add code.
        self.je_translator = pipeline("translation", model="staka/fugumt-ja-en")
        self.ej_translator = pipeline("translation", model="staka/fugumt-en-ja")

    # Add code.
    def is_halfwidth_jp(self):  # ASCII code only is True.
        return all(
            c in string.ascii_letters + string.digits + string.punctuation + " " for c in self.instr
        )

    # fuguMT Translate code.
    def fugumt(input_lang, self):
        article = self.prompt
        if input_lang == "jpn_Jpan":
            result = self.je_translator(article)        
        else:
            result = self.ej_translator(article)        
        answer_text = [ d.get('translation_text') for d in result]
        print(answer_text)
        return answer_text[0]
    
    # fuguMT Translate code.
    def je_fugumt(self):
        article = self.instr
        result = self.je_translator(article)        
        answer_text = [ d.get('translation_text') for d in result]
        print(answer_text)
        return answer_text[0]

    def ej_fugumt(self, resp):
        result = self.ej_translator(resp)        
        answer_text = [ d.get('translation_text') for d in result]
        print(answer_text)
        return answer_text[0]

    def get_os_name(self):
        system_name = platform.system()
        if system_name == "Linux":
            return "linux"
        elif system_name == "Windows":
            return "win.exe"
        elif system_name == "Darwin":
            return "mac"
        # elif system_name == "Android":
        #     return "Android"
        else:
            exit()
            return "Unknown"

    @property
    def command(self):
        command = [
            f"./bin/{self.get_os_name()}",
            # "--color",
            # "-i",
            "--seed",
            f"{self.seed}",
            "-t",
            f"{self.threads}",
            "--top_k",
            f"{self.top_k}",
            "--top_p",
            f"{self.top_p}",
            "--repeat_last_n",
            f"{self.repeat_last_n}",
            "--repeat_penalty",
            f"{self.repeat_penalty}",
            "-m",
            f"{self.model_path}",
            "--interactive-start",
        ]
        return command

    @property
    def bot_input(self):
        """
        prep_bot_input
        """
        prompt = self.persona + "\n" + self.prompt
        history = self.chat_history if self.enable_history else [self.chat_history[-1]]
        for instr, resp in history:
            # Add code.
            self.instr = instr
            if self.is_halfwidth_jp() == False:
                instr = self.je_fugumt()
            prompt += self.format.format(instruction=instr, response=resp)
        prompt = prompt.strip("\n")
        prompt = prompt.replace("\n", "\\\n")
        # print("======")
        # print(prompt)
        # print("======")
        return prompt

    def prep_model(self):
        if self.is_ready:
            return None
        if not os.path.exists(self.model_path):
            print("="*20)
            print("Please Set model path in the settings")
            print("="*20)
            return 

        self.program = process(self.command,timeout=600)
        for _ in track(range(45), "Loading Model"):
            self.program.recvuntil(b".")
        # print("Model Ready to respond")
        self.is_ready = True

    def ask_bot(self, question):
        """
        run
        """
        _ = self.prep_model() if not self.is_ready else None
        self.program.recvuntil("\'\\\'.")
        self.program.recvuntil("\n")

        # self.program.recvuntil(b"REPLERP")
        # self.program.recv(1)
        self.chat_history.append((question, ""))
        # print("------")
        # print(self.bot_input)
        # print("------")

        opts = self.bot_input.split("\n")
        for opt in opts: 
            self.program.sendline(opt)


        try:
            marker_detected = b""
            char = self.program.recv(1)
            data = char
            # yield char.decode("latin")
            while True:
                char = self.program.recv(1)
                data += char

                if char == b"[" or marker_detected:
                    marker_detected += char
                    if marker_detected in self.end_marker:
                        continue
                    else:
                        marker_detected = b""

                if self.end_marker in data:
                    data = data.replace(b"[end of text]", b"")
                    break

                # yield char.decode("latin")
            answer = self.ej_fugumt(data.decode("utf-8"))
            print(answer, type(answer))
            data = answer

        except (KeyboardInterrupt, EOFError):
            print("Stooping")

        self.chat_history[-1] = (question, answer.strip("\n"))
        # self.is_ready = False
        return data

    @staticmethod
    def repl():
        assistant = Assistant()
        assistant.prep_model()
        while True:
            print(assistant.chat_history)
            resp = assistant.ask_bot(input(">>> "))

            for char in resp:
                print(char, end="")
            print()


_ = Assistant.repl() if __name__ == "__main__" else None
