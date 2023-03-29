import os
import platform
import sys
from time import time

from dtype import Conversation
from interaction import Process
from rich import print as eprint
from rich.progress import track


class Assistant:

    def __init__(self):
        self.DEBUG = "-d" in sys.argv

        self.seed = 888777
        self.threads = 4
        self.n_predict = 200
        self.top_k = 40
        self.top_p = 0.9
        self.temp = 0.1
        self.repeat_last_n = 64
        self.repeat_penalty = 1.3

        # self.history_size = 1500

        self.pre_prompt = " Below are instructions to a smart bot named devil, provide response inteligently to instructions.\n\n"
        self.pre_prompt = " Below are instructions provide best possible response and take into account entire history.\n\n"
        self.pre_prompt = "  Below is an instruction that describes a task. Write a response that appropriately completes the request.\n\n"
        self.format = (
            """### Instruction:\n\n{instruction}\n\n### Response:\n\n{response}"""
        )
        # self.pre_prompt = "you are a highly intelligent chatbot named devil and you remember all conversation history."
        self.enable_history = True
        self.history: list[Conversation] = []

        self.end_marker = b"RSTsr"

        self.chat_history = []
        self.model_idx = 0

    def list_available_models(self, directory_path="models", extension="bin"):
        """Returns a list of file names with the given extension in the given directory"""
        file_list = []
        for file in os.listdir(directory_path):
            if file.endswith(extension):
                file_list.append(os.path.join(directory_path, file))
        return file_list

    @staticmethod
    def get_bin_path():
        if os.path.exists("chat"):
            return "./chat"
        system_name = platform.system()
        if system_name == "Linux":
            name = "linux"
        elif system_name == "Windows":
            name = "win.exe"
        elif system_name == "Darwin":
            name = "mac"
        # elif system_name == "Android":
        #     return "Android"
        else:
            exit()

        return os.path.join("bin", name)

    @property
    def command(self):
        command = [
            Assistant.get_bin_path(),
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
            "--temp",
            f"{self.temp}",
            "--n_predict",
            f"{self.n_predict}",
            "-m",
            f"{self.list_available_models()[self.model_idx]}",
            "--interactive-start",
        ]
        return command

    def load_model(self):
        """load binary in memory"""
        self.process = Process(self.command, timeout=10000)
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.recvuntil("load: ")
        is_loaded = False
        for _ in track(range(100)):
            if is_loaded:
                continue
            ppt = self.process.read(1)
            is_loaded = b"d" == ppt

        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.readline()
        self.process.recvuntil(self.end_marker)
        self.current_state = "prompt"

    def action(self, command):
        """returns whether a request can be colmpleted or not"""

        if command == "generate":
            is_possible = self.current_state == "prompt"
        if command == "stop":
            is_possible = self.current_state == "generating"
        return is_possible

    def stop_generation(self):
        """Interrupts generation"""
        self.current_state = "stoping_generation"
        self.process.send("\003")
        self.current_state = "prompt"

    def chatbot(self, prompt: Conversation):
        """Adds history support"""
        self.history.append(prompt)
        # build history chahe
        final_prompt_2_send = []
        data2use = self.history if self.enable_history else [self.history[-1]]
        for convo in data2use:
            for sequence in convo.get_prompt():
                final_prompt_2_send.append(sequence)
        final_prompt_2_send = "".join(final_prompt_2_send)
        if prompt.preprompt:
            final_prompt_2_send = [prompt.preprompt, final_prompt_2_send]
        self.send_prompts(final_prompt_2_send)
        for char in self.stream_generation():
            self.history[-1].response += char
            yield char

    def send_prompts(self, txtblob):
        """send the prompts with bos token"""
        eprint(txtblob)
        txtblob = txtblob if isinstance(txtblob, list) else [txtblob]
        _ = eprint(txtblob) if self.DEBUG else None
        if self.action("generate"):
            bos = len(txtblob)
            self.process.recvuntil("n_inps>  ")
            self.process.sendline(str(bos))

            self.process.recvuntil("n_threads> ")
            self.process.sendline(str(self.threads))
            self.process.recvuntil("top_k> ")
            self.process.sendline(str(self.top_k))
            self.process.recvuntil("top_p> ")
            self.process.sendline(str(self.top_p))
            self.process.recvuntil("temperature> ")
            self.process.sendline(str(self.temp))
            self.process.recvuntil("repeat_penalty> ")
            self.process.sendline(str(self.repeat_penalty))

            for txt in txtblob:
                lines = txt.split("\n")
                for line in lines:
                    self.process.recvuntil(") :  ")
                    self.process.sendline(line)

                self.process.recvuntil(") :  ")
                self.process.sendline("@done@")
            self.process.readline()
            self.current_state = "generating"
        else:
            print("CRITICAL")

    def stream_generation(self):
        """returns a generator that returns the generation"""

        buffer = b""
        marker_detected = b""
        char_old = b""
        while self.current_state == "generating":
            char = self.process.read(1)
            buffer += char  # update the buffer

            # Detect end of text if detected try to confirm else reset
            if char == b"R" or len(marker_detected) > 0:
                marker_detected += char
                char_old += char
                # print("==========")
                # print(marker_detected)
                # print(self.end_marker[:len(marker_detected)])
                if marker_detected in self.end_marker[:len(marker_detected)]:
                    # print("cont")
                    continue
                marker_detected = b""

            if self.end_marker in buffer:
                buffer = buffer.replace(self.end_marker, b"")
                char_old += char
                char_old = char_old.replace(self.end_marker, b"")
                self.current_state = "prompt"
                yield char_old.decode("utf-8")
                # print(f"\nStream Ended {buffer}")
                break

            try:
                # Load the full character cache
                char = char_old + char

                # print single printable chars
                if len(char) == 1 and char[0] <= 0x7E and char[0] >= 0x21:
                    char = char.decode("utf-8")
                    char_old = b""
                elif len(char) in [
                        4, 6
                ]:  # If 4 byte code or handle weird edge cases
                    char = char.decode("utf-8")
                    char_old = b""
                else:
                    char_old = char
                    continue
            except UnicodeDecodeError:
                char_old = char
                continue
            # print(char, end="")
            yield char

        # return buffer

    @staticmethod
    def repl():
        """Repl for my chat bot"""
        assistant = Assistant()
        assistant.load_model()
        assistant.enable_history = False
        fmt = assistant.format
        # assistant.pre_prompt = ""
        preprompt = assistant.pre_prompt
        while True:
            # print("=====")
            prompt = input(">>>>>> ")
            conv = Conversation(preprompt, fmt, prompt)
            preprompt = ""

            resp = assistant.chatbot(conv)

            for char in resp:
                print(char, end="")
            print()


Assistant.repl()



"""

/list_models
/load_model (idx)

/send_input {inp="dsfasf",t="12"}


/get_generation
/stop
/status

/settings

/chat_history []
/save_chat {}
/chat 1


/get_personas

{
name
persona
format
}

Generate a passage on alpacap @T/12@



"""
