import os
import platform
import sys
from time import time

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
        self.temp = 0.5
        self.repeat_last_n = 64
        self.repeat_penalty = 1.3
        # self.history_size = 1500

        self.format = (
            """### Instruction:\n\n{instruction}\n### Response:\n{response}"""
        )
        self.enable_history = False
        self.history  = []

        self.end_marker = b"RSTsr"

        self.chat_history = []

    def list_available_models(directory_path="models", extension="bin"):
        """Returns a list of file names with the given extension in the given directory"""
        file_list = []
        for file in os.listdir(directory_path):
            if file.endswith(extension):
                file_list.append(file)
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
            "--n_predict",
            f"{self.n_predict}",
            "-m",
            f"{self.model_path}",
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



    def send_prompts(self, txtblob):
        """send the prompts with bos token"""
        txtblob = txtblob if isinstance(txtblob, list) else [txtblob]
        _ = eprint(txtblob) if self.DEBUG else None
        if self.action("generate"):
            bos = len(txtblob)
            self.process.recvuntil("bos> ")
            self.process.sendline(str(bos))
            for txt in txtblob:
                lines = txt.split("\n")
                for line in lines:
                    self.process.recvuntil(") :  ")
                    self.process.sendline(line)


                self.process.recvuntil(") :  ")
                self.process.sendline("@end@")
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
                # print("==========")
                # print(marker_detected)
                # print(self.end_marker[:len(marker_detected)])
                if marker_detected in self.end_marker[:len(marker_detected)]:
                    # print("cont")
                    continue
                marker_detected = b""

            if self.end_marker in buffer:
                buffer = buffer.replace(self.end_marker, b"")
                self.current_state = "prompt"
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
        while True:
            # print("=====")
            prompt = "### Instruction:\n\n"
            prompt += input(">>> ")
            prompt += "\n### Response:\n\n"
            assistant.send_prompts(prompt)
            resp = assistant.stream_generation()

            for char in resp:
                print(char, end="")
            print()


Assistant.repl()
