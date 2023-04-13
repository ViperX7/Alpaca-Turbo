#!/bin/python3
"""
     ▄▄▄· ▄▄▌   ▄▄▄· ▄▄▄·  ▄▄·  ▄▄▄·     ▄▄▄▄▄▄• ▄▌▄▄▄  ▄▄▄▄·       
    ▐█ ▀█ ██•  ▐█ ▄█▐█ ▀█ ▐█ ▌▪▐█ ▀█     •██  █▪██▌▀▄ █·▐█ ▀█▪▪     
    ▄█▀▀█ ██▪   ██▀·▄█▀▀█ ██ ▄▄▄█▀▀█      ▐█.▪█▌▐█▌▐▀▀▄ ▐█▀▀█▄ ▄█▀▄ 
    ▐█ ▪▐▌▐█▌▐▌▐█▪·•▐█ ▪▐▌▐███▌▐█ ▪▐▌     ▐█▌·▐█▄█▌▐█•█▌██▄▪▐█▐█▌.▐▌
     ▀  ▀ .▀▀▀ .▀    ▀  ▀ ·▀▀▀  ▀  ▀      ▀▀▀  ▀▀▀ .▀  ▀·▀▀▀▀  ▀█▄▀▪

https;//github.comViperX7/Alpaca-Turbo
"""
import os
import platform
import sys

from helpers.dtype import Conversation, load_all_conversations
from helpers.interaction import Process
from rich import print as eprint


class Assistant:
    def __init__(self):
        self.DEBUG = "-d" in sys.argv

        self.threads = 4
        self.top_k = 200
        self.top_p = 0.99
        self.temp = 0.7
        self.repeat_penalty = 1
        self.batch_size = 256

        self.seed = 888777
        self.n_predict = 1000
        self.repeat_last_n = 512
        self.use_bos = True
        self.antiprompt = "### Human:"
        self.models_directory = "models"

        # self.history_size = 1500

        # self.pre_prompt = " Below are instructions to a smart bot named devil, provide response inteligently to instructions.\n\n"
        # self.pre_prompt = " Below are instructions provide best possible response and take into account entire history.\n\n"
        self.pre_prompt = " Below is an instruction that describes a task. Write a response that appropriately completes the request."
        self.format = "### Instruction:\n\n{instruction}\n\n### Response:\n\n{response}"
        # self.pre_prompt = "you are a highly intelligent chatbot named devil and you remember all conversation history."
        self.enable_history = False
        self.history: list[Conversation] = []

        self.end_marker = b"RSTsr"

        self.model_idx = 0
        self.is_loaded = ""

        self.current_state = "Initialised"
        self.old_preprompt = None
        self.is_first_request = True

    def load_chat(self, id):
        """load chat"""
        result = {"can't load generation going on"}
        if self.current_state != "generating":
            data = load_all_conversations()
            print(data)
        return data[id]

    def remove_all_chat(self):
        """hello world"""

        # specify the path of the folder
        folder_path = "conversations"

        # loop through all files in the folder
        r_count = 0
        for file_name in os.listdir(folder_path):
            # join the folder path and file name
            file_path = os.path.join(folder_path, file_name)
            # check if the file exists
            if os.path.isfile(file_path):
                # delete the file
                os.remove(file_path)
                r_count += 1
        print(f"{r_count} deleted successfully")
        return f"{r_count} files removed"

    def save_chat(self):
        """load chat"""
        result = "can't save generation going on"
        if self.current_state != "generating":
            if self.history:
                Conversation.save(self.history)
                result = "success"
            else:
                result = "no conversation to save"
        return result

    def get_conv_logs(self):
        """conversation logs"""
        data = load_all_conversations()
        return data

    def clear_chat(self):
        """clear current history context"""
        result = "can't save generation going on"
        if self.current_state != "generating":
            self.history = []
            result = "success"
            self.is_first_request = True
            self.use_bos = True
        return result

    def safe_kill(self):
        """kill the bot if not in use"""
        if self.current_state == "generating":
            return "Can't kill bot busy"

        self.process.killx()
        self.is_first_request = True
        self.current_state = "Initialised"
        if self.history:
            Conversation.save(self.history)
        self.history = []
        self.is_loaded = ""

        return "killed the bot"

    def list_available_models(self, directory_path="models", extension="bin"):
        """Returns a list of file names with the given extension  given dir"""
        file_list = []
        for file in os.listdir(directory_path):
            if file.endswith(extension):
                file_list.append(os.path.join(directory_path, file))
        return file_list

    @staticmethod
    def get_bin_path():
        system_name = platform.system()
        if os.path.exists("/main"):
            name = "/main"
        elif system_name == "Linux":
            name = "bin/main"
        elif system_name == "Windows":
            name = "bin/main.exe"
        elif system_name == "Darwin":
            name = "bin/mac"
        else:
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXX    CHAT BINARY MISSING    XXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")

        # elif system_name == "Android":
        #     return "Android"
        # else:
        #     exit()
        return name

    @property
    def command(self):
        command = [
            Assistant.get_bin_path(),
            # "--color",
            "-i",
            "--seed",
            f"{self.seed}",
            "-ins",
            "-t",
            f"{self.threads}",
            "-b",
            f"{self.batch_size}",
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
            f"{self.list_available_models(self.models_directory)[self.model_idx]}",
            # "--interactive-start",
            "--interactive-first",
        ]
        return command

    def load_model(self):
        """load binary in memory"""
        if self.is_loaded:
            return (
                f"model already loaded {self.list_available_models(self.models_directory)[self.model_idx]}"
            )
        try:
            self.process = Process(self.command, timeout=10000)
            for _ in range(6):
                _ = (
                    [print("ERRoR" * 20), exit(1)]
                    if "error" in self.process.readline().decode("utf-8").lower()
                    else None
                )
            is_loaded = False
            for _ in range(100):
                if is_loaded:
                    continue
                ppt = self.process.read(1)
                is_loaded = b"d" == ppt
            for _ in range(12):
                (self.process.readline())
            self.process.recvuntil(self.end_marker)
            self.current_state = "prompt"

            self.is_loaded = self.list_available_models(self.models_directory)[self.model_idx]
        except Exception as e:
            print(e)
            self.is_loaded = ""
            return f"Failed loading {self.list_available_models(self.models_directory)[self.model_idx]}"

        return f"loaded successfully {self.list_available_models(self.models_directoryh)[self.model_idx]}"

    def unload_model(self):
        if self.is_loaded:
            self.safe_kill()
            self.is_loaded = False

    def action(self, command):
        """returns whether a request can be colmpleted or not"""

        if command == "generate":
            is_possible = self.current_state == "prompt"
        if command == "stop":
            is_possible = self.current_state == "generating"
        return is_possible

    def stop_generation(self):
        """Interrupts generation"""
        if self.current_state == "generating":
            self.current_state = "stoping_generation"
            # self.process.send("\003")
            self.process.interrupt()
            self.current_state = "prompt"
            return "Stopped"

        return f"failed to stop current status {self.current_state}"

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
            self.process.recvuntil("n_batch> ")
            self.process.sendline(str(self.batch_size))
            self.process.recvuntil("antiprompt> ")
            self.process.sendline(str(self.antiprompt))

            for txt in txtblob:
                lines = txt.split("\n")
                lines[-1] += "@end@" if self.use_bos else "@done@"
                self.use_bos = False
                for line in lines:
                    self.process.recvuntil(") :  ")
                    self.process.sendline(line)

            # print(self.process.readline())
            self.current_state = "generating"
        else:
            print("CRITICAL")

    def stream_generation(self):
        """returns a generator that returns the generation"""

        buffer = b""
        marker_detected = b""
        antiprompt_detected = b""
        char_old = b""
        while self.current_state == "generating":
            char = self.process.read(1)
            buffer += char  # update the buffer

            # Detect end of text if detected try to confirm else reset
            if (
                char == self.end_marker.decode()[0].encode("utf-8")
                or len(marker_detected) > 0
            ):
                marker_detected += char
                char_old += char
                # print("==========")
                # print(marker_detected)
                # print(self.end_marker[:len(marker_detected)])
                if marker_detected in self.end_marker[: len(marker_detected)]:
                    # print("cont")
                    continue
                marker_detected = b""
            elif (
                char == self.antiprompt[0].encode("utf-8")
                or len(antiprompt_detected) > 0
            ):
                antiprompt_detected += char
                char_old += char
                # print("==========")
                # print(antiprompt_detected)
                # print(self.end_antiprompt[:len(antiprompt_detected)])
                if antiprompt_detected in self.antiprompt[
                    : len(antiprompt_detected)
                ].encode("utf-8"):
                    # print("cont")
                    continue
                antiprompt_detected = b""

            if self.antiprompt.encode("utf-8") in buffer:
                buffer = buffer.replace(self.antiprompt.encode("utf-8"), b"")
                buffer = buffer[:-1] if buffer[-1] == 10 else buffer
                char_old = char_old.replace(self.antiprompt.encode("utf-8"), b"")
                char_old = char_old[:-1] if char_old[-1] == 10 else char_old

            if self.end_marker in buffer:
                buffer = buffer.replace(self.end_marker, b"")
                char_old += char
                char_old = char_old.replace(self.end_marker, b"")
                self.current_state = "prompt"
                try:
                    res = char_old.decode("utf-8")
                except UnicodeDecodeError:
                    res = f">{str(char_old)}<"
                yield res
                # print(f"\nStream Ended {buffer}")
                break

            try:
                # Load the full character cache
                char = char_old + char

                # print single printable chars
                if len(char) == 1 and char[0] <= 0x7E and char[0] >= 0x21:
                    char = char.decode("utf-8")
                    char_old = b""
                elif len(char) >= 4:
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

    def send_conv(self, preprompt, fmt, prompt):
        """function to simplify interface"""

        if self.old_preprompt is None:
            self.old_preprompt = preprompt
        elif self.old_preprompt is not None and self.old_preprompt != preprompt:
            self.old_preprompt = preprompt
        elif self.old_preprompt == preprompt:
            preprompt = None

        preprompt = preprompt if preprompt is not None else None
        preprompt = self.pre_prompt if self.is_first_request else preprompt

        self.is_first_request = False
        fmt = self.format if fmt is None else fmt
        conv = Conversation(preprompt, fmt, prompt)
        resp = self.chatbot(conv)
        return resp

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
            preprompt = ""

            resp = assistant.send_conv(preprompt, fmt, prompt)

            for char in resp:
                print(char, end="")
            print()


_ = Assistant.repl() if __name__ == "__main__" else None
