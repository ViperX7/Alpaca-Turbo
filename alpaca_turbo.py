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

import django
from rich import print as eprint
from utils.interaction import Process

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "turbo_server.settings")
django.setup()

from ai_model_manager.models import AIModel
from chatbot.models import Conversation, Message


class Assistant:
    def __init__(self, aimodel: AIModel|None = None):

        if aimodel is None:
            print("No model specified using the first one from database")
            aimodel = AIModel.objects.first()

        self.DEBUG = "-d" in sys.argv

        self.model = aimodel
        self.conversation: Conversation = Conversation()
        self.conversation.save()

        # Configurables
        self.threads = 4
        self.use_bos = True
        self.enable_history = False

        self.new_chat()

        # Internal state store
        self.is_loaded = ""
        self.current_state = "Initialised"
        self.old_preprompt = None
        self.is_first_request = True

        # fixed values
        self.end_marker = b"RSTsr"

    def new_chat(self):
        "save current conv and set proper title and start new conv"
        try:
            self.conversation.title = self.conversation[0].ai_response
            self.conversation.save()
        except (IndexError, TypeError):
            pass

        Conversation.clear_blank()
        self.conversation = Conversation()
        self.conversation.title = "New Chat"
        self.conversation.save()

    def remove_all_chat(self):
        r_count = Conversation.remove_all_conv()
        return f"{r_count} files removed"

    def load_chat(self, id):
        """load chat"""
        data = {"can't load generation going on"}
        if self.current_state != "generating":
            data = Conversation.objects.filter(id=id).first()
            data = list(data)
        return data

    def get_conv_logs(self):
        """conversation logs"""
        data = Conversation.get_all_conversations()
        return data

    def remove_chat(self, uuid):
        """-"""
        uuid = str(uuid)
        print(uuid)
        if uuid != str(self.conversation.id):
            Conversation.objects.filter(id=uuid).delete()

    def clear_chat(self):
        """clear current history context"""
        result = "can't save generation going on"
        if self.current_state != "generating":
            self.conversation = Conversation()
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
        if self.conversation:
            Conversation.save(self.conversation)
        self.conversation = Conversation()
        self.is_loaded = ""

        return "killed the bot"

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
            f"{self.model.settings.seed}",
            "-ins",
            "-t",
            f"{self.threads}",
            "-b",
            f"{self.model.settings.batch_size}",
            "--top_k",
            f"{self.model.settings.top_k}",
            "--top_p",
            f"{self.model.settings.top_p}",
            "--repeat_last_n",
            f"{self.model.settings.repeat_last_n}",
            "--repeat_penalty",
            f"{self.model.settings.repetition_penalty}",
            "--temp",
            f"{self.model.settings.temperature}",
            "--n_predict",
            f"{self.model.settings.n_predict}",
            "-m",
            f"{self.model.path}",
            # "--interactive-start",
            "--interactive-first",
        ]
        return command

    def load_model(self):
        """load binary in memory"""
        if self.is_loaded:
            return f"model already loaded {self.model.path}"
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

            self.is_loaded = self.model.path
        except Exception as e:
            print(e)
            self.is_loaded = ""
            return f"Failed loading {self.model.path}"

        return f"loaded successfully {self.model.path}"

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

    def chatbot(self, message: Message):
        """Adds history support"""
        # self.conversation.append(prompt)
        # build history chahe
        final_prompt_2_send = []

        data2use = self.conversation if self.enable_history else [message]
        for convo in data2use:
            for sequence in convo.get_prompt():
                final_prompt_2_send.append(sequence)

        final_prompt_2_send = "".join(final_prompt_2_send)
        if message.preprompt:
            final_prompt_2_send = [message.preprompt, final_prompt_2_send]
        self.send_prompts(final_prompt_2_send)

        for char in self.stream_generation():
            message.ai_response += char
            message.save()
            yield char

    def completion(self, prompt: Message, count=-1):
        """ add completion support"""
        final_prompt_2_send = [prompt.user_request]

        final_prompt_2_send = "".join(final_prompt_2_send)
        self.send_prompts(final_prompt_2_send)

        sp_count = 0
        for char in self.stream_generation():
            sp_count += 1 if " " in char else 0
            if sp_count >= count:
                self.stop_generation()  # this sometimes misses a word or two
                # return char
            prompt.ai_response += char
            prompt.save()
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
            self.process.sendline(str(self.model.settings.top_k))
            self.process.recvuntil("top_p> ")
            self.process.sendline(str(self.model.settings.top_p))
            self.process.recvuntil("temperature> ")
            self.process.sendline(str(self.model.settings.temperature))
            self.process.recvuntil("repeat_penalty> ")
            self.process.sendline(str(self.model.settings.repetition_penalty))
            self.process.recvuntil("n_batch> ")
            self.process.sendline(str(self.model.settings.batch_size))
            self.process.recvuntil("antiprompt> ")
            self.process.sendline(str(self.model.prompt.antiprompt))

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
                char == self.model.prompt.antiprompt[0].encode("utf-8")
                or len(antiprompt_detected) > 0
            ):
                print("Antiprompt buffering started")
                antiprompt_detected += char
                char_old += char
                # print("==========")
                # print(antiprompt_detected)
                # print(self.end_antiprompt[:len(antiprompt_detected)])
                if antiprompt_detected in self.model.prompt.antiprompt[
                    : len(antiprompt_detected)
                ].encode("utf-8"):
                    # print("cont")
                    continue
                antiprompt_detected = b""

            if self.model.prompt.antiprompt.encode("utf-8") in buffer:
                buffer = buffer[:-1] if buffer[-1] == 10 else buffer
                char_old = char_old.replace(
                    self.model.prompt.antiprompt.encode("utf-8"), b""
                )
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

    def sane_check_msg(self, msg):
        if self.old_preprompt is None:
            self.old_preprompt = msg.preprompt
        elif self.old_preprompt is not None and self.old_preprompt != msg.preprompt:
            self.old_preprompt = msg.preprompt
        elif self.old_preprompt == msg.preprompt:
            msg.preprompt = None

        msg.preprompt = msg.preprompt if msg.preprompt is not None else None
        msg.preprompt = (
            self.model.prompt.preprompt if self.is_first_request else msg.preprompt
        )

        self.is_first_request = False
        msg.format = self.model.prompt.format if msg.format is None else msg.format
        return msg

    def send_conv(self, preprompt, fmt, prompt):
        """function to simplify interface"""

        msg = self.conversation.add_message(prompt, preprompt=preprompt, format=fmt)
        msg = self.sane_check_msg(msg)

        resp = self.chatbot(msg)
        return resp

    @staticmethod
    def repl():
        """Repl for my chat bot"""
        assistant = Assistant(AIModel.objects.all()[1])
        assistant.load_model()
        assistant.enable_history = False
        fmt = assistant.model.prompt.format
        # assistant.pre_prompt = ""
        preprompt = assistant.model.prompt.preprompt
        while True:
            # print("=====")
            prompt = input(">>>>>> ")
            preprompt = ""

            resp = assistant.send_conv(preprompt, fmt, prompt)

            for char in resp:
                print(char, end="")
            print()


_ = Assistant.repl() if __name__ == "__main__" else None
