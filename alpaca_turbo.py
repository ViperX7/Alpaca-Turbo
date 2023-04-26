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
import time

import django
from rich import print as eprint
from utils.interaction import Process

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "turbo_server.settings")
django.setup()

from ai_model_manager.models import AIModel
from chatbot.models import Conversation, Message


class Assistant:
    def __init__(self, aimodel: AIModel | None = None):
        if aimodel is None:
            print("No model specified using the first one from database")
            aimodel = AIModel.objects.first()

        self.DEBUG = "-d" in sys.argv

        self.model :AIModel= aimodel
        self.settings = self.model.settings
        self.prompt = self.model.prompt
        self.conversation: Conversation = Conversation()
        self.conversation.save()
        self.last_in_mem = 0

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

    def new_chat(self, conv:Conversation=None):
        "save current conv and set proper title and start new conv"
        try:
            self.conversation.title = " ".join(self.conversation[0].ai_response.split(" ")[:6])
            self.conversation.save()
        except (IndexError, TypeError):
            pass

        Conversation.clear_blank()

        self.conversation = conv if conv else Conversation()
        if not conv:
            setattr(self.conversation,"title","New Chat")
            self.conversation.save()

    def remove_all_chat(self):
        r_count = Conversation.remove_all_conv()
        return f"{r_count} files removed"

    def load_chat(self, id):
        """load chat"""
        # data = {"can't load generation going on"}
        # if self.current_state != "generating":
        conv = Conversation.objects.filter(id=id).first()
        self.conversation = conv
        data = list(conv)
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
            self.conversation.save()
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
            self.conversation.save()
        self.is_loaded = ""

        return "killed the bot"

    @staticmethod
    def get_bin_path():
        system_name = platform.system()
        if os.path.exists("bin/cmain"):
            name = "bin/cmain"
        elif system_name == "Linux":
            name = "bin/main"
        elif system_name == "Windows":
            name = "bin/main.exe"
        elif system_name == "Darwin":
            name = "bin/mac"
        else:
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXX    CHAT BINARY MISSING    XXXXXXXXXXXXXXXXX")
            print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            exit()

        return name

    @property
    def command(self):
        command = [
            Assistant.get_bin_path(),
            # "--color",
            "-i",
            "--seed",
            f"{self.settings.seed}",
            "-ins",
            "-t",
            f"{self.threads}",
            "-b",
            f"{self.settings.batch_size}",
            "--top_k",
            f"{self.settings.top_k}",
            "--top_p",
            f"{self.settings.top_p}",
            "--repeat_last_n",
            f"{self.settings.repeat_last_n}",
            "--repeat_penalty",
            f"{self.settings.repetition_penalty}",
            "--temp",
            f"{self.settings.temperature}",
            "--n_predict",
            f"{self.settings.n_predict}",
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
