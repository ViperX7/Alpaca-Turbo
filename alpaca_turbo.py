"""
Alpaca Turbo
"""
import json
import logging
import os
import platform
import signal

import psutil
from interact import Process as process
from rich.logging import RichHandler
from rich.progress import track
from rich import print as eprint

# from pwn import  process

# pylint: disable=C0103
# pylint: disable=C0114
# pylint: disable=C0116


class AssistantSettings:
    """Settings handler for assistant"""

    def __init__(self, assistant, auto_load=True):
        self.assistant = assistant
        self.load_settings()
        _ = self.assistant.prep_model() if auto_load else None

    def load_settings(self):
        if os.path.exists("settings.dat"):
            with open("settings.dat", "r", encoding="utf-8") as file:
                settings = json.load(file)
            self.update(*settings)
        else:
            print("can't load the settings file continuing with defaults")

    def reload(self):
        self.assistant.is_ready = False
        self.assistant.program.kill(signal.SIGTERM)
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

        if old_settings[1:-3] != new_settings[1:-3] and self.assistant.is_ready:
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

    model_path = "~/dalai/alpaca/models/7B/ggml-model-q4_0.bin"

    def __init__(self, auto_load=True) -> None:
        self.prompt_hit = False
        self.seed = 888777
        self.threads = 4
        self.n_predict = 200
        self.top_k = 40
        self.top_p = 0.9
        self.temp = 0.5
        self.repeat_last_n = 64
        self.repeat_penalty = 1.3
        self.model_path = os.path.expanduser(Assistant.model_path)

        self.persona = "chat transcript between human and a bot named devil and the bot remembers everything from previous response"

        self.prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request."""

        self.format = (
            """\n### Instruction:\n{instruction}\n\n### Response:\n{response}"""
        )
        self.enable_history = True
        self.is_ready = False

        self.settings = AssistantSettings(self, auto_load)

        self.end_marker = b"[end of text]"

        self.chat_history = []

    def reload(self):
        self.program.kill(signal.SIGTERM)
        self.is_ready = False
        self.prep_model()



    @staticmethod
    def get_bin_path():
        if os.path.exists("bin/local"):
            return "bin/local"
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
            "-m",
            f"{self.model_path}",
            "--interactive-start",
        ]
        # print(f"starting with {command}")
        return command

    @property
    def bot_input(self):
        """
        prep_bot_input
        """
        prompt = self.persona + "\n" + self.prompt
        history = self.chat_history if self.enable_history else [self.chat_history[-1]]
        for instr, resp in history:
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
        _ = (
            ""
            if os.path.exists(self.model_path)
            else print("Set the model path in settings")
        )
        if not os.path.exists(self.model_path):
            return

        if os.path.exists("./pid"):
            try:
                with open("./pid") as file:
                    pid = int(file.readline())
                    os.kill(pid, signal.SIGTERM)
                    os.remove("./pid")
            except (ProcessLookupError, FileNotFoundError):
                pass

        self.program = process(self.command, timeout=600)
        self.program.readline()
        self.program.recvuntil(b".")

        model_done = False
        for _ in track(range(40), "Loading Model"):
            data = self.program.recv(1).decode("utf-8") if not model_done else None
            model_done = True if data == "d" else model_done
            if model_done:
                continue
        self.program.recvuntil("\n")
        self.is_ready = True

    def ask_bot(self, question):
        """
        run
        """
        _ = self.prep_model() if not self.is_ready else None

        self.program.recvuntil(">")

        # print("Model Ready to Respond")

        # self.program.recv(1)
        self.chat_history.append((question, ""))
        # print("------")
        # print(self.bot_input)
        # print("------")

        opts = self.bot_input.split("\n")
        # eprint(opts)
        for opt in opts:
            self.program.sendline(opt)

        try:
            marker_detected = b""
            char = self.program.recv(1)
            data = char
            yield char.decode("latin")
            while True:
                char = self.program.recv(1)

                # print(f"app{char}")

                data += char

                if char == b"[" or marker_detected:
                    marker_detected += char
                    if marker_detected in self.end_marker:
                        continue
                    else:
                        marker_detected = b""

                if self.end_marker in data:
                    data = data.replace(b"[end of text]", b"")
                    self.prompt_hit = False
                    break

                yield char.decode("latin")
        except (KeyboardInterrupt, EOFError):
            print("Stooping")

        self.chat_history[-1] = (question, data.decode("utf-8").strip("\n"))

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


def health_checks():
    FORMAT = "%(message)s"
    logging.basicConfig(
        level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
    )
    log = logging.getLogger("rich")

    log.info("Running health checks ")
    test_assistant = Assistant(auto_load=False)

    # check if binary is available for system
    log.info("Checking for dependencies")
    if os.path.exists(Assistant.get_bin_path()):
        log.info("Found binary")
    else:
        log.fatal("Binary Not Found")
        log.info("Check https://github.com/ViperX7/alpaca.cpp")
        log.info("put the compiled file in (./bin/main or ./bin/main.exe )")
        exit()

    log.info("checking if system is supported")
    try:
        prog = process(Assistant.get_bin_path())
        log.info("Supported system")
    except OSError:
        log.fatal("Binary Not supported on this system")
        log.info("Check https://github.com/ViperX7/alpaca.cpp")
        log.info("put the compiled file in (./bin/main or ./bin/main.exe )")
        exit()

    log.info("Looking for the models to load")
    if os.path.exists(os.path.expanduser(Assistant.model_path)):
        log.info(f"Found Model {Assistant.model_path}")
        sz = os.path.getsize(test_assistant.model_path) // (1024 * 1024)
        log.info(f"size of your model is {sz} MB (approx)")
    else:
        log.fatal(
            "model not found you need to download the models and set the model path in settings"
        )

    if os.path.exists("./pid"):
        log.info("Other checks")
        log.fatal("Already running another instance or dirty exit last time")
        with open("./pid") as file:
            pid = int(file.readline())
        log.info("Attempting to kill the process")
        os.kill(pid, signal.SIGTERM)
        os.remove("./pid")
        log.info("Fixed the Issue Now Retry running")
        exit()

    memstat = psutil.virtual_memory()
    log.info("checking memory")
    log.info(f"Total memory {memstat.total//(1024*1024)} MB")
    log.info(f"Used memory {memstat.used//(1024*1024)} MB")
    log.info(f"Free memory {memstat.free//(1024*1024)} MB")
    exit()
    log.level = 5


# health_checks()

assistant = Assistant.repl() if __name__ == "__main__" else None
