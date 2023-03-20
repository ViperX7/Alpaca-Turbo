"""
Alpaca Turbo
"""
import os
import subprocess
import sys

from pwn import context, process
from rich.progress import track

context.log_level = "critical"

# pylint: disable=C0103
# pylint: disable=C0114
# pylint: disable=C0116

class Assistant:
    """Alpaca Assistant"""

    def __init__(self) -> None:
        self.seed = 888777
        self.threads = 11
        self.n_predict = 200
        self.threads = 16
        self.top_k = 40
        self.top_p = 0.9
        self.temp = 0.5
        self.repeat_last_n = 64
        self.repeat_penalty = 1.3
        self.model = "alpaca.13B"
        self.model_path = "~/dalai/alpaca/models/13B/ggml-model-q4_0.bin"
        self.model_path = "~/dalai/alpaca/models/7B/ggml-model-q4_0.bin"
        self.executable = "./bin/main"
        self.model_path = os.path.expanduser(self.model_path)
        self.executable = os.path.expanduser(self.executable)

        self.persona = "chat transcript between human and a bot named devil and the bol remembers everything from previous response"

        self.prompt = f"""Below is an instruction that describes a task. Write a response that appropriately completes the request."""

        self.format =  """\n###Instruction:\n{instruction}\n\n###Response:\n{response}"""
        self.enable_history = True



        self.chat_history = []
        self.is_ready = False

    @property
    def command(self):
        command = [
            self.executable,
            # "--color",
            "-i",
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
            prompt += self.format.format(instruction=instr, response=resp)
        prompt = prompt.replace("\n", "\\\n")
        print("======")
        print(prompt)
        print("======")
        return prompt

    def prep_model(self):
        if self.is_ready:
            return None
        self.program = process(self.command)
        for _ in track(range(45), "Loading Model"):
            self.program.recvuntil(b".", timeout=10)
        self.program.recvuntil(b"'\\'.\n")
        # print("Model Ready to respond")
        self.is_ready = True

    def ask_bot(self, question):
        """
        run
        """
        _ = self.prep_model() if not self.is_ready else None
        self.program.recvuntil(b"REPLERP\n")
        self.chat_history.append((question, ""))
        # print("------")
        # print(self.bot_input)
        # print("------")

        self.program.sendline(self.bot_input.encode())
        self.end_marker = b"[end of text]"

        try:
            marker_detected = b""
            char = self.program.recv(1, timeout=40)
            data = char
            yield char.decode("latin")
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

                yield char.decode("latin")
        except (KeyboardInterrupt, EOFError):
            print("Stooping")

        # self.program.kill()
        # self.is_ready = False

        self.chat_history[-1] = (question, data)
        return data

    @staticmethod
    def repl():
        assistant = Assistant()
        assistant.prep_model()
        while True:
            resp = assistant.ask_bot(input(">>> "))

            for char in resp:
                print(char, end="")
            print()


_ = Assistant.repl() if __name__ == "__main__" else None
