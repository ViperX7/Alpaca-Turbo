"""
Interactive library
"""
import os
import sys
from signal import SIGINT, SIGTERM

from colorama import Fore
from pexpect.popen_spawn import PopenSpawn
from rich import print as eprint


def log(text):
    with open("./turbo.log", "a", encoding="utf-8") as file:
        file.write(text)


class Process(PopenSpawn):
    """process"""

    def __init__(
        self,
        cmd,
        timeout=30,
        maxread=2000,
        searchwindowsize=None,
        logfile=None,
        cwd=None,
        env=None,
        encoding=None,
        codec_errors="strict",
        preexec_fn=None,
    ):
        super().__init__(
            cmd,
            timeout,
            maxread,
            searchwindowsize,
            logfile,
            cwd,
            env,
            encoding,
            codec_errors,
            preexec_fn,
        )
        with open("./pid", "w", encoding="utf-8") as file:
            file.writelines([str(self.pid)])

        self.debug = True
        eprint(cmd)

    def interrupt(self):
        """kill the process with sigterm"""
        super().kill(SIGINT)
        return "done"

    def kill(self, sig):
        os.remove("pid")
        return super().kill(sig)

    def killx(self):
        """kill the process with sigterm"""
        return self.kill(SIGTERM)

    def recvuntil(self, data):
        """Recv data until a pattern is found"""
        data = data if isinstance(data, bytes) else data.encode("utf-8")
        info = b""
        while data not in info:
            info += self.read(1)
        return info

    def read(self, size=-1):
        data = super().read(size)
        _ = (
            log(
                Fore.RED
                + str(data)[2:-1]
                + Fore.RESET
                # end="" if data[-1] != b"\n" else "\n",
            )
            if self.debug
            else None
        )
        return data

    def readline(self, size=-1):
        data = super().readline(size)
        _ = log(Fore.BLUE + str(data)[2:-1] + Fore.RESET) if self.debug else None
        return data

    def send(self, s):
        data = s.encode("utf-8") if isinstance(s, str) else s
        _ = log(Fore.GREEN + str(data) + Fore.RESET) if self.debug else None
        data = super().send(data)
        # print(data)
        return data

    # def interactive(self, *cfg):
    #     return self.interactive(*cfg)

    def sendline(self, line):
        line = line.encode("utf-8") if isinstance(line, str) else line
        msg = line + b"\n"
        self.send(msg)


def main():
    prog = Process("cat")
    prog.sendline("hi")
    print(prog.recvuntil("hi"))

    # o = prog.read(1)
    # print(o)
    # input()
    # prog.recvuntil("..............")
    prog.send(chr(27) + chr(79) + chr(83))

    prog.sendline("hi")
    print(prog.recvuntil("hi"))


_ = main() if __name__ == "__main__" else None
