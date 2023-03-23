"""
Interactive library
"""
import os
from signal import SIGTERM

from pexpect.popen_spawn import PopenSpawn


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

    def kill(self, sig):
        os.remove("pid")
        return super().kill(sig)

    def killx(self):
        return self.kill(SIGTERM)

    def recvuntil(self, data):
        """Recv data until a pattern is found"""
        data = data if isinstance(data, bytes) else data.encode("latin")
        info = b""
        while data not in info:
            info += self.read(1)
            # print(info)
        return info

    def recv(self, *cfg):
        data = self.read(*cfg)
        # print(data)
        return data

    def interactive(self, *cfg):
        return self.interact(*cfg)

    def sendline(self, line):
        msg = line + "\n"
        self.send(msg)


def main():
    prog = Process("cmd.exe")
    prog.sendline("hi")

    # o = prog.read(1)
    # print(o)
    # input()
    # prog.recvuntil("..............")
    prog.interact()


_ = main() if __name__ == "__main__" else None
