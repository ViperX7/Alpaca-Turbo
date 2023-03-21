"""
Interactive library
"""
from pexpect.popen_spawn import PopenSpawn


class Process(PopenSpawn):
    """process"""

    def recvuntil(self, data):
        """Recv data until a pattern is found"""
        data = data if isinstance(data, bytes) else data.encode("latin")
        info = b""
        while data not in info:
            info += self.read(1)
        return info

    def recv(self, *cfg):
        return self.read(*cfg)

    def interactive(self, *cfg):
        return self.interact(*cfg)

    def sendline(self, line):
        self.send(line + "\n")


def main():
    prog = Process("cmd.exe")
    prog.sendline("hi")

    # o = prog.read(1)
    # print(o)
    # input()
    # prog.recvuntil("..............")
    prog.interact()


_ = main() if __name__ == "__main__" else None
