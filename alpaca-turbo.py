"""
test
"""
import os
import subprocess
import sys

# pylint: disable=C0103
# pylint: disable=C0114
# pylint: disable=C0116
context = "chat transcript between human and a bot named devil and the bol remembers everything from previous response"
prompt = f"""\"Below is an instruction that describes a task. Write a response that appropriately completes the request."""
prompt = context + prompt
init_prompt = prompt

format = """
###Instruction:
{instruction}

###Response:
"""


seed = 888777
threads = 11
n_predict = 200
threads = 11
top_k = 40
top_p = 0.9
temp = 0.5
repeat_last_n = 64
repeat_penalty = 1.3
model = "alpaca.13B"
model_path = "./models/13B/ggml-model-q4_0.bin"

command = [
    "./main",
    # "--color",
    "-i",
    "--seed",
    f"{seed}",
    "-t",
    f"{threads}",
    "--top_k",
    f"{top_k}",
    "--top_p",
    f"{top_p}",
    "--repeat_last_n",
    f"{repeat_last_n}",
    "--repeat_penalty",
    f"{repeat_penalty}",
    "-m",
    f"{model_path}",
    "--interactive-start",
]

from pwn import process

while True:
    uinp = input("input:  ")
    new_prompt = prompt + "\n\n" + format.format(instruction=uinp)

    program = magic("./main", "")
    program = process(command)
    # program.start(custom=command)
    # pr, wsnd = program.pr, program.wsnd
    program.recvuntil(b".............................................", timeout=10)
    program.recvuntil(b"'\\'.\n")
    print("Model Loaded")

    program.sendline(new_prompt.replace("\n", "\\\n"))
    print("Prompt Sent")

    try:
        data = program.recv(1, timeout=40)
        while True:
            data += program.recv(1)
            if b"[end of text]" in data:
                break
            # print(data)
    except (KeyboardInterrupt, EOFError):
        pass

    new_prompt += data.decode("latin")
    prompt = new_prompt
    print(prompt)
