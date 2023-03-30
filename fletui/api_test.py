import sys

import requests
from rich import print as eprint

sess = requests.Session()

URL = "http://localhost:5000/"


# get stats
def status():
    endpoint = "status"
    idx = 0

    resp = sess.get(URL + endpoint)
    msg = f"Testing {endpoint} ({resp.status_code})"
    eprint(msg)
    eprint("\t\t" + str(resp.json()))


def list_models():
    "List Available models"
    resp = sess.get(URL + "list_models")
    msg = f"Testing list_models ({resp.status_code})"
    eprint(msg)
    eprint("\t\t" + str(resp.json()))


# Load a model
def load_model():
    endpoint = "load_model"
    idx = 0

    resp = sess.get(URL + endpoint + "/0")
    msg = f"Testing {endpoint} ({resp.status_code})"
    eprint(msg)
    eprint("\t\t" + str(resp.json()))


# Stop generation
def stop_generation():
    endpoint = "stop"
    idx = 0
    resp = sess.get(URL + endpoint)
    msg = f"Testing {endpoint} ({resp.status_code})"
    eprint(msg)
    eprint("\t\t" + str(resp.json()))


######################################
def get_generations():
    import socketio

    sio = socketio.Client()

    @sio.on("connect")
    def on_connect():
        print("Connected to server")

    @sio.on("disconnect")
    def on_disconnect():
        print("Disconnected from server")

    @sio.on("data")
    def on_data(data):
        print(data, end="")

    sio.connect("http://localhost:5000")

    sio.emit("test")
    print("OOKO")
    inp = {"inp": "write an promotion email", "fmt": None, "pre": None}
    _ = sio.emit("send_input", inp) if "KK" in sys.argv else None
    print("OOKO")

    sio.wait()


status()
list_models()
load_model()
get_generations()

######################################

# # Send atest input
# endpoint = "send_input"
# data = {
#     "inp": "hi",
#     "pre": "",
#     "fmt": "### Instruction:\n\n{instruction}\n\n### Response:\n\n{response}",
# }
#
# resp = sess.post(URL + endpoint, json=data)
# msg = f"Testing {endpoint} ({resp.status_code})"
# eprint(resp.text)
#
# # Send another input
# endpoint = "send_input"
# data = {
#     "inp": "give me a thumbs up emoji",
#     "pre": "",
#     "fmt": "### Instruction:\n\n{instruction}\n\n### Response:\n\n{response}",
# }
#
# resp = sess.post(URL + endpoint, json=data)
# msg = f"Testing {endpoint} ({resp.status_code})"
# eprint(resp.text)

# stream generation
# Load a model
# endpoint = "stream_generation"
#
# resp = sess.get(URL + endpoint)
# msg = f"Testing {endpoint} ({resp.status_code})"
# eprint(msg)
# print("_____")
# print(resp.text)
# print(resp.text)
# print(resp.text)
# print("-----")
# print(resp.text)
# eprint("\t\t" + str(resp.json()))
