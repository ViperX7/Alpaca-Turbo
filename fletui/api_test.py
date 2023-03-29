import requests
from rich import print as eprint

sess = requests.Session()

URL = "http://localhost:5000/"

# List Available models
resp = sess.get(URL + "list_models")
msg = f"Testing list_models ({resp.status_code})"
eprint(msg)
eprint("\t\t" + str(resp.json()))

# Load a model
endpoint = "load_model"
idx = 0

resp = sess.get(URL + endpoint + "/0")
msg = f"Testing {endpoint} ({resp.status_code})"
eprint(msg)
eprint("\t\t" + str(resp.json()))

# Send atest input
endpoint = "send_input"
data = {
    "inp": "hi",
    "pre": "",
    "fmt": "### Instruction:\n\n{instruction}\n\n### Response:\n\n{response}",
}

resp = sess.post(URL + endpoint, json=data)
msg = f"Testing {endpoint} ({resp.status_code})"
eprint(resp.text)

# Send another input
endpoint = "send_input"
data = {
    "inp": "give me a thumbs up emoji",
    "pre": "",
    "fmt": "### Instruction:\n\n{instruction}\n\n### Response:\n\n{response}",
}

resp = sess.post(URL + endpoint, json=data)
msg = f"Testing {endpoint} ({resp.status_code})"
eprint(resp.text)












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
