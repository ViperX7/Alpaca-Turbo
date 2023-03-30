import time

from alpaca_turbo import Assistant
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from rich.progress import track

app = Flask(__name__)
assistant = Assistant()

################################
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="http://localhost:4200")


@socketio.on("connect")
def test_connect():
    print("Socket connected")


@socketio.on("disconnect")
def test_disconnect():
    print("socket disconnected")


@socketio.on("send_input")
def send_conv(data):
    inp = data["inp"]
    fmt = data.get("fmt", "")
    preprompt = data.get("pre", "")
    output = assistant.send_conv(preprompt, fmt, inp)
    print("Attempting to GENERATE======================")
    for value in output:  # (output, "Generating"):
        print(value, end="")
        emit("data", value)


@socketio.on("test")
def send_conv():
    print("TEXTEXTE")


########################


@app.route("/list_models")
def list_models():
    models = assistant.list_available_models()
    return jsonify(models)


@app.route("/load_model/<int:model_idx>")
def load_model(model_idx):
    assistant.models_idx = model_idx
    resp = assistant.load_model()
    return jsonify({"status": resp})


@app.route("/stop")
def stop():
    res = assistant.stop_generation()
    return jsonify({"status": res})


import psutil


@app.route("/status")
def status():
    cpu_percent = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    total_ram = psutil.virtual_memory().total / (1024**3)  # convert to GB
    total_cores = psutil.cpu_count(logical=False)
    total_threads = psutil.cpu_count(logical=True)
    threads_above_80 = len(
        [
            thread
            for thread in psutil.process_iter(attrs=["pid", "name", "cpu_percent"])
            if thread.info["cpu_percent"] > 80
        ]
    )
    return jsonify(
        {
            "cpu_percent": cpu_percent,
            "ram_usage": ram_usage,
            "total_ram": total_ram,
            "total_cores": total_cores,
            "total_threads": total_threads,
            "threads_above_80": threads_above_80,
            "is_model_loaded": assistant.is_loaded,
            "turbo_status": assistant.current_state,
        }
    )


@app.route("/config", methods=["GET"])
def get_config():
    return jsonify({
        "threads": assistant.threads,
        "top_k": assistant.top_k,
        "top_p": assistant.top_p,
        "temp": assistant.temp,
        "repeat_penalty": assistant.repeat_penalty,
        "seed": assistant.seed,
        "n_predict": assistant.n_predict,
        "repeat_last_n": assistant.repeat_last_n
    })

@app.route("/config", methods=["POST"])
def set_config():
    data = request.get_json()
    assistant.threads = data.get("threads", assistant.threads)
    assistant.top_k = data.get("top_k", assistant.top_k)
    assistant.top_p = data.get("top_p", assistant.top_p)
    assistant.temp = data.get("temp", assistant.temp)
    assistant.repeat_penalty = data.get("repeat_penalty", assistant.repeat_penalty)
    assistant.seed = data.get("seed", assistant.seed)
    assistant.n_predict = data.get("n_predict", assistant.n_predict)
    assistant.repeat_last_n = data.get("repeat_last_n", assistant.repeat_last_n)
    return jsonify({"success": True})



@app.route("/chat_history")
def chat_history():
    return jsonify({"chat_history": assistant.chat_history})


@app.route("/save_chat", methods=["POST"])
def save_chat():
    data = request.json
    assistant.save_chat(data)
    return jsonify({"status": "success"})


@app.route("/chat/<int:persona_id>")
def chat(persona_id):
    response = assistant.chat_with_persona(persona_id)
    return jsonify(response)


@app.route("/get_personas")
def get_personas():
    personas = assistant.get_personas()
    return jsonify(personas)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", allow_unsafe_werkzeug=True, debug=True)
