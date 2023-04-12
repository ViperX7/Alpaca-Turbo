#!/bin/python
"""
     ▄▄▄· ▄▄▌   ▄▄▄· ▄▄▄·  ▄▄·  ▄▄▄·     ▄▄▄▄▄▄• ▄▌▄▄▄  ▄▄▄▄·       
    ▐█ ▀█ ██•  ▐█ ▄█▐█ ▀█ ▐█ ▌▪▐█ ▀█     •██  █▪██▌▀▄ █·▐█ ▀█▪▪     
    ▄█▀▀█ ██▪   ██▀·▄█▀▀█ ██ ▄▄▄█▀▀█      ▐█.▪█▌▐█▌▐▀▀▄ ▐█▀▀█▄ ▄█▀▄ 
    ▐█ ▪▐▌▐█▌▐▌▐█▪·•▐█ ▪▐▌▐███▌▐█ ▪▐▌     ▐█▌·▐█▄█▌▐█•█▌██▄▪▐█▐█▌.▐▌
     ▀  ▀ .▀▀▀ .▀    ▀  ▀ ·▀▀▀  ▀  ▀      ▀▀▀  ▀▀▀ .▀  ▀·▀▀▀▀  ▀█▄▀▪

https;//github.comViperX7/Alpaca-Turbo
"""
import mimetypes
import psutil
from alpaca_turbo import Assistant
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from helpers.prompts import Personas

mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('text/css', '.css')

app = Flask(
    __name__,
    static_url_path="",
    static_folder="templates",
)
assistant = Assistant()

################################
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")
personas = Personas("./prompts.json")


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
    buffer = ""
    for value in output:  # (output, "Generating"):
        buffer += value
        emit("data", value)
    print("=====LOG=====")
    print(buffer)
    print("=====LOG=====")


@app.route("/unload")
def unload_model():
    result = assistant.safe_kill()
    return jsonify({"result": result})


@app.route("/remove_all_chat")
def remove_all_chat():
    result = assistant.remove_all_chat()
    return jsonify({"result": result})


########################


@app.route("/list_models")
def list_models():
    models = assistant.list_available_models()
    return jsonify(models)


@app.route("/load_model/<int:model_idx>")
def load_model(model_idx):
    assistant.model_idx = model_idx
    assistant.unload_model()
    resp = assistant.load_model()
    return jsonify({"status": resp})


@app.route("/stop")
def stop():
    res = assistant.stop_generation()
    return jsonify({"status": res})


@app.route("/status")
def status():
    cpu_percent = psutil.cpu_percent()
    ram_usage = psutil.virtual_memory().percent
    total_ram = psutil.virtual_memory().total / (1024**3)  # convert to GB
    total_cores = psutil.cpu_count(logical=False)
    total_threads = psutil.cpu_count(logical=True)
    # threads_above_80 = len(
    #     [
    #         thread
    #         for thread in psutil.process_iter(attrs=["pid", "name", "cpu_percent"])
    #         if thread.info["cpu_percent"] > 80
    #     ]
    # )
    return jsonify(
        {
            "cpu_percent": cpu_percent,
            "ram_usage": ram_usage,
            "total_ram": total_ram,
            "total_cores": total_cores,
            "total_threads": total_threads,
            # "threads_above_80": threads_above_80,
            "is_model_loaded": assistant.is_loaded,
            "turbo_status": assistant.current_state,
        }
    )


@app.route("/config", methods=["GET"])
def get_config():
    return jsonify(
        {
            "threads": assistant.threads,
            "top_k": assistant.top_k,
            "top_p": assistant.top_p,
            "temp": assistant.temp,
            "repeat_penalty": assistant.repeat_penalty,
            "seed": assistant.seed,
            "n_predict": assistant.n_predict,
            "repeat_last_n": assistant.repeat_last_n,
            "batch_size": assistant.batch_size,
            "antiprompt": assistant.antiprompt,
        }
    )


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
    assistant.batch_size = data.get("batch_size", assistant.batch_size)
    assistant.antiprompt = data.get("antiprompt", assistant.antiprompt)
    return jsonify({"success": True})


@app.route("/load_chat/<string:id>", methods=["GET"])
def load_chat(id):
    result = assistant.load_chat(id)
    try:
        new_res = [res.to_json() for res in result]
    except AttributeError:
        new_res = result
    return jsonify(new_res)


@app.route("/save_chat")
def save_chat():
    result = assistant.save_chat()
    return jsonify(result)


@app.route("/get_conv_logs", methods=["GET"])
def get_conv_logs():
    result = assistant.get_conv_logs()
    return jsonify(result)


@app.route("/clear_chat", methods=["GET"])
def clear_chat():
    result = assistant.clear_chat()
    return jsonify(result)


@app.route("/personas", methods=["GET"])
def get_personas():
    personas_list = personas.get_all()
    return jsonify(personas_list)


@app.route("/personas/<string:name>", methods=["GET"])
def get_persona(name):
    persona_data = personas.get(name)
    if persona_data:
        return jsonify(persona_data)
    else:
        return jsonify({"error": "Persona not found."})


@app.route("/personas", methods=["POST"])
def add_persona():
    data = request.json
    if "name" not in data or "data" not in data:
        return jsonify({"error": "Name and data fields are required."})
    name = data["name"]
    persona_data = data["data"]
    personas.add(name, persona_data)
    return jsonify({"success": True})


@app.route("/personas/<string:name>", methods=["PUT"])
def update_persona(name):
    data = request.json
    persona_data = data["data"]
    personas.update(name, persona_data)
    return jsonify({"success": True})


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        allow_unsafe_werkzeug=True,
        debug=True,
    )
