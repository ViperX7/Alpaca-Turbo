import time

from alpaca_turbo import Assistant
from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from rich.progress import track

app = Flask(__name__)
assistant = Assistant()
CORS(app)

################################
socketio = SocketIO(app)


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
    for value in output:#(output, "Generating"):
        print(value,end="")
        emit("data", f"data: {value}")

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


@app.route("/status")
def status():
    return jsonify({"status": assistant.current_state})


@app.route("/settings")
def settings():
    return jsonify({"settings": assistant.__dict__})


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
    socketio.run(app)
