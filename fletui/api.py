from alpaca_turbo import Assistant
from flask import Flask, Response, jsonify, request

app = Flask(__name__)
assistant = Assistant()


# Set the CSP header to allow POST requests from any origin
@app.after_request
def set_csp_header(response):
    response.headers[
        "Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src *; frame-src 'none'; media-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'self';"
    return response


@app.route("/list_models")
def list_models():
    models = assistant.list_available_models()
    return jsonify(models)


@app.route("/load_model/<int:model_idx>")
def load_model(model_idx):
    assistant.models_idx = model_idx
    assistant.load_model()
    return jsonify({"status": "success"})


@app.route("/send_input", methods=["POST"])
def send_conv():
    data = request.json
    inp = data["inp"]
    fmt = data["fmt"] if "fmt" in data else ""
    preprompt = data["pre"] if "pre" in data else ""

    return Response(assistant.send_conv(preprompt, fmt, inp))


@app.route("/stream_generation")
def stream_generation():
    response = assistant.stream_generation()
    return jsonify(list(response))


@app.route("/stop")
def stop():
    assistant.stop_generation()
    return jsonify({"status": "success"})


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
    app.run()
