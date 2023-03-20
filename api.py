# importing the multiprocessing module
# import signal
import time

from alpaca_turbo import Assistant
from flask import Flask, Response, render_template, request

# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

assistant = Assistant()
assistant.prep_model()
app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/ask_bot", methods=["POST"])
def ask_bot():
    question = request.json.get("question")
    print("Question:", question)

    return Response(assistant.ask_bot(question), mimetype="text/plain")

if __name__ == "__main__":
    # both processes finished
    app.run(debug=True)
