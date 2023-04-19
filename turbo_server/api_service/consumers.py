import json

from channels.generic.websocket import WebsocketConsumer

from . import api_assistant


class TestConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json["message"]

        self.send(text_data=json.dumps({"message": message}))


class ChatConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        print(text_data)
        text_data = json.loads(text_data)
        preprompt = ""
        fmt = api_assistant.ASSISTANT.model.prompt.format
        inp = text_data["message"]
        generator = api_assistant.ASSISTANT.send_conv(preprompt, fmt, inp)
        for res in generator:
            self.send(text_data=json.dumps({"message": res}))
