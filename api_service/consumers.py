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
        inp = text_data["message"]
        preprompt = text_data["preprompt"] if "preprompt" in text_data else api_assistant.ASSISTANT.model.prompt.preprompt
        fmt = text_data["format"] if "format" in text_data else api_assistant.ASSISTANT.model.prompt.format
        generator = api_assistant.ASSISTANT.send_conv(preprompt, fmt, inp)
        for res in generator:
            self.send(text_data=json.dumps({"message": res}))
