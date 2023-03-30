import json
import os


class Conversation:
    """one interaction back and forth"""

    SAVE_DIR = "conversations"
    FILENAME_PREFIX = "chat"
    FILE_EXTENSION = "json"
    CONVERSATION_COUNTER = 0

    def __init__(
        self,
        preprompt: str = "",
        fmt=[""],
        instruction: str = "",
        response: str = "",
    ):
        self.format = fmt if isinstance(fmt, list) else [fmt]
        self.response = response
        self.instruction = instruction
        self.preprompt = preprompt

    def get_prompt(self):
        """Return the prompt filled with conversation"""
        convo = []
        for data in self.format:
            data = data.format(instruction=self.instruction, response=self.response)
            convo.append(data)
        return convo

    @staticmethod
    def load():  # -> dict[str, list["Conversation"]]:
        """Load a list of conversations and return as a dictionary"""
        convo_dict = {}
        for filename in os.listdir(Conversation.SAVE_DIR):
            if filename.endswith(Conversation.FILE_EXTENSION):
                with open(os.path.join(Conversation.SAVE_DIR, filename), "r") as f:
                    convo_data = json.load(f)
                    fmt = convo_data["format"]
                    instruction = convo_data["instruction"]
                    response = convo_data["response"]
                    preprompt = convo_data["preprompt"]
                    convo_list = [
                        Conversation(fmt, instruction, response, preprompt)
                        for convo_data in convo_data
                    ]
                    convo_dict[filename] = convo_list
        return convo_dict

    @staticmethod
    def save(conversations):  # list["Conversation"]) -> None:
        """Save a list of conversations"""
        if not os.path.exists(Conversation.SAVE_DIR):
            os.makedirs(Conversation.SAVE_DIR)
        Conversation.CONVERSATION_COUNTER += 1
        filename = f"{Conversation.FILENAME_PREFIX}{Conversation.CONVERSATION_COUNTER}.{Conversation.FILE_EXTENSION}"
        while os.path.exists(os.path.join(Conversation.SAVE_DIR, filename)):
            Conversation.CONVERSATION_COUNTER += 1
            filename = f"{Conversation.FILENAME_PREFIX}{Conversation.CONVERSATION_COUNTER}.{Conversation.FILE_EXTENSION}"
        with open(os.path.join(Conversation.SAVE_DIR, filename), "w") as f:
            convo_list = []
            for convo in conversations:
                convo_dict = {
                    "format": convo.format,
                    "instruction": convo.instruction,
                    "response": convo.response,
                    "preprompt": convo.preprompt,
                }
                convo_list.append(convo_dict)
            json.dump(convo_list, f)

    @staticmethod
    def remove_file(filename: str) -> None:
        """Remove a conversation file with the given name"""
        filepath = os.path.join(Conversation.SAVE_DIR, filename)
        os.remove(filepath)


class Personas:
    """Persona"""

    def __init__(self, filename):
        if not os.path.exists(filename):
            self.data = []
            self.save()

        self.filename = filename
        self.load()

    def load(self):
        with open(self.filename, "r") as f:
            self.bots = json.load(f)

    def save(self):
        with open(self.filename, "w") as f:
            json.dump(self.bots, f)

    def add(self, name, data):
        self.bots[name] = data
        self.save()

    def update(self, name, data):
        if name in self.bots:
            self.bots[name] = data
            self.save()

    def get_all(self):
        return list(self.bots.keys())

    def get(self, name):
        if name in self.bots:
            # eprint(self.bots[name])
            return list(self.bots[name].values())
        return None
