import json
import os

from rich import print as eprint


def load_all_conversations():# -> Dict[str, List[Conversation]]:
    """Load all conversations from chat files in the conversations directory and map the file name to the conversation data"""
    conversations_dict = {}
    for filename in os.listdir(Conversation.SAVE_DIR):
        if filename.endswith(Conversation.FILE_EXTENSION):
            filepath = os.path.join(Conversation.SAVE_DIR, filename)
            conversations = Conversation.load(filename)
            conversations_dict[filename] = Conversation.to_json_multi(conversations)
    return conversations_dict

class Conversation:
    """one interaction back and forth"""

    SAVE_DIR = "conversations"
    FILENAME_PREFIX = "chat"
    FILE_EXTENSION = "json"
    CONVERSATION_COUNTER = 0

    def __init__(
        self,
        preprompt: str = "",
        fmt="",
        instruction: str = "",
        response: str = "",
    ):
        self.format = fmt #if isinstance(fmt, list) else [fmt]
        self.response = response
        self.instruction = instruction
        self.preprompt = preprompt

    def to_json(self):
        return {
            "format": self.format,
            "response": self.response,
            "instruction": self.instruction,
            "preprompt": self.preprompt,
        }

    def get_prompt(self):
        """Return the prompt filled with conversation"""
        convo = []
        data = self.format.format(instruction=self.instruction, response=self.response)
        convo.append(data)
        return convo

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

        with open(os.path.join(Conversation.SAVE_DIR, filename), "w") as file:
            convo_list = []
            for convo in conversations:
                convo_dict = convo.to_json()
                print("************")
                print(convo.to_json())
                convo_list.append(convo_dict)
            json.dump(convo_list, file)



    @staticmethod
    def load(filename: str):# -> List[Conversation]:
        """Load a list of conversations from a file"""
        filepath = os.path.join(Conversation.SAVE_DIR, filename)
        with open(filepath, "r") as file:
            convo_list = json.load(file)
            conversations = []
            for convo_data in convo_list:
                convo = Conversation(
                    fmt=convo_data["format"],
                    response=convo_data["response"],
                    instruction=convo_data["instruction"],
                    preprompt=convo_data["preprompt"],
                )
                conversations.append(convo)
        return conversations


    @staticmethod
    def to_json_multi(conversations): # -> List[Dict[str, Union[str, List[str]]]]:
        """Convert a list of conversations into a JSON equivalent"""
        convo_list = []
        for convo in conversations:
            convo_dict = convo.to_json()
            convo_list.append(convo_dict)
        return convo_list

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
