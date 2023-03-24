import json
import os

from rich import print as eprint


class Personas:
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


class History:
    """History"""

    def __init__(self, filename):
        self.filename = filename
        if not os.path.exists(filename):
            self.data = []
            self.save()

        self.data = []

    def clean(self):
        self.load()
        while [] in self.data:
            self.data.remove([])
        self.save()
        self.load()

    def strip_n(self):
        new_data = []
        for chat_log in self.data:
            mod_chat_log = []
            for pair in chat_log:
                new_pair = []
                for item in pair:
                    if item:
                        new_pair.append(item.strip(" ").strip("\n"))
                    else:
                        new_pair.append(item)
                mod_chat_log.append(new_pair)
            new_data.append(mod_chat_log)
        self.data = new_data


    def load(self):
        """load"""
        with open(self.filename, "r", encoding="utf-8") as file:
            self.data = json.load(file)
        self.strip_n()

    def save(self):
        """save"""
        self.strip_n()
        with open(self.filename, "w", encoding="utf-8") as file:
            json.dump(self.data, file)

    def __getitem__(self, index):
        self.load()
        return self.data[index]

    def __setitem__(self, index, value):
        self.load()
        if self.data:
            self.data[index] = value
        else:
            self.data.append(value)
        self.save()

    def __delitem__(self, index):
        del self.data[index]

    def __len__(self):
        return len(self.data)

    def __str__(self):
        self.load()
        return str(self.data)

    def __repr__(self):
        self.__str__()

    def append(self, new_item):
        """append"""
        self.load()
        if new_item not in self.data:
            if new_item not in [[],[None,None],[None,None]]:
                self.data.append(new_item)
        self.save()
