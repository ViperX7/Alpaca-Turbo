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

    def clean(self):
        self.load()
        while [] in self.data:
            self.data.remove([])
        self.save()
        self.load()

    def __init__(self, filename):
        if not os.path.exists(filename):
            self.data = []
            self.save()

        self.filename = filename
        self.data = []

    def load(self):
        """load"""
        with open(self.filename, "r", encoding="utf-8") as file:
            self.data = json.load(file)

    def save(self):
        """save"""
        with open(self.filename, "w", encoding="utf-8") as file:
            json.dump(self.data, file)

    def __getitem__(self, index):
        self.load()
        return self.data[index]

    def __setitem__(self, index, value):
        self.load()
        self.data[index] = value
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
            self.data.append(new_item)
        self.save()
