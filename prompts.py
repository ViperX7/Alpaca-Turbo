import json


class Personas:
    def __init__(self, filename):
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
            return list(self.bots[name].values())
        return None
