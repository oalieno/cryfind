from collections import defaultdict

class DB:
    def __init__(self, description):
        self.description = description
        self.collections = defaultdict(list)
    def add(self, algo, collection):
        self.collections[algo].append(collection)
    def load(self, data):
        for item in data:
            self.add(item['algo'], item['collection'])