from collections import defaultdict
from .. import Constant

class DB:
    def __init__(self, description):
        self.description = description
        self.constants = defaultdict(list)
    def load(self, data):
        for item in data:
            algo = item['algo']
            values = item['constant']['values']
            description = item['constant']['description']
            self.constants[algo].append(Constant(algorithm = algo, values = values, description = description))
