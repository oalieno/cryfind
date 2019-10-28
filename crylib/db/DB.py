from collections import defaultdict
from .. import Constant

class DB:
    def __init__(self, description):
        self.description = description
        self.constants = []
    def load(self, data):
        for item in data:
            algorithm = item['algorithm']
            values = item['constant']['values']
            description = item['constant']['description']
            self.constants.append(Constant(algorithm = algorithm,values = values, description = description))
