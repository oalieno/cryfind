class Constant:
    def __init__(self, algorithm = '', values = None, description = ''):
        self.algorithm = algorithm
        self.values = values
        if values == None:
            self.values = []
        self.description = description
    def __str__(self):
        text = ''
        if self.algorithm:
            text += self.algorithm
        if self.algorithm and self.description:
            text += ' - '
        if self.description:
            text += self.description
        return text

class Result:
    def __init__(self, constant = None, address = -1):
        self.constant = constant
        if constant == None:
            self.constant = constant
        self.address = address
