from typing import List
from dataclasses import dataclass, field

@dataclass
class Constant:
    algorithm: str = ''
    values: List[bytes] = field(default_factory = list)
    description: str = ''
    def __str__(self):
        text = ''
        if self.algorithm:
            text += self.algorithm
        if self.algorithm and self.description:
            text += ' - '
        if self.description:
            text += self.description
        return text

@dataclass
class Result:
    constant: Constant
    address: int = -1
