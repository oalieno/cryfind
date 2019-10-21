from typing import List
from dataclasses import dataclass, field

@dataclass
class Constant:
    algorithm: str = ''
    values: List[bytes] = field(default_factory = list)
    description: str = ''

@dataclass
class Result:
    constant: Constant
    address: int = -1
