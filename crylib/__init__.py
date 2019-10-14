from typing import List
from dataclasses import dataclass

@dataclass
class Constant:
    values: List[bytes]
    description: str = ''

@dataclass
class Result:
    address: int = -1
    description: str = ''
