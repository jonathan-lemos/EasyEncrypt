from abc import ABC, abstractmethod
from typing import Any, Dict, List, Union


class Kdf(ABC):
    @abstractmethod
    def derive(self, password: str, out_len: int) -> bytes:
        pass

    @abstractmethod
    def serialize(self) -> Dict[str, Union[str, int, bool, None, Dict, List]]:
        pass

    @staticmethod
    @abstractmethod
    def deserialize(props: Dict[str, Union[str, int, bool, None, Dict, List]]) -> "Kdf":
        pass
