class KmsError(Exception):
    """Base de todos os erros do KMS."""


class KeyNotFoundError(KmsError):
    def __init__(self, key_id: str):
        super().__init__(f"chave não encontrada: {key_id}")
        self.key_id = key_id


class InvalidTransitionError(KmsError):
    def __init__(self, key_id: str, from_state, to_state):
        super().__init__(
            f"transição inválida pra chave {key_id}: {from_state.value} -> {to_state.value}"
        )
        self.key_id = key_id
        self.from_state = from_state
        self.to_state = to_state
