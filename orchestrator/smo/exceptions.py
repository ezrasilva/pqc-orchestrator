class UnsupportedConnectionError(Exception):
    """(slice, interface) não mapeia pra nenhuma conexão IPsec real —
    ver smo/service.py `resolve_connection`."""

    def __init__(self, slice, interface):
        super().__init__(f"sem conexão IPsec pra slice={slice} interface={interface}")
        self.slice = slice
        self.interface = interface
