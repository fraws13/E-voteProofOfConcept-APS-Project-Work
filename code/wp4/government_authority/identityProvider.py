class IdentityProvider:
    """Modulo IP (Identity Provider): Gestisce l'autenticazione dell'identità reale."""

    def __init__(self, registered_users: set[str]) -> None:
        # In uno scenario reale, questo conterrebbe hash di password o interfacce verso SPID/CIE
        #crea un set degli utenti che sono registrati
        self._registered_users = registered_users

    def authenticate_internal(self, user_id: str) -> bool:
        """Verifica se l'utente esiste nel registro interno."""
        return user_id in self._registered_users