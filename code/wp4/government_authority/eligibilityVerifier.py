class EligibilityVerifier:
    """Modulo EV (Eligibility Verifier): Verifica il diritto di voto."""
    #il modulo EV è responsabile per verificare se un utente ha i requisiti per partecipare all'elezione

    def __init__(self, eligible_users: set[str]) -> None:
        self._eligible_users = eligible_users
        #crea un set degli utenti che sono eligibili per votare

    def is_eligible(self, user_id: str) -> bool:
        """Verifica se l'utente possiede i requisiti per partecipare all'elezione."""
        return user_id in self._eligible_users