class Error(Exception):
    pass


class DownloadError(Error):
    pass


class NotFoundError(DownloadError):
    pass


class RepositoryError(Error):
    pass


# Known types of attacks.


class Attack(Error):
    pass


class ArbitrarySoftwareAttack(Attack):
    pass


class EndlessDataAttack(Attack):
    pass


class FreezeAttack(Attack):
    pass


class RollbackAttack(Attack):
    pass


class SlowRetrievalAttack(Attack):
    pass
