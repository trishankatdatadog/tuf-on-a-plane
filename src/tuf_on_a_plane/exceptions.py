class Error(Exception):
    pass


# Errors related to downloads.


class DownloadError(Error):
    pass


class DownloadNotFoundError(DownloadError):
    pass


# Errors about a remote repository.


class RepositoryError(Error):
    pass


class NoConsistentSnapshotsError(RepositoryError):
    pass


class TargetNotFoundError(RepositoryError):
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


class MixAndMatchAttack(Attack):
    pass


class RollbackAttack(Attack):
    pass


class SlowRetrievalAttack(Attack):
    pass
