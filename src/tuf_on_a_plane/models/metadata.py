from binascii import unhexlify
from dataclasses import dataclass
from typing import Dict, Set

from securesystemslib.ecdsa_keys import verify_signature as verify_ecdsa_signature
from securesystemslib.ed25519_keys import verify_signature as verify_ed25519_signature
from securesystemslib.rsa_keys import verify_rsa_signature

from .common import (
    DateTime,
    Hashes,
    KeyID,
    Length,
    RolenameToHashes,
    RolenameToVersion,
    SpecVersion,
    Threshold,
    Version,
)


# Each key may list one or more signatures.
Signature = str
# NOTE: In Python >= 3.7, KeyIDs are ordered (because dict), but not
# Signatures (because set).
Signatures = Dict[KeyID, Set[Signature]]


@dataclass
class Signed:
    expires: DateTime
    spec_version: SpecVersion
    version: Version


@dataclass
class Metadata:
    # NOTE: I suppose "canonical" should be the result of lazily serializing
    # "signed", but I do not want to repeat the writing work from
    # https://github.com/theupdateframework/tuf/blob/develop/tuf/api/metadata.py,
    # especially for what is supposed to be just a reader.
    canonical: bytes
    signatures: Signatures
    signed: Signed


# We don't need a separate key type, because the scheme already encodes this
# information redundantly.
# TODO: generalize to more signing schemes per public key algorithm.
@dataclass
class Scheme:
    value: str


@dataclass
class ECDSAScheme(Scheme):
    value: str = "ecdsa-sha2-nistp256"


@dataclass
class ED25519Scheme(Scheme):
    value: str = "ed25519"


@dataclass
class RSAScheme(Scheme):
    value: str = "rsassa-pss-sha256"


@dataclass
class PublicKey:
    scheme: Scheme
    value: str

    def signed(self, sig: Signature, data: bytes) -> bool:
        # FIXME: The securesystemslib "abstraction" feels ad hoc...
        public = self.value
        scheme = self.scheme
        sig_bytes = unhexlify(sig.encode("utf-8"))

        if scheme is ECDSAScheme:
            return verify_ecdsa_signature(public, scheme.value, sig_bytes, data)
        elif scheme is ED25519Scheme:
            public_bytes = unhexlify(public.encode("utf-8"))
            return verify_ed25519_signature(public_bytes, scheme.value, sig_bytes, data)
        elif scheme is RSAScheme:
            return verify_rsa_signature(sig_bytes, scheme.value, public, data)
        else:
            raise ValueError(f"unknown scheme: {scheme}")


PublicKeys = Dict[KeyID, PublicKey]


# NOTE: maybe this can be a Role instead, but I will leave this design
# decision to the future, especially when we write the code for delegations.
class ThresholdOfPublicKeys:
    def __init__(self, threshold: Threshold, pubkeys: PublicKeys):
        if len(pubkeys) < threshold.value:
            raise ValueError(f"{len(pubkeys)} < {threshold.value}")
        self.threshold = threshold
        self.pubkeys = pubkeys

    def verified(self, signatures: Signatures, data: bytes) -> bool:
        counter = 0

        # NOTE: each keyid is counted at most once.
        for keyid, pubkey in self.pubkeys.items():
            sigs = signatures.get(keyid, set())
            for sig in sigs:
                if pubkey.signed(sig, data):
                    counter += 1
                    break

        return counter >= self.threshold.value


@dataclass
class Root(Signed):
    consistent_snapshot: bool
    root: ThresholdOfPublicKeys
    snapshot: ThresholdOfPublicKeys
    targets: ThresholdOfPublicKeys
    timestamp: ThresholdOfPublicKeys


@dataclass
class Timestamp(Signed):
    hashes: Hashes
    length: Length


@dataclass
class Snapshot(Signed):
    hashes: RolenameToHashes
    versions: RolenameToVersion


@dataclass
class Targets(Signed):
    pass
