"""A recursive descent parser for JSON TUF metadata."""

from datetime import datetime
from typing import (
    Any,
    List,
    Sized,
    Tuple,
    Type,
)

from securesystemslib.formats import encode_canonical

from . import Parser
from ..models.common import (
    Json,
    KeyID,
    SpecVersion,
    Version,
)
from ..models.metadata import (
    ECDSAScheme,
    ED25519Scheme,
    Metadata,
    PublicKey,
    PublicKeys,
    Root,
    RSAScheme,
    Scheme,
    Signature,
    Signatures,
    Signed,
    Snapshot,
    Targets,
    Threshold,
    ThresholdOfPublicKeys,
    Timestamp,
)


def check_dict(d: Any) -> None:
    if not isinstance(d, dict):
        raise TypeError(f"{d} is not a dict")


def check_key(observed: str, expected: str) -> None:
    if observed != expected:
        raise ValueError(f"{observed} != {expected}")


def canonical(_signed: Json) -> bytes:
    """Returns the UTF-8 encoded canonical JSON representation of _signed."""
    return encode_canonical(_signed).encode("utf-8")


def spec_version(sv: str) -> SpecVersion:
    _spec_version = SpecVersion(sv)
    if _spec_version.major != 1:
        raise ValueError(f"unsupported major spec_version: {_spec_version.value}")
    return _spec_version


def check_empty(i: Sized) -> None:
    if len(i) > 0:
        raise ValueError(f"{i} is not empty")


def check_str(s: Any) -> None:
    if not isinstance(s, str):
        raise TypeError(f"{s} is not a str")


def keyval(_keyval: Json) -> str:
    check_dict(_keyval)

    k, public = _keyval.popitem()
    check_key(k, "public")
    check_str(public)

    check_empty(_keyval)
    return public


def check_scheme(observed: Type[Scheme], expected: Type[Scheme]) -> None:
    if observed is not expected:
        raise ValueError(f"{observed} != {expected}")


def key(_key: Json) -> PublicKey:
    check_dict(_key)

    k, scheme = _key.popitem()
    check_key(k, "scheme")
    if scheme == "ecdsa-sha2-nistp256":
        scheme = ECDSAScheme
    elif scheme == "ed25519":
        scheme = ED25519Scheme
    elif scheme == "rsassa-pss-sha256":
        scheme = RSAScheme
    else:
        raise ValueError(f"{_key} has unknown scheme: {scheme}")

    k, _keyval = _key.popitem()
    check_key(k, "keyval")
    value = keyval(_keyval)

    k, keytype = _key.popitem()
    check_key(k, "keytype")
    if keytype == "ecdsa-sha2-nistp256":
        check_scheme(scheme, ECDSAScheme)
    elif keytype == "ed25519":
        check_scheme(scheme, ED25519Scheme)
    elif keytype == "rsa":
        check_scheme(scheme, RSAScheme)
    else:
        raise ValueError(f"{_key} has unknown keytype: {keytype}")

    k, keyid_hash_algorithms = _key.popitem()
    check_key(k, "keyid_hash_algorithms")
    if keyid_hash_algorithms != ["sha256", "sha512"]:
        raise ValueError(
            f"{_key} has unknown keyid_hash_algorithms: {keyid_hash_algorithms}"
        )

    check_empty(_key)
    return PublicKey(scheme, value)


def keys(_keys: Json) -> PublicKeys:
    check_dict(_keys)

    public_keys = {}

    while True:
        try:
            keyid, _key = _keys.popitem()
            public_key = key(_key)
            public_keys[keyid] = public_key
        except KeyError:
            break

    return public_keys


def check_list(_list: Any) -> None:
    if not isinstance(_list, list):
        raise TypeError(f"{_list} is not a list")


def root_role(role: dict, _keys: PublicKeys) -> ThresholdOfPublicKeys:
    check_dict(role)

    k, threshold = role.popitem()
    check_key(k, "threshold")
    if not isinstance(threshold, int):
        raise ValueError(f"{threshold} is not an int")
    threshold = Threshold(threshold)

    k, keyids = role.popitem()
    check_key(k, "keyids")
    check_list(keyids)
    _keys = {keyid: _keys[keyid] for keyid in set(keyids)}

    check_empty(role)
    return ThresholdOfPublicKeys(_keys, threshold)


def root_roles(
    roles: dict, _keys: PublicKeys
) -> Tuple[
    ThresholdOfPublicKeys,
    ThresholdOfPublicKeys,
    ThresholdOfPublicKeys,
    ThresholdOfPublicKeys,
]:
    check_dict(roles)

    k, timestamp = roles.popitem()
    check_key(k, "timestamp")
    timestamp = root_role(timestamp, _keys)

    k, targets = roles.popitem()
    check_key(k, "targets")
    targets = root_role(targets, _keys)

    k, snapshot = roles.popitem()
    check_key(k, "snapshot")
    snapshot = root_role(snapshot, _keys)

    k, root = roles.popitem()
    check_key(k, "root")
    root = root_role(root, _keys)

    return root, snapshot, targets, timestamp


def expires(_expires: str) -> datetime:
    return datetime.strptime(_expires, "%Y-%m-%dT%H:%M:%SZ")


def root(_signed: Json) -> Root:
    check_dict(_signed)

    k, version = _signed.popitem()
    check_key(k, "version")
    version = Version(version)

    k, _spec_version = _signed.popitem()
    check_key(k, "spec_version")
    _spec_version = spec_version(_spec_version)

    k, _root_roles = _signed.popitem()
    check_key(k, "roles")

    k, _keys = _signed.popitem()
    check_key(k, "keys")
    _keys = keys(_keys)

    # TODO: is it a big deal that we do not check whether all keys listed are used?
    _root, _snapshot, _targets, _timestamp = root_roles(_root_roles, _keys)

    k, _expires = _signed.popitem()
    check_key(k, "expires")
    _expires = expires(_expires)

    k, consistent_snapshot = _signed.popitem()
    check_key(k, "consistent_snapshot")
    if not isinstance(consistent_snapshot, bool):
        raise TypeError(
            f"{_signed} has non-boolean consistent_snapshot: {consistent_snapshot}"
        )

    k, _type = _signed.popitem()
    check_key(k, "_type")
    if _type != "root":
        raise ValueError(f"{_signed} has unexpected type {_type}")

    check_empty(_signed)
    return Root(
        _expires,
        _spec_version,
        version,
        consistent_snapshot,
        _root,
        _snapshot,
        _targets,
        _timestamp,
    )


def timestamp(_signed: Json) -> Timestamp:
    raise NotImplementedError


def snapshot(_signed: Json) -> Snapshot:
    raise NotImplementedError


def targets(_signed: Json) -> Targets:
    raise NotImplementedError


def signed(_signed: Json) -> Signed:
    # Peek ahead.
    type = _signed.get("_type")
    if not type:
        raise TypeError(f"{_signed} has no type")
    if type == "root":
        return root(_signed)
    elif type == "timestamp":
        return timestamp(_signed)
    elif type == "snapshot":
        return snapshot(_signed)
    elif type == "targets":
        return targets(_signed)
    else:
        raise ValueError(f"{_signed} has unknown type {type}")


def signature(_signature: Json) -> Tuple[KeyID, Signature]:
    check_dict(_signature)

    k, sig = _signature.popitem()
    check_key(k, "sig")
    check_str(sig)

    k, keyid = _signature.popitem()
    check_key(k, "keyid")
    check_str(keyid)

    check_empty(_signature)
    return keyid, sig


def signatures(_signatures: List) -> Signatures:
    check_list(_signatures)
    keyids: Signatures = {}

    while len(_signatures) > 0:
        # NOTE: pop in order of appearance, so that we preserve order of key IDs.
        _signature = _signatures.pop(0)
        keyid, sig = signature(_signature)
        sigs = keyids.setdefault(keyid, set())
        sigs.add(sig)

    return keyids


class JSONParser(Parser):
    @classmethod
    def parse(cls, d: Json) -> Metadata:
        """This method is used to try to parse any JSON dictionary containing TUF metadata.

        It destructively reads the dictionary in reverse order of canonical sorting.
        If the original dictionary must be preserved, be sure to pass in a copy.

        We assume that keys are sorted in both input and output.
        We have always output keys in this order.
        In Python >= 3.7, this order is preserved in input thanks to ordered dict.

        It does NOT verify signatures. Be sure to verify signatures after parsing."""
        check_dict(d)

        k, _signed = d.popitem()
        check_key(k, "signed")
        # NOTE: Before we destroy the signed object, build its canonical representation.
        _canonical = canonical(_signed)
        _signed = signed(_signed)

        k, _signatures = d.popitem()
        check_key(k, "signatures")
        _signatures = signatures(_signatures)

        check_empty(d)
        return Metadata(_canonical, _signatures, _signed)
