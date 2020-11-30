"""A recursive descent parser for JSON TUF metadata."""

import re
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
    DateTime,
    Hashes,
    Json,
    KeyID,
    Length,
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
    TargetFile,
    TargetFiles,
    Targets,
    Threshold,
    ThresholdOfPublicKeys,
    TimeSnap,
    TimeSnaps,
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
        raise ValueError(f"unsupported major spec_version: {_spec_version}")
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

    # NOTE: we iterate in order of appearance to preserve it in the new dict.
    return {keyid: key(_key) for keyid, _key in _keys.items()}


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
    return ThresholdOfPublicKeys(threshold, _keys)


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


def expires(_expires: str) -> DateTime:
    return DateTime.strptime(_expires, "%Y-%m-%dT%H:%M:%S%z")


def footer(_signed: Json) -> Tuple[SpecVersion, Version]:
    check_dict(_signed)

    k, version = _signed.popitem()
    check_key(k, "version")
    version = Version(version)

    k, _spec_version = _signed.popitem()
    check_key(k, "spec_version")
    _spec_version = spec_version(_spec_version)

    return _spec_version, version


def root(_signed: Json) -> Root:
    _spec_version, version = footer(_signed)

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


METADATA_FILENAME_PATTERN = re.compile(r"^[0-9a-z\-]+\.json$")


def hashes(_hashes: Json) -> Hashes:
    check_dict(_hashes)

    # We don't do much here... for now.
    for key, value in _hashes.items():
        check_str(key)
        check_str(value)

    return _hashes


def meta(_meta: Json) -> TimeSnaps:
    check_dict(_meta)
    timesnaps = {}

    # NOTE: we iterate in order of appearance to preserve it in the new dict.
    for filename, timesnap in _meta.items():
        check_str(filename)
        if not METADATA_FILENAME_PATTERN.fullmatch(filename):
            raise ValueError(f"{filename} is not a valid targets filename")

        check_dict(timesnap)
        k, version = timesnap.popitem()
        check_key(k, "version")
        version = Version(version)

        try:
            k, length = timesnap.popitem()
        except KeyError:
            length = None
        else:
            check_key(k, "length")
            length = Length(length)

        try:
            k, _hashes = timesnap.popitem()
        except KeyError:
            _hashes = None
        else:
            check_key(k, "hashes")
            _hashes = hashes(_hashes)
            check_empty(timesnap)

        timesnaps[filename] = TimeSnap(version, _hashes, length)

    return timesnaps


def header(_signed: Json, expected_type: str) -> DateTime:
    k, _expires = _signed.popitem()
    check_key(k, "expires")
    _expires = expires(_expires)

    k, _type = _signed.popitem()
    check_key(k, "_type")
    if _type != expected_type:
        raise ValueError(f"{_signed} has unexpected type {_type} != {expected_type}")

    check_empty(_signed)

    return _expires


def timestamp(_signed: Json) -> Timestamp:
    _spec_version, version = footer(_signed)

    k, _meta = _signed.popitem()
    check_key(k, "meta")
    timesnaps = meta(_meta)
    check_dict(timesnaps)

    k, timesnap = timesnaps.popitem()
    check_key(k, "snapshot.json")
    check_empty(timesnaps)

    _expires = header(_signed, "timestamp")

    return Timestamp(
        _expires,
        _spec_version,
        version,
        timesnap,
    )


def snapshot(_signed: Json) -> Snapshot:
    _spec_version, version = footer(_signed)

    k, _meta = _signed.popitem()
    check_key(k, "meta")
    timesnaps = meta(_meta)
    check_dict(timesnaps)

    _expires = header(_signed, "snapshot")

    return Snapshot(
        _expires,
        _spec_version,
        version,
        timesnaps,
    )


def target_file(_target_file: Json) -> TargetFile:
    check_dict(_target_file)

    k, length = _target_file.popitem()
    check_key(k, "length")
    length = Length(length)

    k, _hashes = _target_file.popitem()
    check_key(k, "hashes")
    _hashes = hashes(_hashes)

    try:
        k, custom = _target_file.popitem()
    except KeyError:
        custom = None
    else:
        check_dict(custom)
        check_empty(_target_file)

    return TargetFile(_hashes, length, custom)


def target_files(_target_files: Json) -> TargetFiles:
    check_dict(_target_files)

    # NOTE: we iterate in order of appearance to preserve it in the new dict.
    return {path: target_file(file) for path, file in _target_files.items()}


# FIXME: I don't see a good way to reuse header/footer here, but we can push
# that to the future.
def targets(_signed: Json) -> Targets:
    check_dict(_signed)

    k, version = _signed.popitem()
    check_key(k, "version")
    version = Version(version)

    k, _target_files = _signed.popitem()
    check_key(k, "targets")
    _target_files = target_files(_target_files)

    k, _spec_version = _signed.popitem()
    check_key(k, "spec_version")
    _spec_version = spec_version(_spec_version)

    k, _expires = _signed.popitem()
    check_key(k, "expires")
    _expires = expires(_expires)

    k, delegations = _signed.popitem()
    check_key(k, "delegations")
    # TODO: parse delegations.
    check_dict(delegations)

    k, _type = _signed.popitem()
    check_key(k, "_type")
    if _type != "targets":
        raise ValueError(f"{_signed} has unexpected type {_type} != targets")

    check_empty(_signed)
    return Targets(_expires, _spec_version, version, _target_files)


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
