"""A recursive descent parser for JSON TUF metadata."""

import os
import re
from typing import (
    Any,
    Callable,
    List,
    Sized,
    Tuple,
    Type,
)

from securesystemslib.formats import encode_canonical

from . import Parser
from ..models.common import (
    DateTime,
    Filepaths,
    Hashes,
    Json,
    KeyID,
    Length,
    Rolename,
    SpecVersion,
    Version,
)
from ..models.metadata import (
    Delegation,
    Delegations,
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


def canonical(_signed: Json) -> bytes:
    """Returns the UTF-8 encoded canonical JSON representation of _signed."""
    return encode_canonical(_signed).encode("utf-8")


def check_key(observed: str, expected: str) -> None:
    if observed != expected:
        raise ValueError(f"{observed} != {expected}")


def spec_version(sv: str) -> SpecVersion:
    _spec_version = SpecVersion(sv)
    if _spec_version.major != 1:
        raise ValueError(f"unsupported major spec_version: {_spec_version}")
    return _spec_version


def footer(
    _signed: Json, callback: Callable[[Json], Any] = lambda x: None
) -> Tuple[SpecVersion, Any, Version]:
    check_dict(_signed)

    k, version = _signed.popitem()
    check_key(k, "version")
    version = Version(version)

    result = callback(_signed)

    k, _spec_version = _signed.popitem()
    check_key(k, "spec_version")
    _spec_version = spec_version(_spec_version)

    return _spec_version, result, version


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


def check_int(i: Any) -> None:
    if not isinstance(i, int):
        raise ValueError(f"{i} is not an int")


def check_list(_list: Any) -> None:
    if not isinstance(_list, list):
        raise TypeError(f"{_list} is not a list")


def role(
    _role: dict, _keys: PublicKeys, callback: Callable[[Json], Any] = lambda x: None
) -> Tuple[Any, ThresholdOfPublicKeys]:
    check_dict(_role)

    k, threshold = _role.popitem()
    check_key(k, "threshold")
    check_int(threshold)
    threshold = Threshold(threshold)

    result = callback(_role)

    k, keyids = _role.popitem()
    check_key(k, "keyids")
    check_list(keyids)
    _keys = {keyid: _keys[keyid] for keyid in set(keyids)}

    check_empty(_role)
    return result, ThresholdOfPublicKeys(threshold, _keys)


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
    _, timestamp = role(timestamp, _keys)

    k, targets = roles.popitem()
    check_key(k, "targets")
    _, targets = role(targets, _keys)

    k, snapshot = roles.popitem()
    check_key(k, "snapshot")
    _, snapshot = role(snapshot, _keys)

    k, root = roles.popitem()
    check_key(k, "root")
    _, root = role(root, _keys)

    return root, snapshot, targets, timestamp


def expires(_expires: str) -> DateTime:
    return DateTime.strptime(_expires, "%Y-%m-%dT%H:%M:%S%z")


def header(
    _signed: Json, expected_type: str, callback: Callable[[Json], Any] = lambda x: None
) -> Tuple[Any, DateTime]:
    k, _expires = _signed.popitem()
    check_key(k, "expires")
    _expires = expires(_expires)

    result = callback(_signed)

    k, _type = _signed.popitem()
    check_key(k, "_type")
    if _type != expected_type:
        raise ValueError(f"{_signed} has unexpected type {_type} != {expected_type}")

    check_empty(_signed)

    return result, _expires


def check_bool(b: Any) -> None:
    if not isinstance(b, bool):
        raise TypeError(f"{b} is not a bool")


def root(_signed: Json) -> Root:
    _spec_version, _, version = footer(_signed)

    k, _root_roles = _signed.popitem()
    check_key(k, "roles")

    k, _keys = _signed.popitem()
    check_key(k, "keys")
    _keys = keys(_keys)

    # TODO: is it a big deal that we do not check whether all keys listed are used?
    _root, _snapshot, _targets, _timestamp = root_roles(_root_roles, _keys)

    def callback(_signed: Json) -> bool:
        k, consistent_snapshot = _signed.popitem()
        check_key(k, "consistent_snapshot")
        check_bool(consistent_snapshot)
        return consistent_snapshot

    consistent_snapshot, _expires = header(_signed, "root", callback=callback)

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


ROLENAME_PATTERN = re.compile(r"^[0-9a-z\-]+")


def check_rolename(rolename: Rolename) -> None:
    check_str(rolename)
    if not ROLENAME_PATTERN.fullmatch(rolename):
        raise ValueError(f"{rolename} is not a valid targets rolename")


def hashes(_hashes: Json) -> Hashes:
    check_dict(_hashes)

    # We don't do much here... for now.
    for key, value in _hashes.items():
        check_str(key)
        check_str(value)

    return _hashes


def meta(_meta: Json) -> TimeSnaps:
    check_dict(_meta)
    timesnaps: TimeSnaps = {}

    # NOTE: we iterate in order of appearance to preserve it in the new dict.
    for filename, timesnap in _meta.items():
        rolename, _ = os.path.splitext(filename)
        check_rolename(rolename)

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


def timestamp(_signed: Json) -> Timestamp:
    _spec_version, _, version = footer(_signed)

    k, _meta = _signed.popitem()
    check_key(k, "meta")
    timesnaps = meta(_meta)
    check_dict(timesnaps)

    k, timesnap = timesnaps.popitem()
    check_key(k, "snapshot.json")
    check_empty(timesnaps)

    _, _expires = header(_signed, "timestamp")

    return Timestamp(
        _expires,
        _spec_version,
        version,
        timesnap,
    )


def snapshot(_signed: Json) -> Snapshot:
    _spec_version, _, version = footer(_signed)

    k, _meta = _signed.popitem()
    check_key(k, "meta")
    timesnaps = meta(_meta)
    check_dict(timesnaps)

    _, _expires = header(_signed, "snapshot")

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


# One or more of anything in [a-zA-Z0-9_], a hypen, an asterisk, or a dot.
_FILENAME_PATTERN = r"[\w\-*.]+"
# One or more filenames, separated by a forward slash.
TARGETS_PATH_PATTERN = re.compile(
    fr"^{_FILENAME_PATTERN}(?:/{_FILENAME_PATTERN})*$", re.ASCII
)


def targets_roles(roles: dict, _keys: PublicKeys) -> Delegations:
    check_list(roles)
    delegations: Delegations = {}

    def callback(_role: dict) -> Tuple[Rolename, Filepaths, bool]:
        k, terminating = _role.popitem()
        check_key(k, "terminating")
        check_bool(terminating)

        k, paths = _role.popitem()
        check_key(k, "paths")
        check_list(paths)
        for path in paths:
            if not TARGETS_PATH_PATTERN.fullmatch(path):
                raise ValueError(f"{path} is not a valid targets path pattern")

        k, rolename = _role.popitem()
        check_key(k, "name")
        check_rolename(rolename)

        return rolename, paths, terminating

    # NOTE: we iterate in order of appearance to preserve it in the new dict.
    while len(roles) > 0:
        _role = roles.pop(0)

        rolename: Rolename
        paths: Filepaths
        terminating: bool
        result, _role = role(_role, _keys, callback=callback)
        rolename, paths, terminating = result
        if rolename in delegations:
            raise ValueError(f"{roles} has duplicate {rolename}")

        delegations[rolename] = Delegation(_role, paths, terminating)

    return delegations


def targets(_signed: Json) -> Targets:
    def get_target_files(_signed: Json) -> TargetFiles:
        k, _target_files = _signed.popitem()
        check_key(k, "targets")
        return target_files(_target_files)

    _spec_version, _target_files, version = footer(_signed, callback=get_target_files)

    def get_delegations(_signed: Json) -> Delegations:
        k, delegations = _signed.popitem()
        check_key(k, "delegations")
        check_dict(delegations)

        k, _targets_roles = delegations.popitem()
        check_key(k, "roles")

        k, _keys = delegations.popitem()
        check_key(k, "keys")
        _keys = keys(_keys)

        check_empty(delegations)
        return targets_roles(_targets_roles, _keys)

    delegations, _expires = header(_signed, "targets", callback=get_delegations)

    return Targets(_expires, _spec_version, version, _target_files, delegations)


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
