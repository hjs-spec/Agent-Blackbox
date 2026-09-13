"""JEP v0.6-style event objects for Agent Blackbox."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from copy import deepcopy
import rfc8785
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

JEP_WIRE_VERSION = "1"
JEP_CORE_PROFILE = "jep-core-0.6"
JAC_CHAIN_EXT = "https://jac.org/chain"
HJS_EVIDENCE_EXT = "https://hjs.org/evidence-refs"


class Verb(str, Enum):
    JUDGMENT = "J"
    DELEGATION = "D"
    TERMINATION = "T"
    VERIFICATION = "V"

    # Backward-compatible names
    JUDGE = "J"
    DELEGATE = "D"
    TERMINATE = "T"
    VERIFY = "V"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    if not isinstance(data, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", data):
        raise ValueError("invalid base64url")
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    if b64u(raw) != data:
        raise ValueError("non-canonical base64url")
    return raw


def canonicalize(obj: Any) -> bytes:
    return rfc8785.dumps(obj)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JOSE header member")
        result[key] = value
    return result


def tagged_hash(obj: Any) -> str:
    raw = obj if isinstance(obj, bytes) else canonicalize(obj)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest_value(value: Any) -> str:
    if isinstance(value, bytes):
        return tagged_hash(value)
    if isinstance(value, str):
        return tagged_hash(value.encode("utf-8"))
    return tagged_hash(value)


@dataclass
class JEPEvent:
    """JEP v0.6-style event used by Agent Blackbox.

    This is an implementation seed object, not a full replacement for the
    normative JEP-Core specification.
    """

    verb: Verb
    who: str
    when: int
    what: Any
    nonce: str
    aud: str = "agent-blackbox"
    ref: Optional[str] = None
    ext: Dict[str, Any] = field(default_factory=dict)
    ext_crit: List[str] = field(default_factory=list)
    sig: Optional[str] = None
    _wire: Optional[Dict[str, Any]] = field(default=None, repr=False, compare=False)

    def unsigned_dict(self) -> Dict[str, Any]:
        if self._wire is not None:
            data = deepcopy(self._wire)
            data.pop("sig", None)
            for name in (
                "verb",
                "who",
                "when",
                "what",
                "nonce",
                "aud",
                "ref",
                "ext",
                "ext_crit",
            ):
                value = getattr(self, name)
                if isinstance(value, Verb):
                    value = value.value
                if name in data or value is not None:
                    data[name] = deepcopy(value)
            return data
        data = {
            "jep": JEP_WIRE_VERSION,
            "verb": self.verb.value,
            "who": self.who,
            "when": self.when,
            "what": self.what,
            "nonce": self.nonce,
            "aud": self.aud,
            "ref": self.ref,
        }
        if self.ext:
            data["ext"] = self.ext
        if self.ext_crit:
            data["ext_crit"] = self.ext_crit
        return deepcopy(data)

    def to_dict(self) -> Dict[str, Any]:
        data = self.unsigned_dict()
        data["sig"] = self.sig
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JEPEvent":
        return cls(
            verb=Verb(data["verb"]),
            who=data["who"],
            when=data["when"],
            what=deepcopy(data.get("what")),
            nonce=data["nonce"],
            aud=data.get("aud"),
            ref=data.get("ref"),
            ext=deepcopy(data.get("ext")),
            ext_crit=deepcopy(data.get("ext_crit")),
            sig=data.get("sig"),
            _wire=deepcopy(data),
        )

    def event_hash(self) -> str:
        return tagged_hash(self.to_dict())

    def unsigned_hash(self) -> str:
        return tagged_hash(self.unsigned_dict())

    def sign(
        self, private_key: ed25519.Ed25519PrivateKey, kid: str = "local-agent-key"
    ) -> str:
        protected = {
            "alg": "Ed25519",
            "kid": kid,
            "typ": "jep-event+jws",
            "jep": JEP_WIRE_VERSION,
        }
        protected_b64 = b64u(canonicalize(protected))
        payload_b64 = b64u(canonicalize(self.unsigned_dict()))
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = private_key.sign(signing_input)
        self.sig = f"{protected_b64}..{b64u(signature)}"
        return self.sig

    def verify(
        self, public_key: ed25519.Ed25519PublicKey, *, legacy: bool = False
    ) -> bool:
        """Verify integrity with an explicitly trusted key; legacy hashes require opt-in."""
        try:
            if not isinstance(self.sig, str) or self.sig.count(".") != 2:
                return False
            protected_b64, empty, sig_b64 = self.sig.split(".")
            if empty:
                return False
            header = json.loads(
                b64u_decode(protected_b64).decode("utf-8"),
                object_pairs_hook=_unique_object,
            )
            if (
                not isinstance(header, dict)
                or header.get("alg") != "Ed25519"
                or "crit" in header
                or header.get("b64", True) is not True
            ):
                return False
            payload = self.unsigned_dict()
            raw = (
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
                if legacy
                else canonicalize(payload)
            )
            signing_input = f"{protected_b64}.{b64u(raw)}".encode("ascii")
            VerifyKey(
                public_key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
            ).verify(signing_input, b64u_decode(sig_b64))
            return True
        except (
            BadSignatureError,
            InvalidSignature,
            ValueError,
            TypeError,
            AttributeError,
        ):
            return False


def make_jac_chain_ext(
    based_on: Optional[str],
    based_on_type: str = "jep-event",
    relation: str = "derived-from",
    observed_log_assumption: str = "partial",
) -> Dict[str, Any]:
    return {
        "based_on": based_on,
        "based_on_type": based_on_type,
        "relation": relation,
        "observed_log_assumption": observed_log_assumption,
    }


def make_hjs_evidence_refs(
    input_digest: Optional[str] = None,
    output_digest: Optional[str] = None,
    error_digest: Optional[str] = None,
) -> Dict[str, Any]:
    refs = {}
    if input_digest:
        refs["input_digest"] = input_digest
    if output_digest:
        refs["output_digest"] = output_digest
    if error_digest:
        refs["error_digest"] = error_digest
    return refs
