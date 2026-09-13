import asyncio
import json
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from agent_blackbox import AgentBlackbox, JEPEvent, Verb
from agent_blackbox.jep import canonicalize, b64u


def test_rfc8785_unicode_and_float_rendering():
    assert canonicalize({"\ue000": 1.0, "😀": 1e-7}) == '{"😀":1e-7,"\ue000":1}'.encode()


def test_import_preserves_signed_member_presence_and_mutation_is_rejected():
    key = Ed25519PrivateKey.generate()
    data = {"jep":"1", "verb":"J", "who":"a", "when":1, "nonce":str(uuid.uuid4()), "what":{"claim":"yes"}, "ref":None, "ext":{}, "ext_crit":[]}
    header = b64u(canonicalize({"alg":"Ed25519", "kid":"a"}))
    data["sig"] = header + ".." + b64u(key.sign((header + "." + b64u(canonicalize(data))).encode()))
    event = JEPEvent.from_dict(data)
    assert event.to_dict() == data
    assert event.verify(key.public_key())
    event.what["claim"] = "changed"
    assert not event.verify(key.public_key())


def test_identity_key_forgery_rejected():
    event = JEPEvent(Verb.JUDGMENT, "a", 1, {"claim":"test"}, str(uuid.uuid4()))
    event.sig = b64u(canonicalize({"alg":"Ed25519"})) + ".." + b64u(bytes([1]) + bytes(63))
    assert not event.verify(Ed25519PublicKey.from_public_bytes(bytes([1]) + bytes(31)))


def test_async_trace_waits_for_result_and_records_cancellation(tmp_path):
    box = AgentBlackbox(str(tmp_path))
    @box.trace("worker")
    async def work():
        await asyncio.sleep(0)
        return {"result": 1.0}
    pending = work()
    assert not box.events
    assert asyncio.run(pending) == {"result": 1.0}
    assert all(box.verify_event(h) for h in box.events)
    @box.trace("worker")
    async def cancel(): raise asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError): asyncio.run(cancel())
    assert list(box.traces.values())[-1].status == "cancelled"
