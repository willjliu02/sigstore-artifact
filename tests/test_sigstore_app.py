"""Offline tests using real hashes/signatures and mocked Rekor responses."""

import base64
import datetime
import hashlib
import json
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sscs_hw import main as app
from sscs_hw import merkle_proof as merkle
from sscs_hw import util


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """An unexpected HTTP call must fail rather than reach the real service."""
    monkeypatch.setattr(
        app.requests, "get", Mock(side_effect=AssertionError("Unexpected HTTP request"))
    )


@pytest.fixture
def signed_artifact(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pytest")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "artifact.txt"
    path.write_bytes(b"An offline signed artifact")
    signature = key.sign(path.read_bytes(), ec.ECDSA(hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return path, signature, pem, key.public_key()


def test_hashes_follow_rfc6962():
    leaf = hashlib.sha256(b"\x00hello").digest()
    sibling = hashlib.sha256(b"\x00world").digest()
    assert merkle.DefaultHasher.hash_leaf(b"hello") == leaf
    assert merkle.DefaultHasher.empty_root() == hashlib.sha256(b"").digest()
    assert merkle.DefaultHasher.size() == 32
    assert (
        merkle.DefaultHasher.hash_children(leaf, sibling)
        == hashlib.sha256(b"\x01" + leaf + sibling).digest()
    )
    assert merkle.compute_leaf_hash(base64.b64encode(b"hello")) == leaf.hex()


def test_inclusion_proofs_and_invalid_inputs(capsys):
    left = hashlib.sha256(b"\x00left").digest()
    right = hashlib.sha256(b"\x00right").digest()
    root = hashlib.sha256(b"\x01" + left + right).hexdigest()
    for index, leaf, sibling in [(0, left, right), (1, right, left)]:
        merkle.verify_inclusion(
            merkle.DefaultHasher,
            index,
            2,
            leaf.hex(),
            [sibling.hex()],
            root,
            debug=True,
        )
    assert "Calculated root hash" in capsys.readouterr().out
    with pytest.raises(merkle.RootMismatchError) as error:
        merkle.verify_inclusion(
            merkle.DefaultHasher, 0, 2, left.hex(), [right.hex()], left.hex()
        )
    assert "does not match expected root" in str(error.value)
    for index, size, leaf, proof, message in [
        (2, 2, left, [], "index is beyond size"),
        (0, 1, b"short", [], "unexpected size"),
        (0, 2, left, [], "wrong proof size"),
    ]:
        with pytest.raises(ValueError, match=message):
            merkle.root_from_inclusion_proof(
                merkle.DefaultHasher, index, size, leaf, proof
            )


def test_consistency_proofs_and_invalid_inputs():
    h = merkle.DefaultHasher
    a, b, c = [h.hash_leaf(value) for value in (b"a", b"b", b"c")]
    ab = h.hash_children(a, b)
    abc = h.hash_children(ab, c)
    for first, second, proof, old, new in [
        (1, 1, [], a, a),
        (0, 1, [], h.empty_root(), a),
        (1, 2, [b.hex()], a, ab),
        (2, 3, [c.hex()], ab, abc),
    ]:
        merkle.verify_consistency(h, first, second, proof, old.hex(), new.hex())
    for first, second, proof, message in [
        (2, 1, [], "size2"),
        (1, 1, [a.hex()], "not empty"),
        (0, 1, [a.hex()], "expected empty"),
        (1, 2, [], "empty bytearray_proof"),
        (1, 2, [a.hex(), b.hex()], "wrong bytearray_proof size"),
    ]:
        with pytest.raises(ValueError, match=message):
            merkle.verify_consistency(h, first, second, proof, a.hex(), a.hex())
    assert merkle.chain_inner_right(h, b, [a], 1) == ab
    assert merkle.chain_border_right(h, b, [a]) == ab


def test_certificate_extraction_and_valid_signature(signed_artifact, capsys):
    path, signature, certificate, expected_key = signed_artifact
    public_pem = util.extract_public_key(certificate)
    loaded = serialization.load_pem_public_key(public_pem)
    assert loaded.public_numbers() == expected_key.public_numbers()
    util.verify_artifact_signature(signature, public_pem, path)
    assert capsys.readouterr().out == ""
    with pytest.raises(ValueError):
        util.extract_public_key(b"not a certificate")


def test_tampered_artifact_reports_invalid_signature(signed_artifact, capsys):
    path, signature, certificate, _ = signed_artifact
    path.write_bytes(b"tampered")
    # Current API prints failures instead of raising; this does not assert that
    # the CLI correctly rejects a tampered artifact end to end.
    util.verify_artifact_signature(
        signature, util.extract_public_key(certificate), path
    )
    assert "Signature is invalid" in capsys.readouterr().out


def test_entry_fetch_and_response_validation(monkeypatch):
    entry = {
        "body": "body",
        "integratedTime": 1,
        "logID": "id",
        "logIndex": 7,
        "verification": {"proof": True},
    }
    get = Mock(
        return_value=Mock(status_code=200, json=Mock(return_value={"uuid": entry}))
    )
    monkeypatch.setattr(app.requests, "get", get)
    assert app.get_log_entry(7) == {
        key: entry[key] for key in ("body", "integratedTime", "logID", "logIndex")
    }
    assert app.get_verification_proof(7) == {"proof": True}
    get.assert_called_with(f"{app.BASE_URL}/api/v1/log/entries?logIndex=7", timeout=10)
    get.return_value.status_code = 404
    with pytest.raises(ValueError, match="invalid"):
        app.get_entry(7)
    get.return_value.status_code = 200
    get.return_value.json.side_effect = ValueError("bad JSON")
    with pytest.raises(ValueError, match="valid json"):
        app.get_entry(7)
    get.return_value.json.side_effect = None
    for payload in ({}, {"a": entry, "b": entry}):
        get.return_value.json.return_value = payload
        for function in (app.get_log_entry, app.get_verification_proof):
            with pytest.raises(SystemExit) as error:
                function(7)
            assert error.value.code == 1


def test_inclusion_with_real_certificate_and_proof(
    monkeypatch, signed_artifact, capsys
):
    path, signature, certificate, _ = signed_artifact
    body = base64.b64encode(
        json.dumps(
            {
                "spec": {
                    "signature": {
                        "publicKey": {
                            "content": base64.b64encode(certificate).decode()
                        },
                        "content": base64.b64encode(signature).decode(),
                    }
                }
            }
        ).encode()
    ).decode()
    entry = {
        "body": body,
        "integratedTime": 1,
        "logID": "id",
        "logIndex": 0,
        "verification": {
            "inclusionProof": {
                "logIndex": 0,
                "treeSize": 1,
                "rootHash": hashlib.sha256(
                    b"\x00" + base64.b64decode(body)
                ).hexdigest(),
                "hashes": [],
            }
        },
    }
    get = Mock(
        return_value=Mock(status_code=200, json=Mock(return_value={"uuid": entry}))
    )
    monkeypatch.setattr(app.requests, "get", get)
    app.inclusion(0, path, debug=True)
    assert "Offline verification successful" in capsys.readouterr().out
    entry["verification"]["inclusionProof"]["rootHash"] = "00" * 32
    with pytest.raises(SystemExit) as error:
        app.inclusion(0, path)
    assert error.value.code == 1
    assert "Inclusion proof verification failed" in capsys.readouterr().out


def test_inclusion_rejects_missing_inputs(tmp_path, capsys):
    for index, path, message in [
        (None, None, "Please enter a log index"),
        (1, None, "Please enter a valid artifact filepath"),
        (1, tmp_path / "missing", "Please enter a valid artifact filepath"),
    ]:
        with pytest.raises(SystemExit) as error:
            app.inclusion(index, path)
        assert error.value.code == 1
        assert message in capsys.readouterr().out


def test_checkpoint_and_consistency_http_flow(monkeypatch, capsys):
    a = hashlib.sha256(b"\x00a").digest()
    b = hashlib.sha256(b"\x00b").digest()
    previous = {"treeID": "tree", "treeSize": 1, "rootHash": a.hex()}
    latest = {
        "treeID": "tree",
        "treeSize": 2,
        "rootHash": hashlib.sha256(b"\x01" + a + b).hexdigest(),
    }
    checkpoint_response = Mock(
        json=Mock(side_effect=lambda: {**latest, "inactiveShards": []})
    )
    proof_response = Mock(
        status_code=200, json=Mock(return_value={"hashes": [b.hex()]})
    )
    get = Mock(side_effect=[checkpoint_response, proof_response])
    monkeypatch.setattr(app.requests, "get", get)
    app.consistency(previous)
    assert "Consistency verification successful" in capsys.readouterr().out
    assert get.call_args_list[0].args == (f"{app.BASE_URL}/api/v1/log/",)
    assert get.call_args_list[1].args == (
        f"{app.BASE_URL}/api/v1/log/proof?treeID=tree&firstSize=1&lastSize=2",
    )
    assert all(call.kwargs == {"timeout": 10} for call in get.call_args_list)
    for status, json_error, proof in [
        (500, None, {}),
        (200, ValueError("bad JSON"), {}),
        (200, None, {"hashes": []}),
    ]:
        proof_response.status_code = status
        proof_response.json.side_effect = json_error
        proof_response.json.return_value = proof
        get.side_effect = [checkpoint_response, proof_response]
        with pytest.raises(SystemExit):
            app.consistency(previous)
    checkpoint_response.json.side_effect = ValueError("bad JSON")
    get.side_effect = [checkpoint_response]
    with pytest.raises(SystemExit):
        app.get_latest_checkpoint()


def test_cli_routes_commands_and_validates_options(monkeypatch, capsys):
    checkpoint = {"treeID": "tree", "treeSize": 1, "rootHash": "abc"}
    fetch, inclusion, consistency = Mock(return_value=checkpoint), Mock(), Mock()
    monkeypatch.setattr(app, "get_latest_checkpoint", fetch)
    monkeypatch.setattr(app, "inclusion", inclusion)
    monkeypatch.setattr(app, "consistency", consistency)
    monkeypatch.setattr(
        "sys.argv",
        [
            "rekor",
            "-d",
            "-c",
            "--inclusion",
            "7",
            "--artifact",
            "artifact.txt",
            "--consistency",
            "--tree-id",
            "tree",
            "--tree-size",
            "1",
            "--root-hash",
            "abc",
        ],
    )
    app.main()
    fetch.assert_called_once_with(True)
    inclusion.assert_called_once_with(7, "artifact.txt", True)
    consistency.assert_called_once_with(checkpoint, True)
    assert "enabled debug mode" in capsys.readouterr().out
    for options, message in [
        ([], "tree id"),
        (["--tree-id", "tree"], "tree size"),
        (["--tree-id", "tree", "--tree-size", "1"], "root hash"),
    ]:
        monkeypatch.setattr("sys.argv", ["rekor", "--consistency", *options])
        app.main()
        assert message in capsys.readouterr().out
