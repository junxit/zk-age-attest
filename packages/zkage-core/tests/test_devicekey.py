"""Issuance-request binding battery: the device signature must cover the blinded message."""

import pytest

from zkage_core import devicekey

ACCOUNT = bytes([0xAA]) * 16
REQUEST = bytes([0xBB]) * 16
BLINDED = bytes([0xCC]) * 256
TS = 1_781_234_567


@pytest.fixture(scope="module")
def device() -> devicekey.ed25519.Ed25519PrivateKey:
    return devicekey.generate_device_key()


def test_sign_verify_round_trip(device: devicekey.ed25519.Ed25519PrivateKey) -> None:
    sig = devicekey.sign_issuance(device, ACCOUNT, 18, BLINDED, TS, REQUEST)
    devicekey.verify_issuance(device.public_key(), sig, ACCOUNT, 18, BLINDED, TS, REQUEST)


def test_swapped_blinded_msg_rejected(device: devicekey.ed25519.Ed25519PrivateKey) -> None:
    """A valid signature must not authorize a different blinded message."""
    sig = devicekey.sign_issuance(device, ACCOUNT, 18, BLINDED, TS, REQUEST)
    other_blinded = bytes([0xCD]) * 256
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.verify_issuance(device.public_key(), sig, ACCOUNT, 18, other_blinded, TS, REQUEST)


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_id", bytes([0xAB]) * 16),
        ("scope_id", 21),
        ("ts", TS + 1),
        ("request_id", bytes([0xBC]) * 16),
    ],
)
def test_any_field_change_rejected(
    device: devicekey.ed25519.Ed25519PrivateKey, field: str, value: object
) -> None:
    sig = devicekey.sign_issuance(device, ACCOUNT, 18, BLINDED, TS, REQUEST)
    kwargs: dict[str, object] = {
        "account_id": ACCOUNT,
        "scope_id": 18,
        "blinded_msg": BLINDED,
        "ts": TS,
        "request_id": REQUEST,
    }
    kwargs[field] = value
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.verify_issuance(device.public_key(), sig, **kwargs)  # type: ignore[arg-type]


def test_tampered_signature_rejected(device: devicekey.ed25519.Ed25519PrivateKey) -> None:
    sig = bytearray(devicekey.sign_issuance(device, ACCOUNT, 18, BLINDED, TS, REQUEST))
    sig[0] ^= 0x01
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.verify_issuance(
            device.public_key(), bytes(sig), ACCOUNT, 18, BLINDED, TS, REQUEST
        )


def test_wrong_key_rejected(device: devicekey.ed25519.Ed25519PrivateKey) -> None:
    sig = devicekey.sign_issuance(device, ACCOUNT, 18, BLINDED, TS, REQUEST)
    other = devicekey.generate_device_key()
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.verify_issuance(other.public_key(), sig, ACCOUNT, 18, BLINDED, TS, REQUEST)


def test_payload_field_validation() -> None:
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.issuance_payload(ACCOUNT[:-1], 18, BLINDED, TS, REQUEST)
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.issuance_payload(ACCOUNT, 300, BLINDED, TS, REQUEST)
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.issuance_payload(ACCOUNT, 18, b"", TS, REQUEST)
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.issuance_payload(ACCOUNT, 18, BLINDED, TS, REQUEST + b"x")


def test_public_key_raw_round_trip(device: devicekey.ed25519.Ed25519PrivateKey) -> None:
    raw = devicekey.device_public_raw(device)
    assert len(raw) == 32
    loaded = devicekey.load_device_public(raw)
    sig = devicekey.sign_issuance(device, ACCOUNT, 18, BLINDED, TS, REQUEST)
    devicekey.verify_issuance(loaded, sig, ACCOUNT, 18, BLINDED, TS, REQUEST)
    with pytest.raises(devicekey.IssuanceBindingError):
        devicekey.load_device_public(b"\x00" * 31)
