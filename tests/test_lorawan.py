"""Tests for LoRaWAN frame parsing, MIC verification, and payload decryption."""

import struct
import sys

sys.path.insert(0, "src")

from gr_lora_cli.lorawan import decrypt_payload, parse_lorawan, verify_mic

DEV_ADDR = 0x00000000
NWK_S_KEY = bytes(16)
APP_S_KEY = bytes(16)


def _build_lorawan_frame(
    payload: bytes,
    dev_addr: int = DEV_ADDR,
    f_cnt: int = 0,
    f_port: int = 1,
    nwk_key: bytes = NWK_S_KEY,
    app_key: bytes = APP_S_KEY,
) -> bytes:
    """Construct a LoRaWAN 1.0 Unconfirmed Data Up frame."""
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Encrypt FRMPayload with AppSKey (AES-128-CTR, LoRaWAN style)
    n_blocks = (len(payload) + 15) // 16
    key_stream = bytearray()
    for i in range(1, n_blocks + 1):
        a_block = bytearray(16)
        a_block[0] = 0x01
        a_block[5] = 0  # uplink
        struct.pack_into("<I", a_block, 6, dev_addr)
        struct.pack_into("<I", a_block, 10, f_cnt)
        a_block[15] = i
        enc = Cipher(algorithms.AES128(app_key), modes.ECB()).encryptor()
        key_stream.extend(enc.update(bytes(a_block)) + enc.finalize())

    encrypted = bytes(p ^ k for p, k in zip(payload, key_stream))

    # Build MAC payload
    msg = bytearray()
    msg.append(0x40)  # MHDR: Unconfirmed Data Up, LoRaWAN R1
    msg.extend(struct.pack("<I", dev_addr))
    msg.append(0x00)  # FCtrl: no ADR, no ACK, no FOpts
    msg.extend(struct.pack("<H", f_cnt & 0xFFFF))
    msg.append(f_port)
    msg.extend(encrypted)

    # Compute MIC = CMAC(NwkSKey, B0 || msg)[0:4]
    b0 = bytearray(16)
    b0[0] = 0x49
    b0[5] = 0  # uplink
    struct.pack_into("<I", b0, 6, dev_addr)
    struct.pack_into("<I", b0, 10, f_cnt)
    b0[15] = len(msg)

    c = cmac.CMAC(algorithms.AES128(nwk_key))
    c.update(bytes(b0) + bytes(msg))
    mic = c.finalize()[:4]

    msg.extend(mic)
    return bytes(msg)


# ======================================================================
# Tests
# ======================================================================


def test_parse_basic():
    """Parse a manually-constructed frame with known fields."""
    mhdr = 0x40
    dev_addr = struct.pack("<I", 0x26011234)
    f_ctrl = bytes([0x00])
    f_cnt = struct.pack("<H", 42)
    f_port = bytes([1])
    frm_payload = b"Hello"
    mic = bytes(4)

    frame_bytes = (
        bytes([mhdr]) + dev_addr + f_ctrl + f_cnt + f_port + frm_payload + mic
    )
    frame = parse_lorawan(frame_bytes)

    assert frame is not None
    assert frame.dev_addr == 0x26011234
    assert frame.f_cnt == 42
    assert frame.f_port == 1
    assert frame.frm_payload == b"Hello"
    assert frame.mtype == 0b010  # Unconfirmed Data Up


def test_parse_too_short():
    """Frames shorter than 12 bytes should return None."""
    assert parse_lorawan(b"\x40\x00\x00") is None
    assert parse_lorawan(bytes(11)) is None


def test_relay_frame_roundtrip():
    """Build a frame matching the relay firmware and verify parsing."""
    plaintext = b'"Hello World" (-55.00 dBm, SNR: 9.50 dB)'
    frame_bytes = _build_lorawan_frame(plaintext, f_cnt=0)

    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    assert frame.dev_addr == DEV_ADDR
    assert frame.f_cnt == 0
    assert frame.f_port == 1
    assert frame.mtype == 0b010


def test_mic_verification():
    """Verify MIC matches for a frame built with all-zeros NwkSKey."""
    plaintext = b"test payload"
    frame_bytes = _build_lorawan_frame(plaintext, f_cnt=1)

    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    result = verify_mic(frame, NWK_S_KEY)
    assert result is True
    assert frame.mic_ok is True


def test_mic_failure():
    """MIC should fail with a wrong key."""
    plaintext = b"test payload"
    frame_bytes = _build_lorawan_frame(plaintext, f_cnt=1)

    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    wrong_key = bytes(range(16))
    result = verify_mic(frame, wrong_key)
    assert result is False
    assert frame.mic_ok is False


def test_decrypt_payload():
    """Decrypt FRMPayload and verify it matches the original plaintext."""
    plaintext = b'"Hello World" (-55.00 dBm, SNR: 9.50 dB)'
    frame_bytes = _build_lorawan_frame(plaintext, f_cnt=5)

    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    decrypted = decrypt_payload(frame, APP_S_KEY)
    assert decrypted == plaintext


def test_relay_full_pipeline():
    """Full pipeline: build relay frame, parse, verify MIC, decrypt."""
    original = b"sensor data"
    relay_payload = b'"sensor data" (-42.50 dBm, SNR: 7.25 dB)'

    for f_cnt in range(5):
        frame_bytes = _build_lorawan_frame(relay_payload, f_cnt=f_cnt)
        frame = parse_lorawan(frame_bytes)
        assert frame is not None

        assert verify_mic(frame, NWK_S_KEY)
        decrypted = decrypt_payload(frame, APP_S_KEY)
        assert decrypted == relay_payload

        # Verify the decrypted text contains expected fields
        text = decrypted.decode("utf-8")
        assert "sensor data" in text
        assert "dBm" in text
        assert "SNR" in text


def test_fcnt_increment():
    """Verify frames with different FCnt values all parse correctly."""
    payload = b"test"
    for f_cnt in [0, 1, 100, 65535]:
        frame_bytes = _build_lorawan_frame(payload, f_cnt=f_cnt)
        frame = parse_lorawan(frame_bytes)
        assert frame is not None
        assert frame.f_cnt == f_cnt
        assert verify_mic(frame, NWK_S_KEY)
        assert decrypt_payload(frame, APP_S_KEY) == payload


def test_summary_output():
    """Verify summary() produces expected output fields."""
    payload = b"Hello"
    frame_bytes = _build_lorawan_frame(payload, f_cnt=1)

    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    verify_mic(frame, NWK_S_KEY)
    decrypt_payload(frame, APP_S_KEY)

    summary = frame.summary()
    assert "Unconfirmed Data Up" in summary
    assert "00000000" in summary  # DevAddr
    assert "OK" in summary  # MIC


def test_nonzero_devaddr():
    """Verify correct handling with a non-zero DevAddr."""
    payload = b"test"
    dev_addr = 0xAABBCCDD
    frame_bytes = _build_lorawan_frame(
        payload, dev_addr=dev_addr, f_cnt=10
    )
    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    assert frame.dev_addr == dev_addr
    assert verify_mic(frame, NWK_S_KEY)
    assert decrypt_payload(frame, APP_S_KEY) == payload


def test_long_payload():
    """Verify handling of payloads spanning multiple AES blocks."""
    payload = bytes(range(48))  # 3 AES blocks
    frame_bytes = _build_lorawan_frame(payload, f_cnt=0)
    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    assert verify_mic(frame, NWK_S_KEY)
    assert decrypt_payload(frame, APP_S_KEY) == payload


if __name__ == "__main__":
    test_parse_basic()
    test_parse_too_short()
    test_relay_frame_roundtrip()
    test_mic_verification()
    test_mic_failure()
    test_decrypt_payload()
    test_relay_full_pipeline()
    test_fcnt_increment()
    test_summary_output()
    test_nonzero_devaddr()
    test_long_payload()
    print("\nAll LoRaWAN tests passed.")
