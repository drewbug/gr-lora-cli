"""LoRaWAN MAC-layer frame parser and ABP crypto.

Handles uplink data frames (Unconfirmed / Confirmed Data Up) with
ABP session keys for MIC verification and payload decryption.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import cmac


# ======================================================================
# Frame types
# ======================================================================

MTYPE_JOIN_REQUEST = 0b000
MTYPE_JOIN_ACCEPT = 0b001
MTYPE_UNCONFIRMED_UP = 0b010
MTYPE_UNCONFIRMED_DOWN = 0b011
MTYPE_CONFIRMED_UP = 0b100
MTYPE_CONFIRMED_DOWN = 0b101

MTYPE_NAMES = {
    0b000: "Join Request",
    0b001: "Join Accept",
    0b010: "Unconfirmed Data Up",
    0b011: "Unconfirmed Data Down",
    0b100: "Confirmed Data Up",
    0b101: "Confirmed Data Down",
    0b110: "RFU",
    0b111: "Proprietary",
}


@dataclass
class LoRaWANFrame:
    """Parsed LoRaWAN MAC frame."""
    raw: bytes

    # MHDR
    mtype: int = 0
    mtype_name: str = ""
    major: int = 0

    # FHDR
    dev_addr: int = 0
    f_ctrl: int = 0
    f_cnt: int = 0
    f_opts: bytes = b""

    # ADR flags (from FCtrl)
    adr: bool = False
    ack: bool = False
    f_opts_len: int = 0

    # Payload
    f_port: int | None = None
    frm_payload: bytes = b""

    # MIC
    mic: bytes = b""

    # Decode status
    mic_ok: bool | None = None   # None = not checked
    payload_decrypted: bytes | None = None

    def summary(self) -> str:
        lines = [
            f"  Type     : {self.mtype_name}",
            f"  DevAddr  : {self.dev_addr:08X}",
            f"  FCnt     : {self.f_cnt}",
            f"  FPort    : {self.f_port}",
            f"  FCtrl    : ADR={self.adr} ACK={self.ack} FOptsLen={self.f_opts_len}",
        ]
        if self.f_opts:
            lines.append(f"  FOpts    : {self.f_opts.hex()}")
        lines.append(f"  Payload  : {self.frm_payload.hex()}")
        if self.payload_decrypted is not None:
            try:
                text = self.payload_decrypted.decode("utf-8", errors="replace")
                lines.append(f"  Decrypted: {self.payload_decrypted.hex()}  ({text})")
            except Exception:
                lines.append(f"  Decrypted: {self.payload_decrypted.hex()}")
        mic_status = {True: "OK", False: "FAIL", None: "not checked"}[self.mic_ok]
        lines.append(f"  MIC      : {self.mic.hex()} ({mic_status})")
        return "\n".join(lines)


# ======================================================================
# Frame parsing
# ======================================================================

def parse_lorawan(data: bytes) -> LoRaWANFrame | None:
    """Parse a LoRaWAN MAC frame from decoded LoRa payload bytes.

    Minimum frame: MHDR(1) + DevAddr(4) + FCtrl(1) + FCnt(2) + MIC(4) = 12
    """
    if len(data) < 12:
        return None

    frame = LoRaWANFrame(raw=data)

    # MHDR
    mhdr = data[0]
    frame.mtype = (mhdr >> 5) & 0x07
    frame.mtype_name = MTYPE_NAMES.get(frame.mtype, "Unknown")
    frame.major = mhdr & 0x03

    # Only handle data frames
    if frame.mtype not in (
        MTYPE_UNCONFIRMED_UP,
        MTYPE_UNCONFIRMED_DOWN,
        MTYPE_CONFIRMED_UP,
        MTYPE_CONFIRMED_DOWN,
    ):
        return frame

    # MIC is last 4 bytes
    frame.mic = data[-4:]
    mac_payload = data[1:-4]

    if len(mac_payload) < 7:
        return None

    # FHDR
    frame.dev_addr = struct.unpack_from("<I", mac_payload, 0)[0]
    frame.f_ctrl = mac_payload[4]
    frame.f_cnt = struct.unpack_from("<H", mac_payload, 5)[0]

    # FCtrl bits (uplink)
    frame.adr = bool(frame.f_ctrl & 0x80)
    frame.ack = bool(frame.f_ctrl & 0x40)
    frame.f_opts_len = frame.f_ctrl & 0x0F

    fhdr_len = 7 + frame.f_opts_len
    if fhdr_len > len(mac_payload):
        return None

    frame.f_opts = mac_payload[7: 7 + frame.f_opts_len]

    # FPort + FRMPayload
    remaining = mac_payload[fhdr_len:]
    if remaining:
        frame.f_port = remaining[0]
        frame.frm_payload = remaining[1:]

    return frame


# ======================================================================
# MIC verification (AES-128-CMAC, LoRaWAN 1.0.x)
# ======================================================================

def verify_mic(frame: LoRaWANFrame, nwk_s_key: bytes) -> bool:
    """Verify the MIC of a LoRaWAN 1.0 uplink data frame.

    MIC = cmac(NwkSKey, B0 | msg)[0:4]
    B0 = 0x49 | 0x00..0x00(4) | dir(1) | DevAddr(4) | FCntUp(4) | 0x00 | len(msg)(1)
    """
    is_uplink = frame.mtype in (MTYPE_UNCONFIRMED_UP, MTYPE_CONFIRMED_UP)
    direction = 0 if is_uplink else 1

    msg = frame.raw[:-4]  # everything except MIC

    b0 = bytearray(16)
    b0[0] = 0x49
    # bytes 1-4 = 0x00 (already)
    b0[5] = direction
    struct.pack_into("<I", b0, 6, frame.dev_addr)
    struct.pack_into("<I", b0, 10, frame.f_cnt)  # 32-bit, upper 16 assumed 0
    # b0[14] = 0x00
    b0[15] = len(msg)

    c = cmac.CMAC(algorithms.AES128(nwk_s_key))
    c.update(bytes(b0) + msg)
    full_cmac = c.finalize()
    computed_mic = full_cmac[:4]

    frame.mic_ok = computed_mic == frame.mic
    return frame.mic_ok


# ======================================================================
# Payload decryption (AES-128 CTR, LoRaWAN 1.0.x)
# ======================================================================

def decrypt_payload(frame: LoRaWANFrame, app_s_key: bytes) -> bytes:
    """Decrypt FRMPayload of a LoRaWAN 1.0 data frame.

    Uses AES-128 in ECB mode to generate a key stream:
        S_i = AES(key, A_i)
    where A_i = 0x01 | 0x00..0x00(4) | dir | DevAddr | FCnt(4) | 0x00 | i
    Then plaintext = FRMPayload XOR (S_1 | S_2 | ...)

    If FPort == 0, use NwkSKey; otherwise use AppSKey.
    """
    if not frame.frm_payload:
        frame.payload_decrypted = b""
        return b""

    is_uplink = frame.mtype in (MTYPE_UNCONFIRMED_UP, MTYPE_CONFIRMED_UP)
    direction = 0 if is_uplink else 1

    payload = frame.frm_payload
    n_blocks = (len(payload) + 15) // 16
    key_stream = bytearray()

    cipher_ecb = Cipher(algorithms.AES128(app_s_key), modes.ECB())

    for i in range(1, n_blocks + 1):
        a_block = bytearray(16)
        a_block[0] = 0x01
        a_block[5] = direction
        struct.pack_into("<I", a_block, 6, frame.dev_addr)
        struct.pack_into("<I", a_block, 10, frame.f_cnt)
        a_block[15] = i

        enc = cipher_ecb.encryptor()
        key_stream.extend(enc.update(bytes(a_block)) + enc.finalize())

    decrypted = bytes(p ^ k for p, k in zip(payload, key_stream))
    frame.payload_decrypted = decrypted
    return decrypted
