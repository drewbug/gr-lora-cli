"""End-to-end test: gr-lora_sdr TX/RX roundtrip + LoRaWAN parsing.

Requires: gnuradio, gr-lora_sdr (skips gracefully if not installed).
"""

import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, "src")

from gr_lora_cli.lorawan import decrypt_payload, parse_lorawan, verify_mic

try:
    from gnuradio import gr, blocks
    from gnuradio import lora_sdr
    import pmt

    HAS_GR_LORA = True
except ImportError:
    HAS_GR_LORA = False


def _build_lorawan_frame(payload: bytes, f_cnt: int = 0) -> bytes:
    """Construct a LoRaWAN frame with all-zeros keys (matching relay firmware)."""
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    dev_addr = 0x00000000
    nwk_key = bytes(16)
    app_key = bytes(16)

    n_blocks = (len(payload) + 15) // 16
    key_stream = bytearray()
    for i in range(1, n_blocks + 1):
        a_block = bytearray(16)
        a_block[0] = 0x01
        a_block[5] = 0
        struct.pack_into("<I", a_block, 6, dev_addr)
        struct.pack_into("<I", a_block, 10, f_cnt)
        a_block[15] = i
        enc = Cipher(algorithms.AES128(app_key), modes.ECB()).encryptor()
        key_stream.extend(enc.update(bytes(a_block)) + enc.finalize())

    encrypted = bytes(p ^ k for p, k in zip(payload, key_stream))

    msg = bytearray()
    msg.append(0x40)
    msg.extend(struct.pack("<I", dev_addr))
    msg.append(0x00)
    msg.extend(struct.pack("<H", f_cnt & 0xFFFF))
    msg.append(0x01)
    msg.extend(encrypted)

    b0 = bytearray(16)
    b0[0] = 0x49
    b0[5] = 0
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


def test_lorawan_frame_parsing():
    """Test LoRaWAN frame construction and parsing (no GNU Radio needed)."""
    relay_payload = b'"Hello" (-55.00 dBm, SNR: 9.50 dB)'
    frame_bytes = _build_lorawan_frame(relay_payload, f_cnt=1)

    frame = parse_lorawan(frame_bytes)
    assert frame is not None
    assert frame.dev_addr == 0x00000000
    assert frame.f_cnt == 1
    assert frame.f_port == 1

    assert verify_mic(frame, bytes(16))
    decrypted = decrypt_payload(frame, bytes(16))
    assert decrypted == relay_payload


def test_gr_lora_roundtrip():
    """TX via gr-lora_sdr modulator -> RX via gr-lora_sdr decoder."""
    if not HAS_GR_LORA:
        print("SKIP: gr-lora_sdr not installed")
        return

    import queue as queue_mod

    sf = 7
    bw = 125000
    cr = 1
    center_freq = 868100000
    samp_rate = int(bw * 4)
    os_factor = 4

    test_payload = "Hello LoRa"

    with tempfile.NamedTemporaryFile(suffix=".cf32", delete=False) as f:
        tmp_path = f.name

    try:
        # --- TX: generate IQ samples using gr-lora_sdr TX chain ---
        tx = gr.top_block("TX")
        strobe = blocks.message_strobe(pmt.intern(test_payload), 200)
        wh = lora_sdr.whitening(False, False)
        hdr_blk = lora_sdr.header(False, True, cr)
        add_crc_blk = lora_sdr.add_crc(True)
        hamm = lora_sdr.hamming_enc(cr, sf)
        intlv = lora_sdr.interleaver(cr, sf, 2, int(bw))
        gray_tx = lora_sdr.gray_demap(sf)
        mod = lora_sdr.modulate(sf, samp_rate, int(bw), [0x34], 128, 8)
        fsink = blocks.file_sink(gr.sizeof_gr_complex, tmp_path, append=False)

        tx.msg_connect(strobe, "strobe", wh, "msg")
        tx.connect(wh, hdr_blk, add_crc_blk, hamm, intlv, gray_tx, mod, fsink)

        tx.start()
        time.sleep(2)
        tx.stop()
        tx.wait()

        # --- RX: decode using gr-lora_sdr RX chain ---
        frame_queue = queue_mod.Queue()

        class TestSink(gr.basic_block):
            def __init__(self):
                gr.basic_block.__init__(
                    self, name="test_sink", in_sig=[], out_sig=[]
                )
                self.message_port_register_in(pmt.intern("in"))
                self.set_msg_handler(pmt.intern("in"), self._handle)

            def _handle(self, msg):
                if pmt.is_pair(msg):
                    data = pmt.cdr(msg)
                    if pmt.is_u8vector(data):
                        frame_queue.put(bytes(pmt.u8vector_elements(data)))

        rx = gr.top_block("RX")
        src = blocks.file_source(gr.sizeof_gr_complex, tmp_path, repeat=False)
        sync = lora_sdr.frame_sync(
            center_freq, int(bw), sf, False, [0x34], os_factor, 8
        )
        fft = lora_sdr.fft_demod(False, True)
        gray_rx = lora_sdr.gray_mapping(False)
        deintlv = lora_sdr.deinterleaver(False)
        hamming_dec = lora_sdr.hamming_dec(False)
        hdr_dec = lora_sdr.header_decoder(False, cr, 255, True, 2, False)
        dewh = lora_sdr.dewhitening()
        crc_blk = lora_sdr.crc_verif(0, False)
        sink = TestSink()

        rx.connect(
            src, sync, fft, gray_rx, deintlv,
            hamming_dec, hdr_dec, dewh, crc_blk,
        )
        rx.connect(crc_blk, blocks.null_sink(gr.sizeof_char))
        rx.msg_connect(hdr_dec, "frame_info", sync, "frame_info")
        rx.msg_connect(crc_blk, "msg", sink, "in")

        rx.start()
        rx.wait()

        # Collect decoded frames
        frames = []
        while True:
            try:
                frames.append(frame_queue.get(timeout=1.0))
            except queue_mod.Empty:
                break

        assert len(frames) > 0, "gr-lora_sdr did not decode any frames"

        expected = test_payload.encode("ascii")
        matching = [f for f in frames if f == expected]
        assert len(matching) > 0, (
            f"No frame matched expected payload.\n"
            f"Expected: {expected.hex()}\n"
            f"Got: {[f.hex() for f in frames]}"
        )

        print(f"PASS: {len(matching)}/{len(frames)} frames decoded correctly")

    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    test_lorawan_frame_parsing()
    test_gr_lora_roundtrip()
    print("\nAll E2E tests passed.")
