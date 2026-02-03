"""GNU Radio flowgraph using gr-lora_sdr for LoRa PHY decoding."""

from __future__ import annotations

import queue
import sys
from dataclasses import dataclass

try:
    from gnuradio import gr, blocks, filter as gr_filter
    from gnuradio.fft import window as gr_window
    from gnuradio import lora_sdr
    import pmt
except ImportError as e:
    _missing = str(e)
    if "lora_sdr" in _missing:
        print(
            "error: gr-lora_sdr not found.\n"
            "Install from: https://github.com/tapparelj/gr-lora_sdr",
            file=sys.stderr,
        )
    else:
        print(
            "error: GNU Radio Python bindings not found.\n"
            "Install GNU Radio: https://wiki.gnuradio.org/index.php/InstallingGR",
            file=sys.stderr,
        )
    sys.exit(1)

# LoRaWAN public sync word 0x34 — passed as a single byte;
# frame_sync internally expands to symbol values [24, 32].
LORAWAN_SYNC_WORD = [0x34]


@dataclass
class DecodedFrame:
    """A decoded LoRa PHY frame."""

    channel: int
    freq_hz: float
    payload: bytes
    crc_ok: bool
    cr: int


class _FrameSink(gr.basic_block):
    """Collects decoded frames from crc_verif message output."""

    def __init__(self, channel: int, freq_hz: float, frame_queue: queue.Queue):
        gr.basic_block.__init__(
            self, name=f"frame_sink_ch{channel}", in_sig=[], out_sig=[]
        )
        self.channel = channel
        self.freq_hz = freq_hz
        self.frame_queue = frame_queue
        self.message_port_register_in(pmt.intern("in"))
        self.set_msg_handler(pmt.intern("in"), self._handle_msg)

    def _handle_msg(self, msg):
        if not pmt.is_pair(msg):
            return
        meta = pmt.car(msg)
        data = pmt.cdr(msg)
        if not pmt.is_u8vector(data):
            return

        payload = bytes(pmt.u8vector_elements(data))
        crc_ok = True
        cr = 1

        if pmt.is_dict(meta):
            crc_key = pmt.intern("CRC")
            cr_key = pmt.intern("CR")
            if pmt.dict_has_key(meta, crc_key):
                crc_ok = bool(
                    pmt.to_long(pmt.dict_ref(meta, crc_key, pmt.PMT_NIL))
                )
            if pmt.dict_has_key(meta, cr_key):
                cr = pmt.to_long(pmt.dict_ref(meta, cr_key, pmt.PMT_NIL))

        self.frame_queue.put(
            DecodedFrame(
                channel=self.channel,
                freq_hz=self.freq_hz,
                payload=payload,
                crc_ok=crc_ok,
                cr=cr,
            )
        )


class LoRaReceiver(gr.top_block):
    """Multi-channel LoRa receiver using gr-lora_sdr decoder blocks.

    Supports both live RTL-SDR input and cu8 file input.
    Decoded frames are collected in a thread-safe queue.
    """

    def __init__(
        self,
        sf: int = 7,
        channels: dict[int, float] | None = None,
        center_freq: float = 904.6e6,
        capture_fs: float = 2_000_000,
        bw: float = 125_000,
        gain: float = 40,
        file_path: str | None = None,
        os_factor: int = 4,
    ):
        gr.top_block.__init__(self, "LoRa Receiver")

        from .capture import US915_SB2_CHANNELS

        self.frame_queue: queue.Queue[DecodedFrame] = queue.Queue()

        if channels is None:
            channels = US915_SB2_CHANNELS

        # --- Source ---
        if file_path:
            source_out = self._build_cu8_source(file_path)
        else:
            source_out = self._build_rtlsdr_source(center_freq, capture_fs, gain)

        # --- Per-channel decoder chains ---
        target_fs = int(bw * os_factor)
        decimation = int(capture_fs / target_fs)
        taps = gr_filter.firdes.low_pass(
            1, capture_fs, bw / 2, bw / 4, gr_window.WIN_HAMMING
        )
        ldro = 1 if sf >= 11 else 0  # Low Data Rate Optimization for SF11+ at BW125

        for ch_num, ch_freq in channels.items():
            freq_offset = ch_freq - center_freq

            xlat = gr_filter.freq_xlating_fir_filter_ccc(
                decimation, taps, freq_offset, int(capture_fs)
            )

            # gr-lora_sdr decoder chain
            sync = lora_sdr.frame_sync(
                int(ch_freq), int(bw), sf, False,
                LORAWAN_SYNC_WORD, os_factor, 8,
            )
            fft = lora_sdr.fft_demod(False, True)
            gray = lora_sdr.gray_mapping(False)
            deintlv = lora_sdr.deinterleaver(False)
            hamming = lora_sdr.hamming_dec(False)
            hdr = lora_sdr.header_decoder(False, 1, 255, True, 2, False)
            dewh = lora_sdr.dewhitening()
            crc = lora_sdr.crc_verif(0, False)
            sink = _FrameSink(ch_num, ch_freq, self.frame_queue)

            # Stream connections
            self.connect(
                source_out, xlat, sync, fft, gray,
                deintlv, hamming, hdr, dewh, crc,
            )
            self.connect(crc, blocks.null_sink(gr.sizeof_char))

            # Message connections
            self.msg_connect(hdr, "frame_info", sync, "frame_info")
            self.msg_connect(crc, "msg", sink, "in")

    def _build_cu8_source(self, file_path: str):
        """Read cu8 IQ file and output complex float samples."""
        file_src = blocks.file_source(gr.sizeof_char, file_path, repeat=False)
        to_float = blocks.uchar_to_float()
        offset = blocks.add_const_ff(-127.5)
        scale = blocks.multiply_const_ff(1.0 / 127.5)
        deinterleave = blocks.deinterleave(gr.sizeof_float)
        to_complex = blocks.float_to_complex()

        self.connect(file_src, to_float, offset, scale, deinterleave)
        self.connect((deinterleave, 0), (to_complex, 0))
        self.connect((deinterleave, 1), (to_complex, 1))
        return to_complex

    def _build_rtlsdr_source(self, center_freq, capture_fs, gain):
        """Create an RTL-SDR source via gr-osmosdr."""
        try:
            import osmosdr
        except ImportError:
            try:
                from gnuradio import osmosdr
            except ImportError:
                print(
                    "error: gr-osmosdr not found. Required for live RTL-SDR.\n"
                    "Install: apt install gr-osmosdr",
                    file=sys.stderr,
                )
                sys.exit(1)

        src = osmosdr.source(args="rtl=0")
        src.set_sample_rate(capture_fs)
        src.set_center_freq(center_freq)
        src.set_gain(gain)
        src.set_if_gain(40)
        src.set_bb_gain(20)
        src.set_antenna("")
        return src

    def get_frames(self) -> list[DecodedFrame]:
        """Drain the frame queue, returning all available decoded frames."""
        frames = []
        while True:
            try:
                frames.append(self.frame_queue.get_nowait())
            except queue.Empty:
                break
        return frames
