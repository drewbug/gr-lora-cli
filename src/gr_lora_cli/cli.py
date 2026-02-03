"""CLI entry-point for gr-lora-cli: decode LoRaWAN frames via gr-lora_sdr."""

from __future__ import annotations

import argparse
import sys
import time

from .capture import CAPTURE_FS, US915_SB2_CENTER, US915_SB2_CHANNELS
from .flowgraph import DecodedFrame, LoRaReceiver
from .lorawan import decrypt_payload, parse_lorawan, verify_mic


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="gr-lora-cli",
        description="Decode LoRaWAN uplink frames from RTL-SDR "
        "(US915 sub-band 2, BW 125 kHz)",
    )
    parser.add_argument(
        "--sf",
        type=int,
        default=7,
        choices=range(7, 13),
        help="Spreading factor (default: 7)",
    )
    parser.add_argument(
        "--gain",
        type=float,
        default=40.0,
        help="RTL-SDR gain in dB (default: 40)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        help="Capture duration in seconds (0 = continuous, default: 0)",
    )
    parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Read IQ from raw cu8 file instead of live capture",
    )
    parser.add_argument(
        "--channel",
        type=int,
        default=None,
        help="Listen on a single channel number (8-15) instead of all",
    )
    parser.add_argument(
        "--nwk-key",
        type=str,
        default="00000000000000000000000000000000",
        help="NwkSKey (hex, 32 chars) for MIC verification (default: all zeros)",
    )
    parser.add_argument(
        "--app-key",
        type=str,
        default="00000000000000000000000000000000",
        help="AppSKey (hex, 32 chars) for payload decryption (default: all zeros)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Show PHY payload only; skip LoRaWAN parsing",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )
    args = parser.parse_args()

    nwk_key = bytes.fromhex(args.nwk_key)
    app_key = bytes.fromhex(args.app_key)

    # Select channels
    if args.channel is not None:
        if args.channel not in US915_SB2_CHANNELS:
            print(
                f"Error: channel {args.channel} not in sub-band 2 "
                f"(valid: {sorted(US915_SB2_CHANNELS)})",
                file=sys.stderr,
            )
            sys.exit(1)
        channels = {args.channel: US915_SB2_CHANNELS[args.channel]}
    else:
        channels = US915_SB2_CHANNELS

    print(f"gr-lora-cli | SF{args.sf} BW125 | US915 sub-band 2 | gr-lora_sdr")
    print(
        f"Channels: {sorted(channels.keys())}  "
        f"({min(channels.values()) / 1e6:.1f} – "
        f"{max(channels.values()) / 1e6:.1f} MHz)"
    )
    print(f"Gain: {args.gain} dB | Capture rate: {CAPTURE_FS / 1e6:.1f} MS/s")
    print(f"NwkSKey: {nwk_key.hex()}")
    print(f"AppSKey: {app_key.hex()}")
    print("─" * 60)
    sys.stdout.flush()

    receiver = LoRaReceiver(
        sf=args.sf,
        channels=channels,
        center_freq=US915_SB2_CENTER,
        capture_fs=CAPTURE_FS,
        gain=args.gain,
        file_path=args.file,
    )

    frame_count = 0

    if args.file:
        print(f"Reading IQ from {args.file} ...")
    print("Listening...\n", flush=True)

    receiver.start()

    try:
        if args.file:
            receiver.wait()
            time.sleep(0.5)
            for frame in receiver.get_frames():
                _print_frame(frame, nwk_key, app_key, args.raw, args.verbose)
                frame_count += 1
        else:
            deadline = (
                time.time() + args.duration if args.duration > 0 else None
            )
            while True:
                time.sleep(0.5)
                for frame in receiver.get_frames():
                    _print_frame(frame, nwk_key, app_key, args.raw, args.verbose)
                    frame_count += 1
                if deadline and time.time() >= deadline:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        receiver.stop()
        import threading
        wait_thread = threading.Thread(target=receiver.wait, daemon=True)
        wait_thread.start()
        wait_thread.join(timeout=3)
        print(f"\nStopped. {frame_count} frame(s) decoded.", flush=True)


def _print_frame(
    decoded: DecodedFrame,
    nwk_key: bytes,
    app_key: bytes,
    raw: bool,
    verbose: bool,
) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] Frame on Ch {decoded.channel} ({decoded.freq_hz / 1e6:.1f} MHz)")
    print(f"  CR       : 4/{decoded.cr + 4}  CRC: {'OK' if decoded.crc_ok else 'FAIL'}")
    print(f"  PHY bytes: {decoded.payload.hex()}")

    if raw:
        print()
        return

    # Parse LoRaWAN
    wan_frame = parse_lorawan(decoded.payload)
    if wan_frame is None:
        print("  (not a valid LoRaWAN frame)")
        print()
        return

    verify_mic(wan_frame, nwk_key)
    if wan_frame.frm_payload:
        decrypt_payload(wan_frame, app_key)

    print(wan_frame.summary())
    print()


if __name__ == "__main__":
    main()
