"""Channel plan and radio constants for US915 sub-band 2."""

# US915 Sub-band 2 uplink channels (125 kHz BW)
US915_SB2_CHANNELS: dict[int, float] = {
    8: 903.9e6,
    9: 904.1e6,
    10: 904.3e6,
    11: 904.5e6,
    12: 904.7e6,
    13: 904.9e6,
    14: 905.1e6,
    15: 905.3e6,
}

# Center frequency to capture all sub-band 2 channels
US915_SB2_CENTER = 904.6e6

# RTL-SDR capture sample rate (must cover all channels with margin)
CAPTURE_FS = 2_000_000  # 2 MS/s
