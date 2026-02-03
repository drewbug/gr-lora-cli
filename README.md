# gr-lora-cli

Decode LoRaWAN uplink frames from an RTL-SDR dongle using
[gr-lora_sdr](https://github.com/tapparelj/gr-lora_sdr). Targets US915
sub-band 2 (channels 8-15, 903.9-905.3 MHz, BW 125 kHz).

## Quick-start (Ubuntu 24.04)

### 1. System packages

```bash
sudo apt update
sudo apt install -y \
  gnuradio gnuradio-dev gr-osmosdr rtl-sdr \
  cmake build-essential libboost-dev libspdlog-dev \
  libvolk-dev pybind11-dev
```

### 2. Build & install gr-lora_sdr

```bash
git clone https://github.com/tapparelj/gr-lora_sdr.git /tmp/gr-lora_sdr
cd /tmp/gr-lora_sdr
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$HOME/.local
make -j$(nproc)
make install
```

Verify the library loads:

```bash
python3 -c "import sys; sys.path.insert(0,'$HOME/.local/lib/python3.12/site-packages'); from gnuradio.lora_sdr import lora_sdr_python; print('OK')"
```

### 3. Install gr-lora-cli

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone <this-repo> && cd gr-lora-cli-gr
uv sync
```

### 4. Run

Plug in an RTL-SDR dongle and:

```bash
uv run gr-lora-cli
```

Press Ctrl-C to stop.

## Options

```
--sf {7..12}       Spreading factor (default: 7)
--gain GAIN        RTL-SDR gain in dB (default: 40)
--duration SECS    Capture duration, 0 = continuous (default: 0)
--channel N        Single channel 8-15 instead of all
--nwk-key HEX     NwkSKey for MIC verification (default: all zeros)
--app-key HEX     AppSKey for payload decryption (default: all zeros)
--file PATH        Read IQ from a raw cu8 file instead of live capture
--raw              Show PHY payload only, skip LoRaWAN parsing
-v, --verbose      Verbose output
```

## Examples

Listen on all channels with default (all-zeros) keys:

```bash
uv run gr-lora-cli
```

Listen on channel 11 with custom ABP session keys:

```bash
uv run gr-lora-cli --channel 11 \
  --nwk-key 2B7E151628AED2A6ABF7158809CF4F3C \
  --app-key 3C4F09CF098815F7A6D2AE28166E157B
```

Capture IQ to a file, then decode offline:

```bash
rtl_sdr -f 904600000 -s 2000000 -g 40 -n 60000000 capture.cu8
uv run gr-lora-cli --file capture.cu8
```

## Tests

```bash
uv run python tests/test_lorawan.py   # LoRaWAN parsing & crypto (no hardware)
uv run python tests/test_e2e.py       # full TX/RX round-trip via gr-lora_sdr
```

## Architecture

```
cli.py          Entry point, argument parsing, frame display
flowgraph.py    GNU Radio flowgraph: channelization + per-channel gr-lora_sdr decode
capture.py      US915 sub-band 2 channel plan, sample rate constants
lorawan.py      LoRaWAN MAC parser, AES-CMAC MIC verification, AES-CTR decryption
```
