# secure-radio

**secure-radio** is a GNU Radio-based pipeline for encrypted, low-probability-of-detection voice communication over software-defined radio (SDR). It combines Gaussian-Distributed Spread-Spectrum (GDSS) with strong modern cryptography to make transmissions both difficult to detect and impossible to decrypt without the correct keys.

---

## How It Works

Transmissions pass through two independent layers of security:

**Layer 1 — GDSS (Gaussian-Distributed Spread-Spectrum)**
The signal is spread across a wide band of frequencies so that it resembles white noise to a passive observer. This makes the transmission difficult to detect and hard to jam. Because the source is not easily identifiable, physical location of the transmitter is also hard to determine — which provides some practical mitigation against coercion ("the $5 wrench attack").

**Layer 2 — BrainpoolP256r1 + ChaCha20Poly1305**
Audio is encrypted using elliptic-curve key agreement (BrainpoolP256r1) combined with ChaCha20-Poly1305 authenticated encryption. This combination is mathematically infeasible to brute-force with current or foreseeable computing.

### Signal Chain

**TX (Transmit):**
```
Audio → Opus → Encrypt → LDPC → PSK Mod → GDSS Spreader → RRC Filter → USRP
```

**RX (Receive):**
```
USRP → RRC Filter → GDSS Despreader → PSK Demod → LDPC Decode → Decrypt → Opus → Audio
```

---

## Requirements

### Hardware
- An SDR transceiver capable of both RX and TX (e.g., USRP or compatible hardware). See [linux-radio.eu](https://linux-radio.eu/) for available hardware.
- A [Nitrokey](https://www.nitrokey.com/) hardware security module (approximately 10×15 mm) for secure key storage.

### Software
- [GNU Radio](https://www.gnuradio.org/) (with working knowledge of flowgraph construction)
- [gr-linux-crypto](https://github.com/Supermagnum/gr-linux-crypto/tree/master) — provides the `gr-openssl` and `gr-nacl` blocks used for encryption
- [gr-qradiolink](https://github.com/Supermagnum/gr-qradiolink)
- [gr-opus](https://github.com/Supermagnum/gr-opus) — Opus audio codec block for GNU Radio

### Optional
- [gr-rake](https://github.com/Supermagnum/gr-rake) — RAKE receiver for improved multipath performance

---

## Installation

> **Note:** These instructions assume a working GNU Radio installation. Tested on Linux.

### 1. Install gr-linux-crypto

```bash
git clone https://github.com/Supermagnum/gr-linux-crypto.git
cd gr-linux-crypto
mkdir build && cd build
cmake ..
make
sudo make install
sudo ldconfig
```

Repeat the same `cmake` / `make` / `install` process for `gr-opus` and `gr-qradiolink`. Refer to each repository's own documentation for any additional dependencies.

### 2. Install gr-rake (optional)

```bash
git clone https://github.com/Supermagnum/gr-rake.git
cd gr-rake
mkdir build && cd build
cmake ..
make
sudo make install
```

### 3. Connect your Nitrokey

Plug in the Nitrokey before launching GNU Radio. The crypto blocks will use it for key storage and will refuse to operate without it.

---

## Usage

1. Open GNU Radio Companion.
2. Load the provided TX or RX flowgraph (`.grc` file) from this repository.
3. Ensure your Nitrokey is connected and your SDR hardware is recognized by the system.
4. Configure your center frequency, sample rate, and GDSS parameters to match your operating environment.
5. Run the flowgraph.

---

## Emergency Key Wipe

`gr-linux-crypto` includes an emergency key-clearing feature: if the Nitrokey is physically disconnected at any point, **all cached key material is immediately and securely erased from memory**. Because the Nitrokey is small (roughly 10×15 mm), it can be quickly removed and discarded if needed. This significantly reduces the risk of key compromise under duress.

---

## License

Please refer to the individual component repositories for their respective licenses.

---

## Contributing

Pull requests and issues are welcome. If you test this on hardware not listed here, please open an issue describing your setup so others can benefit.
