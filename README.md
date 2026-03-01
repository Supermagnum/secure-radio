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
- An SDR transceiver capable of both RX and TX (e.g., USRP or compatible hardware). A example is [linux-radio.eu](https://linux-radio.eu/) , very suitable when available.
- A [Nitrokey](https://www.nitrokey.com/) hardware security module (approximately 10×15 mm) for secure key storage.

### Software
- [GNU Radio](https://www.gnuradio.org/) (with working knowledge of flowgraph construction).
- [gr-linux-crypto](https://github.com/Supermagnum/gr-linux-crypto/tree/master) — provides the `gr-openssl` and `gr-nacl` blocks used for encryption.
- [gr-qradiolink](https://github.com/Supermagnum/gr-qradiolink)
- [gr-opus](https://github.com/Supermagnum/gr-opus) — Opus audio codec block for GNU Radio.

### Optional
- [gr-rake](https://github.com/Supermagnum/gr-rake) — RAKE receiver for improved multipath performance.

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
2. make  TX and RX flowgraph files. (`.grc` file).
3. Ensure your Nitrokey is connected and your SDR hardware is recognized by the system.
4. Configure your center frequency, sample rate, and GDSS parameters to match your operating environment.
5. Run the flowgraph.

---

## Emergency Key Wipe

`gr-linux-crypto` includes an emergency key-clearing feature: if the Nitrokey is physically disconnected at any point, **all cached key material is immediately and securely erased from memory**. Because the Nitrokey is small (roughly 10×15 mm), it can be quickly removed and discarded/destroyed if needed. This significantly reduces the risk of key compromise under duress.

---

## License

Please refer to the individual component repositories for their respective licenses.

---

## Contributing

Pull requests and issues are welcome. If you test this on hardware not listed here, please open an issue describing your setup so others can benefit.


The covert stack md file lists the needed, experimental modifications to enable:

T1 — Keyed GDSS Masking (The Core Change)
The GDSS spreader already multiplies each chip's I and Q components by the absolute value of a Gaussian random sample — that is the existing masking operation that makes the signal look like noise.
The modification replaces where those Gaussian values come from.
Currently they come from an internal random number generator — unseeded, or seeded arbitrarily. The change swaps that source for a ChaCha20 keystream, fed through a Box-Muller transform to produce Gaussian-distributed values. The arithmetic the block performs on the IQ samples is identical. Only the source of the masking numbers changes.
The consequence is that the masking sequence is now:

Deterministic — the receiver can reproduce it exactly
Cryptographically keyed — nobody without the key can reproduce it
Seekable — ChaCha20's block counter allows jumping to any position, enabling resynchronisation

The despreader gets the symmetric change — it generates the identical masking sequence and divides rather than multiplies, recovering the original chips.
The Box-Muller transform is the mathematical bridge between the uniform random bytes that ChaCha20 produces and the Gaussian-distributed values that GDSS requires.

T2 — Sync Burst Timing and PN Sequence
Two things currently have no cryptographic basis:
The sync burst PN sequence — currently whatever the DSSS spreader defaults to. The modification derives it from the session key via ChaCha20, so it changes every session and is unknown to anyone without the key. The burst still looks like static. But now it is a session-specific static spike that only the intended receiver can recognise.
When the burst is transmitted — currently fixed or predictable. The modification derives a timing offset from the keystream, so the burst arrives at a randomised but deterministically predictable time within a window. Both ends agree on the exact offset because they share the key. A passive observer sees an irregular static spike that bears no obvious relationship to any transmission schedule.
The Gaussian envelope shaping is purely cosmetic — it rounds the edges of the burst so it resembles the rise-and-fall profile of natural impulse noise rather than a rectangular keyed signal.

T3 — Key Derivation and Storage Wiring
This is plumbing. It takes the single ECDH shared secret produced by the BrainpoolP256r1 key exchange and runs it through HKDF four times with different labels, producing four independent 32-byte keys — one for each purpose. It then stores those keys in the Linux kernel keyring so they never sit in a user-space file or Python variable during operation.
The HKDF step matters because using the same key for both payload encryption and GDSS masking would be cryptographically unsound — compromise of one context could leak information about the other. Domain separation via the info labels prevents that entirely.

The Net Effect of All Three Together
Before the modifications, the GDSS spreader is a signal processing block that produces noise-like output using internal randomness the receiver cannot predict. It is physically covert but cryptographically open — anyone who reverse-engineered the block could strip the masking.
After the modifications, the same block produces identical output on the wire, but the masking is now tied to a key that only the two endpoints hold. The receiver can strip the masking precisely because it holds the key. Nobody else can — not because the algorithm is secret, but because the key is.
The sync burst goes from a detectable, fixed, session-independent event to a session-unique, timing-randomised, cryptographically keyed event that only the intended receiver expects.
The key derivation wiring ensures all of this flows from a single root secret established through the existing GnuPG infrastructure, with no new key management burden on the operator.
