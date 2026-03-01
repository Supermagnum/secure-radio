# Covert Stack — Minimum Technical Implementation Specification

**Purpose:** Targeted changes required to integrate cryptographically-keyed GDSS masking
into gr-qradiolink + gr-linux-crypto on GNU Radio 3.10+

---

## 1. Overview of Required Changes

Three distinct tasks. Everything else is flowgraph wiring.

| Task | Scope | Difficulty |
|------|-------|------------|
| T1: Keyed GDSS masking | Modify GDSS spreader C++ block | Medium |
| T2: Sync burst timing | Python flowgraph + HKDF derivation | Low |
| T3: Key derivation wiring | Python HKDF → kernel keyring | Low |

---

## 2. T1 — Keyed GDSS Masking

### What to find

**File:** `gr-qradiolink/lib/gdss_spreader_cc_impl.cc`
**Header:** `gr-qradiolink/include/gnuradio/qradiolink/gdss_spreader_cc.h`
**GRC block:** `gr-qradiolink/grc/qradiolink_gdss_spreader_cc.block.yml`

### What to change

The spreader currently generates Gaussian masking values internally.
Replace the internal random source with a keyed ChaCha20 keystream
passed through a Box-Muller transform.

#### Step 1 — Locate the Gaussian generation in the spreader

Find where IQ masking values are generated. Look for:
```cpp
// Something resembling this pattern:
float mask_i = gaussian_distribution(rng);
float mask_q = gaussian_distribution(rng);
// Followed by:
out[i] = gr_complex(in[i].real() * std::abs(mask_i),
                    in[i].imag() * std::abs(mask_q));
```

The exact variable names will differ but the pattern — multiplication of
I and Q components by absolute values of Gaussian samples — is the core
of the GDSS operation per Shakeel et al. (2023).

#### Step 2 — Add ChaCha20 keystream source

Add to `gdss_spreader_cc_impl.h`:
```cpp
#include <openssl/evp.h>   // or use libsodium chacha20 directly

private:
    std::vector<uint8_t> d_key;       // 32 bytes
    std::vector<uint8_t> d_nonce;     // 12 bytes (96-bit)
    uint64_t d_counter;               // ChaCha20 block counter
    EVP_CIPHER_CTX* d_chacha_ctx;

    // Fills buffer with ChaCha20 keystream bytes
    void fill_keystream(uint8_t* buf, size_t len);

    // Box-Muller: converts two uniform floats [0,1) to one Gaussian sample
    float box_muller(float u1, float u2);
```

#### Step 3 — Implement keystream fill

```cpp
void gdss_spreader_cc_impl::fill_keystream(uint8_t* buf, size_t len) {
    // ChaCha20 encryption of zero buffer = raw keystream
    static const std::vector<uint8_t> zeros(len, 0);
    int outlen = 0;
    EVP_EncryptUpdate(d_chacha_ctx, buf, &outlen, zeros.data(), len);
}
```

**Alternative — use libsodium (simpler, preferred if available):**
```cpp
#include <sodium.h>

void gdss_spreader_cc_impl::fill_keystream(uint8_t* buf, size_t len) {
    // nonce must be extended to 192-bit for XChaCha20, or manage
    // counter manually for standard ChaCha20 (96-bit nonce + 32-bit ctr)
    crypto_stream_chacha20_ietf(buf, len, d_nonce.data(),
                                 d_key.data());
}
```

#### Step 4 — Box-Muller transform

Converts pairs of uniform random bytes → Gaussian sample.
Call twice per chip (once for I, once for Q).

```cpp
float gdss_spreader_cc_impl::box_muller(float u1, float u2) {
    // u1, u2 must be in (0, 1] — exclude exact zero
    if (u1 < 1e-10f) u1 = 1e-10f;
    return std::sqrt(-2.0f * std::log(u1)) * std::cos(2.0f * M_PI * u2);
}
```

Convert raw keystream bytes to uniform floats:
```cpp
// Pull 4 bytes, interpret as uint32, scale to (0,1]
float uniform_from_bytes(const uint8_t* b) {
    uint32_t v;
    std::memcpy(&v, b, 4);
    return (static_cast<float>(v) + 0.5f) / 4294967296.0f;  // / 2^32
}
```

#### Step 5 — Replace masking loop

```cpp
// Per-chip in the work() function:
// Allocate keystream buffer: 16 bytes per chip (4 floats × 4 bytes)
std::vector<uint8_t> ks(noutput_items * 16);
fill_keystream(ks.data(), ks.size());

for (int i = 0; i < noutput_items; i++) {
    const uint8_t* base = ks.data() + i * 16;

    float u1_i = uniform_from_bytes(base + 0);
    float u2_i = uniform_from_bytes(base + 4);
    float u1_q = uniform_from_bytes(base + 8);
    float u2_q = uniform_from_bytes(base + 12);

    float mask_i = std::abs(box_muller(u1_i, u2_i));
    float mask_q = std::abs(box_muller(u1_q, u2_q));

    // Preserve quadrant (original GDSS design constraint)
    out[i] = gr_complex(in[i].real() * mask_i,
                        in[i].imag() * mask_q);
}
```

#### Step 6 — Constructor: accept key parameter

Modify the block factory to accept a 32-byte key:
```cpp
// In gdss_spreader_cc.h public interface:
static sptr make(int spreading_factor,
                 const std::vector<uint8_t>& chacha_key,
                 const std::vector<uint8_t>& chacha_nonce);
```

Update GRC block YAML to expose key/nonce parameters:
```yaml
# In qradiolink_gdss_spreader_cc.block.yml — add parameters:
parameters:
  - id: chacha_key
    label: 'ChaCha20 Key (32 bytes hex)'
    dtype: raw
  - id: chacha_nonce
    label: 'ChaCha20 Nonce (12 bytes hex)'
    dtype: raw
```

#### Step 7 — Counter management for resync

ChaCha20 supports random access via its 32-bit block counter.
Each block = 64 bytes of keystream.

```cpp
// Seek to a specific chip position (for resync after timing slip):
void gdss_spreader_cc_impl::seek_to_chip(uint64_t chip_index) {
    // Each chip uses 16 bytes → chips_per_block = 4
    uint32_t block = static_cast<uint32_t>(chip_index / 4);
    // Reinitialise context with updated counter
    // (OpenSSL EVP does not expose counter directly —
    //  use libsodium crypto_stream_chacha20_ietf_xor with counter prefix,
    //  or maintain position by tracking total bytes consumed)
    d_counter = block;
}
```

**Practical note:** For the sync recovery path, it is simpler to
re-initialise the entire ChaCha20 context with the correct nonce
derived from the timestamp, rather than seeking. See T2.

---

## 3. T2 — Sync Burst Timing Randomisation

### What to find

The sync burst is transmitted using the existing DSSS spreader block:
**`gr-qradiolink/lib/dsss_spreader_cc_impl.cc`**

The timing randomisation is implemented in Python at the flowgraph level,
not inside the C++ block.

### What to build (Python)

```python
import numpy as np
from Crypto.Cipher import ChaCha20          # pycryptodome
from gnuradio import qradiolink, linux_crypto

def derive_sync_schedule(master_key: bytes, session_id: int,
                          window_ms: int = 50) -> callable:
    """
    Returns a function that, given a nominal epoch (integer milliseconds
    since session start), returns the actual TX offset in milliseconds.
    Offset is deterministic for both TX and RX given the same master_key.
    """
    # Domain-separated subkey for sync timing
    import hashlib, hmac
    sync_key = hmac.new(master_key,
                        b'sync-timing-v1' + session_id.to_bytes(8, 'big'),
                        hashlib.sha256).digest()

    def get_offset(epoch_ms: int) -> int:
        # Use ChaCha20 keystream indexed by epoch to get deterministic offset
        nonce = epoch_ms.to_bytes(8, 'little') + b'\x00' * 4  # 12 bytes
        cipher = ChaCha20.new(key=sync_key, nonce=nonce)
        rand_bytes = cipher.encrypt(b'\x00' * 4)
        raw = int.from_bytes(rand_bytes, 'little')
        # Scale to ±window_ms
        return int((raw / 0xFFFFFFFF) * 2 * window_ms) - window_ms

    return get_offset
```

### Sync burst PN sequence keying

The DSSS spreader accepts a PN sequence parameter. Generate it from Key₃:

```python
def derive_sync_pn_sequence(master_key: bytes, session_id: int,
                              chips: int = 10000) -> np.ndarray:
    """
    Returns a binary PN sequence derived from the session key.
    Both TX and RX generate identical sequences given same inputs.
    """
    import hashlib, hmac
    pn_key = hmac.new(master_key,
                      b'sync-pn-v1' + session_id.to_bytes(8, 'big'),
                      hashlib.sha256).digest()

    nonce = b'\x00' * 12
    cipher = ChaCha20.new(key=pn_key, nonce=nonce)
    raw = cipher.encrypt(bytes(chips // 8 + 1))

    # Unpack bytes to bits, map to {-1, +1}
    bits = np.unpackbits(np.frombuffer(raw, dtype=np.uint8))[:chips]
    return bits.astype(np.float32) * 2 - 1   # {0,1} → {-1,+1}
```

### Sync burst envelope shaping

Apply Gaussian envelope to make burst resemble natural static:

```python
def gaussian_envelope(samples: np.ndarray, rise_fraction: float = 0.1
                       ) -> np.ndarray:
    """
    Applies a Gaussian amplitude envelope to a burst.
    rise_fraction: fraction of burst used for rise/fall (each side).
    """
    n = len(samples)
    env = np.ones(n)
    flank = int(n * rise_fraction)
    # Gaussian ramp
    x = np.linspace(-3, 0, flank)
    ramp = np.exp(-x**2 / 2)
    ramp = ramp / ramp[-1]   # Normalise peak to 1.0
    env[:flank] = ramp
    env[-flank:] = ramp[::-1]
    return samples * env
```

---

## 4. T3 — Key Derivation and Keyring Wiring

### HKDF derivation (Python, run once at session start)

```python
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_session_keys(ecdh_shared_secret: bytes,
                         salt: bytes = None) -> dict:
    """
    Derives all session subkeys from ECDH shared secret via HKDF.
    Returns dict with named keys, each 32 bytes.
    """
    if salt is None:
        salt = bytes(32)   # Zero salt if not provided

    def hkdf_expand(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info
        ).derive(ecdh_shared_secret)

    return {
        'payload_enc':    hkdf_expand(b'payload-chacha20poly1305-v1'),
        'gdss_masking':   hkdf_expand(b'gdss-chacha20-masking-v1'),
        'sync_pn':        hkdf_expand(b'sync-dsss-pn-sequence-v1'),
        'sync_timing':    hkdf_expand(b'sync-burst-timing-offset-v1'),
    }
```

### Store in kernel keyring (gr-linux-crypto)

```python
from gr_linux_crypto.python.keyring_helper import KeyringHelper

def store_session_keys(keys: dict) -> dict:
    """Store derived keys in kernel keyring. Returns keyring IDs."""
    helper = KeyringHelper()
    ids = {}
    for name, key_bytes in keys.items():
        ids[name] = helper.add_key('user', f'sdr_session_{name}', key_bytes)
    return ids
```

### Retrieve GDSS masking key for block initialisation

```python
from gr_linux_crypto.python.keyring_helper import KeyringHelper

def load_gdss_key(keyring_id: int) -> bytes:
    helper = KeyringHelper()
    return helper.get_key(keyring_id)
```

### ECDH shared secret from GnuPG BrainpoolP256r1

Using gr-linux-crypto's CryptoHelpers:

```python
from gr_linux_crypto.crypto_helpers import CryptoHelpers

def get_shared_secret_from_gnupg(
        my_private_key_pem: bytes,
        peer_public_key_pem: bytes) -> bytes:
    """
    Perform ECDH using pre-existing BrainpoolP256r1 keys.
    Keys are loaded from GnuPG keyring externally and passed as PEM.
    """
    crypto = CryptoHelpers()
    private_key = crypto.load_brainpool_private_key(my_private_key_pem)
    public_key  = crypto.load_brainpool_public_key(peer_public_key_pem)
    return crypto.brainpool_ecdh(private_key, public_key)
```

**Exporting key material from GnuPG for use above:**
```bash
# Export public key as PEM-compatible format
# (GnuPG uses OpenPGP format; extract raw ECC key via gpgsm or python-gnupg)
gpg --export-ssh-key YOUR_KEY_ID    # Not PEM — needs conversion

# Simpler: use gpg --export and parse with python-gnupg + cryptography lib
# Or: generate a separate Brainpool keypair via gr-linux-crypto,
#     sign and certify it with GnuPG for identity binding
```

**Practical note:** GnuPG's internal key format is OpenPGP (RFC 4880),
not raw PEM. The cleanest path is to use `gr-linux-crypto`'s
`generate_brainpool_keypair()` to create the operational ECDH keys,
then sign those public keys with GnuPG to bind them to operator identity.
The GnuPG web-of-trust handles authentication; the Brainpool keypair
handles the actual ECDH session key derivation.

---

## 5. Nonce Management for ChaCha20

Critical: nonce reuse destroys security. Two nonces in play:

### GDSS masking nonce

Derive from session ID + transmission sequence number:
```python
def gdss_nonce(session_id: int, tx_seq: int) -> bytes:
    """12-byte nonce for GDSS ChaCha20 masking stream."""
    return (session_id.to_bytes(4, 'big') +
            tx_seq.to_bytes(8, 'big'))
```

Pass to GDSS spreader block at start of each transmission frame.
TX sequence number increments monotonically; persist across power cycles
in a small state file or kernel keyring entry.

### Payload encryption nonce (ChaCha20-Poly1305)

Same pattern, different domain:
```python
def payload_nonce(session_id: int, tx_seq: int) -> bytes:
    """96-bit nonce for payload ChaCha20-Poly1305."""
    return (b'pay' +
            session_id.to_bytes(4, 'big') +
            tx_seq.to_bytes(5, 'big'))
```

---

## 6. GNU Radio Flowgraph Connection (Transmit Path)

```
[File/Audio Source]
        |
[ChaCha20-Poly1305 Encrypt]   ← payload_enc key + payload nonce
        |
[LDPC Encoder]                ← rate 1/2, blocklen 2304
        |
[GDSS Spreader (modified)]    ← gdss_masking key + gdss nonce
        |                        spreading factor N=256
[SOQPSK Modulator]
        |
[SDR Sink]                    ← LimeSDR / USRP / PlutoSDR
```

**Sync burst injection** (separate tagged stream or scheduled source):
```
[DSSS Spreader]               ← session-keyed PN sequence
        |
[Gaussian Envelope Shape]     ← custom Python block (T2 above)
        |
[Burst Power Calibration]     ← +3 to +6 dB over noise floor
        |
[Mux into TX stream]          ← at randomised timing offset
```

---

## 7. Receive Path — Keystream Synchronisation

The receiver derives the identical ChaCha20 keystream given:
- Same 32-byte `gdss_masking` key
- Same 12-byte nonce (session ID + TX sequence number)

TX sequence number is conveyed in the sync burst payload (32 bits
sufficient for ~136 years at 1 tx/second). The GDSS despreader
needs the same keyed modification as the spreader (symmetric operation).

**GDSS despreader modification:** Identical to spreader — generate same
Gaussian masking values from keyed ChaCha20, divide (rather than multiply)
the received IQ components by the absolute masking values before passing
to the SOQPSK demodulator.

```cpp
// In gdss_despreader_cc_impl.cc work() function:
// (after generating identical mask_i, mask_q as spreader)
out[i] = gr_complex(in[i].real() / mask_i,
                    in[i].imag() / mask_q);
```

Guard against division by very small values:
```cpp
const float MIN_MASK = 1e-4f;
mask_i = std::max(mask_i, MIN_MASK);
mask_q = std::max(mask_q, MIN_MASK);
```

---

## 8. Dependencies

All should be present on a standard GNU Radio development system:

```bash
# Required for T1 (ChaCha20 in C++)
# Option A — OpenSSL (likely already present):
apt-get install libssl-dev

# Option B — libsodium (cleaner API, preferred):
apt-get install libsodium-dev

# Required for T2/T3 (Python)
pip install pycryptodome cryptography

# gr-linux-crypto (already in scope):
# provides: CryptoHelpers, KeyringHelper, HKDF
# https://github.com/Supermagnum/gr-linux-crypto

# gr-qradiolink (already in scope):
# provides: GDSS spreader/despreader, DSSS spreader, SOQPSK, LDPC
# https://github.com/Supermagnum/gr-qradiolink
```

---

## 9. Build System Changes for T1

Add libsodium (or OpenSSL EVP) to GDSS spreader CMake target:

```cmake
# In gr-qradiolink/lib/CMakeLists.txt
# Find and add to the gdss spreader target:

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM libsodium)

if(SODIUM_FOUND)
    target_link_libraries(gnuradio-qradiolink
        ${SODIUM_LIBRARIES})
    target_compile_definitions(gnuradio-qradiolink
        PRIVATE HAVE_LIBSODIUM=1)
else()
    # Fall back to OpenSSL EVP
    find_package(OpenSSL REQUIRED)
    target_link_libraries(gnuradio-qradiolink
        OpenSSL::SSL OpenSSL::Crypto)
endif()
```

---

## 10. Security Notes for Implementer

1. **Never reuse nonce + key combination.** TX sequence number must
   persist across power cycles. Write to file or kernel keyring on
   every increment before transmitting.

2. **Domain separation is mandatory.** The four HKDF `info` strings in T3
   ensure the four derived keys are cryptographically independent even
   though they share a root secret.

3. **The GDSS masking key is a transmission security parameter, not just
   a signal processing parameter.** An adversary with this key can strip
   the masking and detect the signal. Treat it with the same care as the
   payload encryption key.

4. **The modified GDSS spreader should not fall back to internal random
   generation if no key is provided.** Either require a key or fail loudly.
   Silent fallback to unkeyed operation is a dangerous failure mode.

5. **SOQPSK unit tests for gr-qradiolink are noted as planned but not
   yet implemented.** Add integration tests for the keyed GDSS path
   before treating it as production-ready.

---

## 11. Files Summary

| File | Action | Task |
|------|--------|------|
| `gr-qradiolink/lib/gdss_spreader_cc_impl.cc` | Modify: replace Gaussian source with keyed ChaCha20 + Box-Muller | T1 |
| `gr-qradiolink/lib/gdss_spreader_cc_impl.h` | Modify: add key/nonce/counter members, fill_keystream(), box_muller() | T1 |
| `gr-qradiolink/lib/gdss_despreader_cc_impl.cc` | Modify: same as spreader, divide instead of multiply | T1 |
| `gr-qradiolink/lib/gdss_despreader_cc_impl.h` | Modify: same as spreader header | T1 |
| `gr-qradiolink/grc/qradiolink_gdss_spreader_cc.block.yml` | Modify: add key/nonce parameters | T1 |
| `gr-qradiolink/grc/qradiolink_gdss_despreader_cc.block.yml` | Modify: add key/nonce parameters | T1 |
| `gr-qradiolink/lib/CMakeLists.txt` | Modify: add libsodium or OpenSSL link target | T1 |
| `session_key_derivation.py` | New: HKDF derivation + keyring storage (T3 code above) | T3 |
| `sync_burst_utils.py` | New: PN sequence + envelope shaping + timing offset (T2 code above) | T2 |
| `covert_tx_flowgraph.py` | New: end-to-end GNU Radio flowgraph | Integration |
| `covert_rx_flowgraph.py` | New: end-to-end GNU Radio receive flowgraph | Integration |

---

*Specification based on: Shakeel et al., "Gaussian-Distributed Spread-Spectrum
for Covert Communications," Sensors 23(8):4081, 2023.
Modules: gr-qradiolink (github.com/Supermagnum/gr-qradiolink),
gr-linux-crypto (github.com/Supermagnum/gr-linux-crypto).*
