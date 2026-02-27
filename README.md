# secure-radio


One needs:
https://github.com/Supermagnum/gr-linux-crypto/tree/master with gr-openssl and gr-nacl
https://github.com/Supermagnumgr-qradiolink
https://github.com/Supermagnum/gr-opus
Optional:
https://github.com/Supermagnum/gr-rake

SDR radio hardware capable of RX/TX, https://linux-radio.eu/ when available.
Gnuradio skills.
Nitrokey.

TX Gnuradio flow : Audio → Opus → Encrypt → LDPC → PSK Mod → GDSS Spreader → RRC Filter → USRP

RX gnuradio flow: USRP → RRC Filter → GDSS Despreader → PSK Demod → LDPC Decode → Decrypt → Opus → Audio

This will provide two layers of security:
1: Gaussian-Distributed Spread-Spectrum (GDSS), it looks and sounds like white noise, difficult to detect, difficult to jam.

2: BrainpoolP256r1 + ChaCha20Poly1305.
 That is, at present day mathematical impossible to brute force.
The 5$ hammer method is somewhat mitigated by the factor that GDSS is difficult to detect, so the transmission sources is not so easy to locate.

Gr-linux-crypto also has the neat feature that if the Nitrokey is disconnected in a emergency situation,-
, all cached key data is immediately and securely cleared from memory. A nitrokey measures around 10x15mm so its easy to get rid of in a emergency.
