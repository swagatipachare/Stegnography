🔐 Audio Steganography Suite

The Audio Steganography Suite is a multi-functional Python application built with Streamlit that allows users to securely embed, extract, and analyze hidden messages in audio files using a wide variety of steganography and encryption techniques. It demonstrates both classic and modern approaches to covert communication using digital audio.

- 🌐 [Live Streamlit App](https://stegnography-app.streamlit.app/)

🧪 Features
🎵 LSB Steganography
Embed messages using Least Significant Bit manipulation.

🔐 AES Encryption
Secure full audio files using AES-256 with password-based protection.

🛡️ RSA Steganography
Asymmetric encryption and steganographic embedding using RSA keys.

🔢 QIM Steganography
Use Quantization Index Modulation for robust and noise-tolerant embedding.

🧩 Rubik’s Cube Scrambling
Encrypt message structure using permutation logic inspired by Rubik’s Cube.

🧠 Hybrid Techniques

QIM + LSB

AES + RSA

Rubik + AES

Adaptive QIM

📈 Analysis Tools

Waveform and frequency plots

Band Energy Ratio (BER) analysis

Statistical correlation between original and stego audio

Embedding capacity metrics (bits, chars, %)

🛠️ Tech Stack
Frontend: Streamlit

Backend: Python 3.x

Libraries:
numpy, scipy, matplotlib, wave, rsa, pycryptodome, cryptography, librosa (optional for deeper audio analysis)

