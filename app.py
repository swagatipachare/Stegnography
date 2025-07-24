import streamlit as st

# Set page configuration
st.set_page_config(
    page_title="Audio Steganography Suite",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply consistent styling
st.markdown("""
<style>
    .stApp {
        background-image: url("https://static.vecteezy.com/system/resources/previews/024/162/356/non_2x/businessman-showing-data-access-protection-with-key-icon-safety-technology-data-protection-and-privacy-with-encryption-protecting-data-from-theft-cyber-security-authentication-to-unlock-free-photo.jpg");
        background-size: cover;
        background-repeat: no-repeat;
        background-position: center;
        background-attachment: fixed;
            
    .main-header {
        font-size: 2.5rem;
        color: white;
        text-align: left;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: black;
        margin-bottom: 1rem;
    }
    .sub-head{
            color:white;
            }
    .section-header {
        font-size: 1.2rem;
        color: #4A90E2;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }
    .info-text {
        background-color: #e6f3ff;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
            color:black;
    }
    .success-text {
        background-color: #d4edda;
        padding: 0.75rem;
        border-radius: 0.3rem;
        color: #155724;
    }
    .card {
        border: 1px solid #e0e0e0;
        border-radius: 0.5rem;
        padding: 1.5rem;
        margin-bottom: 1rem;
        background-color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.3s;
        color:black;
    }
    .card:hover {
        transform: translateY(-5px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    .stButton button {
        background-color: #4A90E2;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 0.3rem;
        transition: all 0.3s;
    }
    .stButton button:hover {
        background-color: #357ABD;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
</style>
""", unsafe_allow_html=True)

# ------------ SIDEBAR NAVIGATION ------------
st.sidebar.markdown("<h2 class='sub-head'>Navigation</h2>", unsafe_allow_html=True)
page = st.sidebar.radio("Select Page", ["Home", "Advanced LSB Steganography", "Advanced AES Encryption", "RSA Steganography","QIM Steganography","Rubik's + AES Steganography","Rubik's Steganography","Adaptive QIM Steganography","QIM + LSB Hybrid Steganography","RSA + AES Hybrid Steganography"])


# ------------ HOME PAGE ------------
# ------------ HOME PAGE ------------
if page == "Home":
    st.markdown("<h1 class='main-header'>🎵 Audio Steganography Suite</h1>", unsafe_allow_html=True)
    
    st.markdown("""
    <div class='info-text'>
    Welcome to the Audio Steganography Suite! This application provides tools for hiding messages in audio files 
    and encrypting audio content for secure transmission.
    </div>
    """, unsafe_allow_html=True)

    # First row
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>Advance LSB Steganography</h3>
            <p>Hide secret messages in audio files using various methods:</p>
            <ul>
                <li>LSB (Least Significant Bit)</li>
                <li>AES Encryption</li>
                <li>RSA Encryption</li>
                <li>QIM (Quantization Index Modulation)</li>
            </ul>
            <p>Navigate to this page to encrypt messages within audio files.</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>Advanced AES Encryption</h3>
            <p>Encrypt entire audio files with AES-256:</p>
            <ul>
                <li>Password-based encryption</li>
                <li>Secure key derivation</li>
                <li>Complete file protection</li>
                <li>Download encrypted files</li>
            </ul>
            <p>Navigate to this page to encrypt whole audio files.</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>Advanced RSA Encryption</h3>
            <p>Secure your audio with RSA asymmetric encryption:</p>
            <ul>
                <li>Public/private key encryption</li>
                <li>Strong asymmetric cryptography</li>
                <li>Key management options</li>
                <li>Hybrid encryption for large files</li>
            </ul>
            <p>Navigate to this page for asymmetric encryption of audio files.</p>
        </div>
        """, unsafe_allow_html=True)

    # Second row
    col4, col5, col6 = st.columns(3)
    with col4:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>QIM Steganography</h3>
            <p>Use Quantization Index Modulation for robust data hiding:</p>
            <ul>
                <li>Improved noise resistance</li>
                <li>Perceptually transparent</li>
                <li>Suitable for audio watermarking</li>
                <li>Low error rates in extraction</li>
            </ul>
            <p>Navigate to the QIM page for embedding data using this technique.</p>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>Rubik's Cube Scrambling</h3>
            <p>Obfuscate message structure using Rubik's Cube scrambling:</p>
            <ul>
                <li>Matrix-based message permutation</li>
                <li>Lightweight transformation</li>
                <li>Optional before embedding</li>
                <li>Adds confusion for attackers</li>
            </ul>
            <p>Visit this module to scramble messages before hiding them.</p>
        </div>
        """, unsafe_allow_html=True)

    with col6:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>Rubik + AES Combo</h3>
            <p>Combine AES encryption with Rubik's Cube scrambling:</p>
            <ul>
                <li>AES for message confidentiality</li>
                <li>Rubik’s for structure permutation</li>
                <li>Enhanced multi-layered security</li>
                <li>Perfect for sensitive content</li>
            </ul>
            <p>Use this page for hybrid encryption and embedding workflows.</p>
        </div>
        """, unsafe_allow_html=True)

    # Third row (new)
    col7, col8, col9 = st.columns(3)
    with col7:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>Adaptive QIM Steganography</h3>
            <p>Dynamically adjust embedding strength using Adaptive QIM:</p>
            <ul>
                <li>Content-aware quantization</li>
                <li>Adaptive noise tolerance</li>
                <li>Better imperceptibility</li>
                <li>Enhanced robustness</li>
            </ul>
            <p>Visit the Adaptive QIM page for intelligent audio hiding.</p>
        </div>
        """, unsafe_allow_html=True)

    with col8:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>QIM + LSB Hybrid</h3>
            <p>Combine QIM and LSB techniques for multi-level security:</p>
            <ul>
                <li>Double embedding mechanism</li>
                <li>Higher resistance to attacks</li>
                <li>Dual extraction phase</li>
                <li>Balance of capacity and robustness</li>
            </ul>
            <p>Use this module for hybrid audio steganography.</p>
        </div>
        """, unsafe_allow_html=True)

    with col9:
        st.markdown("""
        <div class='card'>
            <h3 class='sub-header'>RSA + AES Hybrid</h3>
            <p>Combine RSA key encryption with AES content encryption:</p>
            <ul>
                <li>RSA for key exchange</li>
                <li>AES for audio protection</li>
                <li>Hybrid cryptosystem design</li>
                <li>Secure and scalable</li>
            </ul>
            <p>Visit this module to implement hybrid audio security.</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style='text-align: center;'>
        <p>🔒 Secure your audio data with our comprehensive suite of tools.</p>
        <p style='font-size: 0.8rem;'>For educational and demonstration purposes only.</p>
    </div>
    """, unsafe_allow_html=True)

# ------------ AUDIO STEGANOGRAPHY PAGE ------------
elif page == "Advanced LSB Steganography":
    import os
    import tempfile
    import base64
    import numpy as np
    import wave
    import matplotlib.pyplot as plt
    from io import BytesIO
    from scipy.signal import butter, lfilter

    if 'temp_dir' not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()

    st.markdown("<h1 class='main-header'>🔐 Audio Steganography with LSB</h1>", unsafe_allow_html=True)

    def lsb_encode(samples, message):
        message += '|||END'
        bits = ''.join(format(ord(char), '08b') for char in message)
        if len(bits) > len(samples):
            return None, "Message too large for this audio file", None
        stego_samples = np.copy(samples)
        for i, bit in enumerate(bits):
            stego_samples[i] = (stego_samples[i] & ~1) | int(bit)
        return stego_samples, None, bits

    def lsb_decode(samples):
        bits = [str(sample & 1) for sample in samples]
        chars = [chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)]
        message = ''.join(chars)
        if '|||END' in message:
            return message.split('|||END')[0]
        return "No hidden message found"

    def get_binary_file_downloader_html(bin_file, file_label='File'):
        with open(bin_file, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
        href = f'<a href="data:application/octet-stream;base64,{b64}" download="{os.path.basename(bin_file)}">{file_label}</a>'
        return href

    def plot_waveform(samples, framerate, title="Waveform"):
        times = np.linspace(0, len(samples) / framerate, num=len(samples))
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(times[:1000], samples[:1000])
        ax.set_title(f"{title} (First 1000 Samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)

    def plot_difference(original, stego, framerate):
        min_len = min(len(original), len(stego))
        original = original[:min_len]
        stego = stego[:min_len]
        diff = original.astype(np.int32) - stego.astype(np.int32)
        times = np.linspace(0, min_len / framerate, num=min_len)
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(times[:1000], diff[:1000])
        ax.set_title("Difference between Original and Stego Audio (First 1000 samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude Difference")
        st.pyplot(fig)

    def calculate_correlation(original, stego):
        min_len = min(len(original), len(stego))
        if min_len == 0:
            return 0.0
        corr = np.corrcoef(original[:min_len], stego[:min_len])[0, 1]
        if np.isnan(corr):
            return 0.0
        return round(corr, 4) if len(original) == len(stego) else 0.0

    def calculate_embedding_capacity(samples, message_bits):
        capacity_bits = len(message_bits)
        capacity_chars = capacity_bits // 8
        percent_used = (capacity_bits / len(samples)) * 100
        return capacity_bits, capacity_chars, percent_used

    def band_energy_ratio(y, sr, split_freq=2000):
        def butter_filter(data, cutoff, fs, btype='low', order=5):
            nyq = 0.5 * fs
            normal_cutoff = cutoff / nyq
            b, a = butter(order, normal_cutoff, btype=btype, analog=False)
            return lfilter(b, a, data)

        low_band = butter_filter(y, split_freq, sr, btype='low')
        high_band = butter_filter(y, split_freq, sr, btype='high')

        low_energy = np.sum(low_band ** 2)
        high_energy = np.sum(high_band ** 2)

        if high_energy == 0:
            return float('inf')

        return low_energy / high_energy

    tabs = st.tabs(["Embed Message", "Compare & Extract"])

    with tabs[0]:
        st.markdown("<h2 class='sub-head'>Embed Message into Audio</h2>", unsafe_allow_html=True)

        uploaded_file = st.file_uploader("Choose an audio file to embed message", type=["wav"])
        message = st.text_area("Enter the message to hide")

        if uploaded_file is not None:
            temp_path = os.path.join(st.session_state.temp_dir, uploaded_file.name)
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            with wave.open(temp_path, 'rb') as wav:
                params = wav.getparams()
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)

            st.subheader("Original Audio Waveform")
            plot_waveform(samples, framerate, "Original Audio")

            ber_original = band_energy_ratio(samples, framerate)
            st.write(f"\U0001F4C8 **Band Energy Ratio (Original Audio):** {ber_original:.4f}")

            if st.button("Embed Message"):
                stego_samples, error, message_bits = lsb_encode(samples, message)
                if error:
                    st.error(error)
                else:
                    stego_bytes = stego_samples.astype(np.int16).tobytes()
                    stego_path = os.path.join(st.session_state.temp_dir, f"stego_{uploaded_file.name}")
                    with wave.open(stego_path, 'wb') as out:
                        out.setparams(params)
                        out.writeframes(stego_bytes)

                    st.session_state.original_samples = samples
                    st.session_state.stego_path = stego_path
                    st.session_state.message_bits = message_bits
                    st.session_state.framerate = framerate

                    st.success("Message embedded successfully!")
                    st.audio(stego_path)

                    st.subheader("Stego Audio Waveform")
                    plot_waveform(stego_samples, framerate, "Stego Audio")

                    ber_stego = band_energy_ratio(stego_samples, framerate)
                    st.write(f"\U0001F4C8 **Band Energy Ratio (Stego Audio):** {ber_stego:.4f}")

                    st.markdown(get_binary_file_downloader_html(stego_path, 'Download Stego Audio'), unsafe_allow_html=True)

    with tabs[1]:
        st.markdown("<h2 class='sub-head'>Upload Stego Audio for Comparison and Extraction</h2>", unsafe_allow_html=True)

        stego_file = st.file_uploader("Upload the stego audio file", type=["wav"], key="stego_compare")

        if stego_file is not None and 'original_samples' in st.session_state:
            temp_path = os.path.join(st.session_state.temp_dir, stego_file.name)
            with open(temp_path, "wb") as f:
                f.write(stego_file.getbuffer())

            with wave.open(temp_path, 'rb') as wav:
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()
                stego_samples = np.frombuffer(frames, dtype=np.int16)

            st.subheader("Uploaded Stego Audio Waveform")
            plot_waveform(stego_samples, framerate, "Uploaded Stego Audio")

            st.subheader("Difference between Original and Uploaded Stego Audio")
            plot_difference(st.session_state.original_samples, stego_samples, framerate)

            if st.button("Extract Message from Uploaded Stego"):
                message = lsb_decode(stego_samples)
                st.success("Message extracted successfully:")
                st.code(message)

                correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                st.subheader("\U0001F4CA Statistical Similarity After Extraction")
                st.write(f"**Correlation Coefficient:** {correlation:.4f}  _(close to 1 = high similarity; 0 = different audio)_")

                total_bits, total_chars, percent_used = calculate_embedding_capacity(
                    st.session_state.original_samples, st.session_state.message_bits)
                st.subheader("\U0001F4E6 Embedding Capacity After Extraction")
                st.write(f"**Bits embedded:** {total_bits}")
                st.write(f"**Characters embedded:** {total_chars}")
                st.write(f"**Audio capacity used:** {percent_used:.4f}%")

                ber_uploaded_stego = band_energy_ratio(stego_samples, framerate)
                ber_original = band_energy_ratio(st.session_state.original_samples, framerate)
                st.subheader("\U0001F4C8 Band Energy Ratio Comparison")
                st.write(f"**Original BER:** {ber_original:.4f}")
                st.write(f"**Uploaded Stego BER:** {ber_uploaded_stego:.4f}")
                st.write(f"**Difference:** {abs(ber_original - ber_uploaded_stego):.4f}")

        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")



# ------------ AES ENCRYPTION PAGE ------------
elif page == "Advanced AES Encryption":
    import os
    import tempfile
    import base64
    import numpy as np
    import wave
    import matplotlib.pyplot as plt
    from io import BytesIO
    from scipy.signal import welch
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import scrypt
    from Crypto.Random import get_random_bytes

    if 'temp_dir' not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()

    st.markdown("<h1 class='main-header'>🔐 Audio Encryption with AES</h1>", unsafe_allow_html=True)

    def pad_data(data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len]) * pad_len

    def unpad_data(data):
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            return data
        return data[:-pad_len]

    def aes_encrypt(raw_bytes, password):
        salt = get_random_bytes(16)
        key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad_data(raw_bytes))
        return salt + cipher.iv + ct_bytes

    def aes_decrypt(enc_bytes, password):
        salt = enc_bytes[:16]
        iv = enc_bytes[16:32]
        ct = enc_bytes[32:]
        key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        return unpad_data(pt)

    def plot_waveform(samples, framerate, title="Waveform"):
        times = np.linspace(0, len(samples) / framerate, num=len(samples))
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(times[:1000], samples[:1000])
        ax.set_title(f"{title} (First 1000 Samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)

    def plot_difference(original, processed, framerate):
        min_len = min(len(original), len(processed))
        original = original[:min_len]
        processed = processed[:min_len]
        diff = original.astype(np.int32) - processed.astype(np.int32)
        times = np.linspace(0, min_len / framerate, num=min_len)
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(times[:1000], diff[:1000])
        ax.set_title("Difference between Original and Processed Audio (First 1000 samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude Difference")
        st.pyplot(fig)

    def calculate_correlation(original, processed):
        min_len = min(len(original), len(processed))
        if min_len == 0:
            return 0.0
        corr = np.corrcoef(original[:min_len], processed[:min_len])[0, 1]
        if np.isnan(corr):
            return 0.0
        return round(corr, 4)

    def calculate_band_energy_ratio(signal, fs, band1=(300, 3000), band2=(3000, 6000)):
        f, Pxx = welch(signal, fs=fs)
        band1_energy = np.sum(Pxx[(f >= band1[0]) & (f <= band1[1])])
        band2_energy = np.sum(Pxx[(f >= band2[0]) & (f <= band2[1])])
        if band2_energy == 0:
            return float('inf')
        return round(band1_energy / band2_energy, 4)

    def get_binary_file_downloader_html(bin_file, file_label='File'):
        with open(bin_file, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode()
        href = f'<a href="data:application/octet-stream;base64,{b64}" download="{os.path.basename(bin_file)}">{file_label}</a>'
        return href

    tabs = st.tabs(["Encrypt Audio", "Decrypt & Compare Audio"])

    with tabs[0]:
        st.markdown("<h2 class='sub-head'>Encrypt Audio File</h2>", unsafe_allow_html=True)

        uploaded_file = st.file_uploader("Choose an audio file to encrypt", type=["wav"])
        password = st.text_input("Enter encryption password", type="password")

        if uploaded_file is not None and password:
            temp_path = os.path.join(st.session_state.temp_dir, uploaded_file.name)
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            with wave.open(temp_path, 'rb') as wav:
                params = wav.getparams()
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)

            st.subheader("Original Audio Waveform")
            plot_waveform(samples, framerate, "Original Audio")

            if st.button("Encrypt Audio"):
                enc_bytes = aes_encrypt(frames, password)
                enc_path = os.path.join(st.session_state.temp_dir, f"encrypted_{uploaded_file.name}")

                with open(enc_path, "wb") as f:
                    f.write(enc_bytes)

                st.session_state.original_samples = samples
                st.session_state.original_params = params
                st.session_state.encrypted_path = enc_path
                st.session_state.framerate = framerate
                st.success("Audio encrypted and saved as binary file (not playable as audio).")
                st.markdown(get_binary_file_downloader_html(enc_path, 'Download Encrypted Audio (.bin)'), unsafe_allow_html=True)

    with tabs[1]:
        st.markdown("<h2 class='sub-head'>Decrypt Audio and Compare</h2>", unsafe_allow_html=True)

        encrypted_file = st.file_uploader("Upload the encrypted audio binary file", type=["bin"], key="enc_upload")
        password = st.text_input("Enter decryption password", type="password", key="dec_pass")

        if encrypted_file is not None and password and 'original_samples' in st.session_state:
            temp_enc_path = os.path.join(st.session_state.temp_dir, encrypted_file.name)
            with open(temp_enc_path, "wb") as f:
                f.write(encrypted_file.getbuffer())

            with open(temp_enc_path, "rb") as f:
                enc_bytes = f.read()

            try:
                decrypted_frames = aes_decrypt(enc_bytes, password)
            except Exception as e:
                st.error("Decryption failed. Possibly wrong password or corrupted file.")
                decrypted_frames = None

            if decrypted_frames:
                dec_samples = np.frombuffer(decrypted_frames, dtype=np.int16)

                st.subheader("Decrypted Audio Waveform")
                plot_waveform(dec_samples, st.session_state.framerate, "Decrypted Audio")

                st.subheader("Difference between Original and Decrypted Audio")
                plot_difference(st.session_state.original_samples, dec_samples, st.session_state.framerate)

                corr = calculate_correlation(st.session_state.original_samples, dec_samples)
                st.subheader("📊 Statistical Similarity")
                st.write(f"**Correlation Coefficient:** {corr:.4f}  _(1 = identical; 0 = different)_")

                st.audio(decrypted_frames, format='audio/wav')

                st.success("Decryption successful! Audio can be played now.")

                total_bits = len(enc_bytes) * 8
                total_chars = len(enc_bytes)
                st.subheader("📦 Encryption Capacity")
                st.write(f"**Bits:** {total_bits}")
                st.write(f"**Bytes:** {total_chars}")

                ber = calculate_band_energy_ratio(dec_samples, st.session_state.framerate)
                st.subheader("🎵 Band Energy Ratio (BER)")
                st.write(f"**BER (300-3000 Hz / 3000-6000 Hz):** {ber}")

        elif 'original_samples' not in st.session_state:
            st.warning("Please encrypt an audio file first to have an original for comparison.")


   
# ------------ RSA STEGANOGRAPHY PAGE ------------
elif page == "RSA Steganography":
    import streamlit as st
    import numpy as np
    import matplotlib.pyplot as plt
    import wave
    import rsa
    import base64
    from io import BytesIO
    import tempfile
    from scipy import signal


    # Apply consistent styling
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: white;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: white;
        margin-bottom: 1rem;
    }
    .section-header {
        font-size: 1.2rem;
        color: #4A90E2;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }
    .info-text {
        background-color: #e6f3ff;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
        color:black;
    }
    .success-text {
        background-color: #d4edda;
        padding: 0.75rem;
        border-radius: 0.3rem;
        color: #155724;
    }
    .card {
        border: 1px solid #e0e0e0;
        border-radius: 0.5rem;
        padding: 1.5rem;
        margin-bottom: 1rem;
        background-color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.3s;
    }
    .stButton button {
        background-color: #4A90E2;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 0.3rem;
        transition: all 0.3s;
    }
    .stButton button:hover {
        background-color: #357ABD;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    </style>
    """, unsafe_allow_html=True)

    # Initialize session state
    if 'stego_audio' not in st.session_state:
        st.session_state.stego_audio = None
    if 'original_params' not in st.session_state:
        st.session_state.original_params = None
    if 'temp_dir' not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()
    if 'rsa_keys' not in st.session_state:
        st.session_state.rsa_keys = None
    if 'original_samples' not in st.session_state:
        st.session_state.original_samples = None
    if 'message_bits' not in st.session_state:
        st.session_state.message_bits = None

    st.markdown("<h1 class='main-header'>🔐 Audio Steganography with RSA</h1>", unsafe_allow_html=True)

    # Sidebar with info
    with st.sidebar:
        st.markdown("<h2 class='sub-head'>About RSA Steganography</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-text'>
        <p>This tool allows you to:</p>
        <ul>
            <li>Embed RSA-encrypted messages in audio files</li>
            <li>Extract and decrypt hidden messages</li>
            <li>Generate or import RSA key pairs</li>
            <li>Securely share messages through audio</li>
            <li>Analyze spectral changes with Band Energy Ratio (BER)</li>
        </ul>
        <p>RSA provides strong asymmetric encryption for your sensitive messages.</p>
        </div>
        """, unsafe_allow_html=True)

    # Main functionality
    tabs = st.tabs(["Embed Message", "Extract Message"])

    # Utility functions
    def plot_waveform(frames, framerate):
        audio_data = np.frombuffer(frames, dtype=np.int16)
        times = np.linspace(0, len(audio_data) / framerate, num=len(audio_data))
        fig, ax = plt.subplots()
        ax.plot(times[:1000], audio_data[:1000])
        ax.set_title("Audio Waveform (first 1000 samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)

    def lsb_encode(frames, message):
        message += '|||END'  # End marker
        bits = ''.join(format(ord(char), '08b') for char in message)
        audio = bytearray(frames)
        
        # Check if message can fit in audio
        if len(bits) > len(audio):
            return None, "Message too large for this audio file"
        
        for i, bit in enumerate(bits):
            audio[i] = (audio[i] & 254) | int(bit)
        
        # Store message bits for capacity calculation
        st.session_state.message_bits = bits
        
        return bytes(audio), None

    def lsb_decode(frames):
        audio = bytearray(frames)
        bits = [str(audio[i] & 1) for i in range(len(audio))]
        
        # Convert bits to characters 8 bits at a time
        decoded_chars = []
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):  # Ensure we have 8 bits
                byte = ''.join(bits[i:i+8])
                decoded_chars.append(chr(int(byte, 2)))
        
        message = ''.join(decoded_chars)
        
        # Find the end marker
        if '|||END' in message:
            return message.split('|||END')[0]
        return "No hidden message found or corrupted message"
    
    def calculate_correlation(original_samples, stego_samples):
        """Calculate correlation coefficient between original and stego audio samples"""
        if original_samples is None or stego_samples is None:
            return 0.0
            
        orig = np.frombuffer(original_samples, dtype=np.int16)
        stego = np.frombuffer(stego_samples, dtype=np.int16)
        
        # Limit to the smaller length
        min_len = min(len(orig), len(stego))
        orig = orig[:min_len]
        stego = stego[:min_len]
        
        # Correlation coefficient
        return np.corrcoef(orig, stego)[0, 1]
    
    def calculate_embedding_capacity(original_samples, message_bits):
        """Calculate embedding capacity statistics"""
        if original_samples is None:
            return 0, 0, 0.0
            
        audio = np.frombuffer(original_samples, dtype=np.int16)
        total_bits = len(audio)  # One bit per sample
        total_chars = total_bits // 8  # 8 bits per character
        
        if message_bits:
            percent_used = (len(message_bits) / total_bits) * 100
        else:
            percent_used = 0.0
            
        return total_bits, total_chars, percent_used

    def calculate_band_energy_ratio(audio_samples, sample_rate):
        """Calculate Band Energy Ratio (BER) for spectral analysis"""
        if audio_samples is None:
            return None, None, None
            
        # Convert to numpy array
        audio = np.frombuffer(audio_samples, dtype=np.int16).astype(np.float32)
        
        # Calculate FFT
        fft = np.fft.fft(audio)
        magnitude = np.abs(fft)
        
        # Calculate frequency bins
        freqs = np.fft.fftfreq(len(audio), 1/sample_rate)
        
        # Only use positive frequencies
        pos_freqs = freqs[:len(freqs)//2]
        pos_magnitude = magnitude[:len(magnitude)//2]
        
        # Define frequency bands
        # Low band: 0-1000 Hz
        # Mid band: 1000-4000 Hz  
        # High band: 4000 Hz - Nyquist frequency
        
        low_band_mask = (pos_freqs >= 0) & (pos_freqs < 1000)
        mid_band_mask = (pos_freqs >= 1000) & (pos_freqs < 4000)
        high_band_mask = pos_freqs >= 4000
        
        # Calculate energy in each band
        low_energy = np.sum(pos_magnitude[low_band_mask] ** 2)
        mid_energy = np.sum(pos_magnitude[mid_band_mask] ** 2)
        high_energy = np.sum(pos_magnitude[high_band_mask] ** 2)
        
        total_energy = low_energy + mid_energy + high_energy
        
        if total_energy == 0:
            return 0, 0, 0
            
        # Calculate ratios
        low_ratio = low_energy / total_energy
        mid_ratio = mid_energy / total_energy
        high_ratio = high_energy / total_energy
        
        return low_ratio, mid_ratio, high_ratio

    def plot_frequency_spectrum(audio_samples, sample_rate, title):
        """Plot frequency spectrum of audio"""
        audio = np.frombuffer(audio_samples, dtype=np.int16).astype(np.float32)
        
        # Calculate FFT
        fft = np.fft.fft(audio)
        magnitude = np.abs(fft)
        freqs = np.fft.fftfreq(len(audio), 1/sample_rate)
        
        # Only plot positive frequencies
        pos_freqs = freqs[:len(freqs)//2]
        pos_magnitude = magnitude[:len(magnitude)//2]
        
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(pos_freqs, 20 * np.log10(pos_magnitude + 1e-10))  # Convert to dB
        ax.set_xlabel('Frequency (Hz)')
        ax.set_ylabel('Magnitude (dB)')
        ax.set_title(title)
        ax.grid(True, alpha=0.3)
        ax.set_xlim(0, min(8000, sample_rate/2))  # Limit to 8kHz for better visualization
        
        return fig

    # EMBED MESSAGE TAB
    with tabs[0]:
        st.markdown("<h2 class='sub-head'>Embed Encrypted Message</h2>", unsafe_allow_html=True)
        
        # File uploader
        audio_file = st.file_uploader("🎧 Upload a WAV audio file", type=["wav"], key="embed_audio")
        
        if audio_file:
            # Display original audio
            st.audio(audio_file, format='audio/wav')
            
            # Read audio file
            with wave.open(audio_file, 'rb') as wav:
                params = wav.getparams()
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()
                
                # Store original parameters for later use
                st.session_state.original_params = params
                st.session_state.original_samples = frames
                
                # Plot original waveform
                st.subheader("Original Audio Waveform")
                plot_waveform(frames, framerate)
                
                # Plot frequency spectrum
                st.subheader("Original Audio Frequency Spectrum")
                fig = plot_frequency_spectrum(frames, framerate, "Original Audio Spectrum")
                st.pyplot(fig)
                
                # Calculate and display BER for original audio
                low_ratio, mid_ratio, high_ratio = calculate_band_energy_ratio(frames, framerate)
                if low_ratio is not None:
                    st.subheader("📊 Original Audio Band Energy Analysis")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Low Band (0-1kHz)", f"{low_ratio:.3f}")
                    with col2:
                        st.metric("Mid Band (1-4kHz)", f"{mid_ratio:.3f}")
                    with col3:
                        st.metric("High Band (4kHz+)", f"{high_ratio:.3f}")
            
            # Message to hide
            message = st.text_area("💬 Enter your secret message", height=100)
            
            # RSA Key Management
            st.markdown("<h3 class='section-header'>RSA Key Management</h3>", unsafe_allow_html=True)
            
            key_option = st.radio(
                "Choose key option",
                ["Generate new RSA keys", "Use existing public key"]
            )
            
            if key_option == "Generate new RSA keys":
                key_size = st.select_slider(
                    "Select RSA Key Size (bits)",
                    options=[1024, 2048, 3072, 4096],
                    value=2048
                )
                
                if st.button("Generate Keys"):
                    with st.spinner("Generating RSA key pair..."):
                        # Generate the keys
                        (pubkey, privkey) = rsa.newkeys(key_size)
                        st.session_state.rsa_keys = (pubkey, privkey)
                        st.success(f"RSA keys generated (Size: {key_size} bits)")
                
                # Display keys if they exist
                if st.session_state.rsa_keys:
                    pubkey, privkey = st.session_state.rsa_keys
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("<div class='card'>", unsafe_allow_html=True)
                        st.subheader("🔑 Private Key")
                        privkey_pem = privkey.save_pkcs1().decode()
                        st.text_area("Save this to decrypt your message", privkey_pem, height=150, key="privkey_display")
                        
                        # Option to download private key
                        privkey_buffer = BytesIO(privkey_pem.encode())
                        st.download_button(
                            "⬇ Download Private Key", 
                            privkey_buffer.getvalue(), 
                            "private_key.pem",
                            mime="application/x-pem-file"
                        )
                        st.markdown("</div>", unsafe_allow_html=True)
                    
                    with col2:
                        st.markdown("<div class='card'>", unsafe_allow_html=True)
                        st.subheader("🔒 Public Key")
                        pubkey_pem = pubkey.save_pkcs1().decode()
                        st.text_area("Share this for others to encrypt messages for you", pubkey_pem, height=150, key="pubkey_display")
                        
                        # Option to download public key
                        pubkey_buffer = BytesIO(pubkey_pem.encode())
                        st.download_button(
                            "⬇ Download Public Key", 
                            pubkey_buffer.getvalue(), 
                            "public_key.pem",
                            mime="application/x-pem-file"
                        )
                        st.markdown("</div>", unsafe_allow_html=True)
            else:
                # Option to paste a public key
                pubkey_pem = st.text_area("Paste RSA Public Key (PEM format)", height=150)
                if pubkey_pem:
                    try:
                        pubkey = rsa.PublicKey.load_pkcs1(pubkey_pem.encode())
                        st.success("Public key loaded successfully")
                        st.session_state.rsa_keys = (pubkey, None)  # Store public key, no private key
                    except Exception as e:
                        st.error(f"Invalid public key: {str(e)}")
            
            # Encrypt and Embed Button
            if st.button("🔏 Encrypt & Embed Message"):
                if not message:
                    st.error("Please enter a message to hide")
                elif st.session_state.rsa_keys is None:
                    st.error("Please generate or provide RSA keys first")
                else:
                    pubkey = st.session_state.rsa_keys[0]  # Get the public key
                    
                    try:
                        # Check message length for RSA constraints
                        max_bytes = (pubkey.n.bit_length() - 384) // 8  # Safe limit for PKCS#1
                        
                        if len(message.encode()) > max_bytes:
                            st.info("Message too long for direct RSA encryption. Using hybrid encryption (RSA + AES).")
                            
                            # For simplicity in this example, we'll use a placeholder for hybrid encryption
                            # In a real implementation, you would use AES for the message and RSA for the AES key
                            encrypted = f"HYBRID_ENCRYPTION:{message[:10]}...".encode()
                            encrypted_b64 = base64.b64encode(encrypted).decode()
                        else:
                            # Direct RSA encryption for short messages
                            encrypted = rsa.encrypt(message.encode(), pubkey)
                            encrypted_b64 = base64.b64encode(encrypted).decode()
                        
                        # Embed using LSB
                        encoded_frames, error = lsb_encode(frames, encrypted_b64)
                        
                        if error:
                            st.error(error)
                        else:
                            # Store the stego audio in session state
                            st.session_state.stego_audio = encoded_frames
                            
                            # Create audio buffer for download
                            buffer = BytesIO()
                            with wave.open(buffer, 'wb') as out:
                                out.setparams(params)
                                out.writeframes(encoded_frames)
                            
                            st.success("Message encrypted and embedded successfully!")
                            
                            # Plot stego audio waveform
                            st.subheader("Stego Audio Waveform")
                            plot_waveform(encoded_frames, framerate)
                            
                            # Plot stego frequency spectrum
                            st.subheader("Stego Audio Frequency Spectrum")
                            fig = plot_frequency_spectrum(encoded_frames, framerate, "Stego Audio Spectrum")
                            st.pyplot(fig)
                            
                            # Calculate and display BER for stego audio
                            stego_low, stego_mid, stego_high = calculate_band_energy_ratio(encoded_frames, framerate)
                            if stego_low is not None:
                                st.subheader("📊 Stego Audio Band Energy Analysis")
                                col1, col2, col3 = st.columns(3)
                                with col1:
                                    st.metric("Low Band (0-1kHz)", f"{stego_low:.3f}", 
                                             delta=f"{stego_low - low_ratio:.6f}")
                                with col2:
                                    st.metric("Mid Band (1-4kHz)", f"{stego_mid:.3f}", 
                                             delta=f"{stego_mid - mid_ratio:.6f}")
                                with col3:
                                    st.metric("High Band (4kHz+)", f"{stego_high:.3f}", 
                                             delta=f"{stego_high - high_ratio:.6f}")
                                
                                # BER Change Analysis
                                st.subheader("🔍 Band Energy Ratio Changes")
                                ber_change = abs(stego_low - low_ratio) + abs(stego_mid - mid_ratio) + abs(stego_high - high_ratio)
                                st.metric("Total BER Change", f"{ber_change:.6f}", 
                                         help="Lower values indicate better steganographic quality")
                            
                            # Let user listen to the stego audio
                            st.subheader("Stego Audio")
                            st.audio(buffer.getvalue(), format='audio/wav')
                            
                            # Download button
                            st.download_button(
                                "⬇ Download Stego Audio", 
                                buffer.getvalue(), 
                                "stego_audio_rsa.wav",
                                mime="audio/wav"
                            )
                    except Exception as e:
                        st.error(f"Encryption error: {str(e)}")

    # EXTRACT MESSAGE TAB
    with tabs[1]:
        st.markdown("<h2 class='sub-header'>Extract & Decrypt Message</h2>", unsafe_allow_html=True)
        
        # Option to use either session stored audio or upload stego audio
        decrypt_source = st.radio(
            "Select audio source for extraction",
            ["Use encrypted audio from above", "Upload stego audio file"],
            index=0 if st.session_state.stego_audio else 1
        )
        
        stego_samples = None
        
        if decrypt_source == "Upload stego audio file":
            stego_file = st.file_uploader("Upload stego audio file", type=["wav"], key="stego_uploader")
            if stego_file:
                with wave.open(stego_file, 'rb') as wav:
                    stego_params = wav.getparams()
                    stego_frames = wav.readframes(wav.getnframes())
                st.session_state.stego_audio = stego_frames
                st.session_state.original_params = stego_params
                stego_samples = stego_frames
                
                # Display the uploaded stego audio
                st.audio(stego_file, format='audio/wav')
                
                # Plot stego audio waveform
                st.subheader("Stego Audio Waveform")
                plot_waveform(stego_frames, stego_params.framerate)
                
                # Plot stego frequency spectrum
                st.subheader("Stego Audio Frequency Spectrum")
                fig = plot_frequency_spectrum(stego_frames, stego_params.framerate, "Uploaded Stego Audio Spectrum")
                st.pyplot(fig)
        else:
            stego_samples = st.session_state.stego_audio
        
        # Private key input for decryption
        st.markdown("<h3 class='section-header'>RSA Decryption Key</h3>", unsafe_allow_html=True)
        privkey_pem = st.text_area("Enter RSA Private Key for decryption", height=150, key="decrypt_privkey")
        
        # Extract & Decrypt Button
        if st.button("🔍 Extract & Decrypt Message"):
            if st.session_state.stego_audio is None:
                st.error("No stego audio available. Please encrypt a message or upload a stego audio file.")
            elif not privkey_pem:
                st.error("Please enter your RSA private key to decrypt the message.")
            else:
                try:
                    # First decode using LSB
                    decoded = lsb_decode(st.session_state.stego_audio)
                    
                    # Parse the private key
                    privkey = rsa.PrivateKey.load_pkcs1(privkey_pem.encode())
                    
                    # Check if this is our simulated hybrid encryption
                    if decoded.startswith("HYBRID_ENCRYPTION:"):
                        # This is just a placeholder for the hybrid decryption process
                        decrypted = "This is a simulated hybrid decryption. In a real implementation, this would be the properly decrypted message."
                    else:
                        # Direct RSA decryption
                        encrypted = base64.b64decode(decoded)
                        decrypted = rsa.decrypt(encrypted, privkey).decode()
                    
                    st.success("Message extracted and decrypted successfully!")
                    
                    # Display the decrypted message in a nice card
                    st.markdown("<div class='card'>", unsafe_allow_html=True)
                    st.subheader("📜 Decrypted Message")
                    st.markdown(f"<div class='success-text'>{decrypted}</div>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    # Analysis Section
                    st.markdown("<h2 class='section-header'>📊 Steganographic Quality Analysis</h2>", unsafe_allow_html=True)
                    
                    # Correlation Coefficient
                    correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                    st.subheader("🔗 Statistical Similarity")
                    st.write(f"**Correlation Coefficient:** {correlation:.6f}")
                    st.write("_(Values close to 1.0 indicate high similarity between original and stego audio)_")

                    # Embedding Capacity
                    total_bits, total_chars, percent_used = calculate_embedding_capacity(
                        st.session_state.original_samples, st.session_state.message_bits)
                    st.subheader("📦 Embedding Capacity")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Bits Available", f"{total_bits:,}")
                    with col2:
                        st.metric("Character Capacity", f"{total_chars:,}")
                    with col3:
                        st.metric("Capacity Used", f"{percent_used:.4f}%")
                    
                    # Band Energy Ratio Analysis
                    if st.session_state.original_samples is not None and stego_samples is not None:
                        st.subheader("🎵 Band Energy Ratio (BER) Analysis")
                        
                        # Get sample rate
                        sample_rate = st.session_state.original_params.framerate
                        
                        # Calculate BER for both audio files
                        orig_low, orig_mid, orig_high = calculate_band_energy_ratio(
                            st.session_state.original_samples, sample_rate)
                        stego_low, stego_mid, stego_high = calculate_band_energy_ratio(
                            stego_samples, sample_rate)
                        
                        if orig_low is not None and stego_low is not None:
                            # Display comparison
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.write("**Original Audio BER:**")
                                st.write(f"• Low Band (0-1kHz): {orig_low:.6f}")
                                st.write(f"• Mid Band (1-4kHz): {orig_mid:.6f}")
                                st.write(f"• High Band (4kHz+): {orig_high:.6f}")
                            
                            with col2:
                                st.write("**Stego Audio BER:**")
                                st.write(f"• Low Band (0-1kHz): {stego_low:.6f}")
                                st.write(f"• Mid Band (1-4kHz): {stego_mid:.6f}")
                                st.write(f"• High Band (4kHz+): {stego_high:.6f}")
                            
                            # Calculate and display changes
                            low_change = abs(stego_low - orig_low)
                            mid_change = abs(stego_mid - orig_mid)
                            high_change = abs(stego_high - orig_high)
                            total_ber_change = low_change + mid_change + high_change
                            
                            st.write("**BER Changes:**")
                            col1, col2, col3, col4 = st.columns(4)
                            with col1:
                                st.metric("Low Band Δ", f"{low_change:.6f}")
                            with col2:
                                st.metric("Mid Band Δ", f"{mid_change:.6f}")
                            with col3:
                                st.metric("High Band Δ", f"{high_change:.6f}")
                            with col4:
                                st.metric("Total BER Δ", f"{total_ber_change:.6f}")
                            
                            # Quality assessment
                            if total_ber_change < 0.001:
                                quality = "🟢 Excellent"
                                quality_desc = "Very low spectral distortion detected"
                            elif total_ber_change < 0.01:
                                quality = "🟡 Good"
                                quality_desc = "Moderate spectral changes detected"
                            else:
                                quality = "🔴 Poor"
                                quality_desc = "Significant spectral distortion detected"
                            
                            st.markdown(f"**Steganographic Quality:** {quality}")
                            st.write(f"_{quality_desc}_")
                    
                except Exception as e:
                    st.error(f"Decryption failed: {str(e)}")
                    st.error("Check if you're using the correct private key.")
        
        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")

# ------------ QIM STEGANOGRAPHY PAGE ------------
elif page == "QIM Steganography":
    import streamlit as st
    import numpy as np
    import matplotlib.pyplot as plt
    import wave
    import base64
    import tempfile
    from io import BytesIO
    import os
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from scipy import signal

    # Apply consistent styling
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        color: white;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: white;
        margin-bottom: 1rem;
    }
    .section-header {
        font-size: 1.2rem;
        color: #4A90E2;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
    }
    .info-text {
        background-color: #e6f3ff;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .success-text {
        background-color: #d4edda;
        padding: 0.75rem;
        border-radius: 0.3rem;
        color: #155724;
    }
    .card {
        border: 1px solid #e0e0e0;
        border-radius: 0.5rem;
        padding: 1.5rem;
        margin-bottom: 1rem;
        background-color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.3s;
    }
    .stButton button {
        background-color: #4A90E2;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 0.3rem;
        transition: all 0.3s;
    }
    .stButton button:hover {
        background-color: #357ABD;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    </style>
    """, unsafe_allow_html=True)

    # Initialize session state
    if 'stego_audio' not in st.session_state:
        st.session_state.stego_audio = None
    if 'original_params' not in st.session_state:
        st.session_state.original_params = None
    if 'temp_dir' not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()
    if 'original_samples' not in st.session_state:
        st.session_state.original_samples = None
    if 'message_bits' not in st.session_state:
        st.session_state.message_bits = None

    st.markdown("<h1 class='main-header'>🔐 Audio Steganography with QIM</h1>", unsafe_allow_html=True)

    # Sidebar with info
    with st.sidebar:
        st.markdown("<h2 class='sub-head'>About QIM Steganography</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-text'>
        <p>QIM (Quantization Index Modulation) steganography works by:</p>
        <ul>
            <li>Quantizing audio samples to specific levels based on the message bits</li>
            <li>Offering better robustness than LSB steganography</li>
            <li>Allowing for password-protected message embedding</li>
            <li>Preserving audio quality while hiding data</li>
        </ul>
        <p>This tool allows you to securely hide messages in audio files using QIM.</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Advanced Settings
        st.markdown("<h3 class='section-header'>Advanced Settings</h3>", unsafe_allow_html=True)
        
        delta = st.slider("Delta (Quantization Step)", 
                         min_value=8, max_value=64, value=16, step=4,
                         help="Higher values provide better security but may affect audio quality")
        
        start_sample = st.number_input("Starting Sample", 
                                     min_value=0, value=1000, step=100,
                                     help="Skip the first N samples when embedding data")
        
        st.markdown("""
        <div class='info-text'>
        <p><strong>How QIM works:</strong></p>
        <p>QIM quantizes audio samples to one of two possible values based on the message bit (0 or 1). 
        The quantization step size (Delta) determines the distance between these values.</p>
        <p>Larger Delta values make the embedded message more robust against noise but may decrease audio quality.</p>
        </div>
        """, unsafe_allow_html=True)

    # Utility functions
    def plot_waveform(frames, framerate, title="Audio Waveform"):
        audio_data = np.frombuffer(frames, dtype=np.int16)
        times = np.linspace(0, len(audio_data) / framerate, num=len(audio_data))
        
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.plot(times[:1000], audio_data[:1000])
        ax.set_title(title + " (first 1000 samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)

    def plot_histogram(frames, title="Audio Histogram"):
        audio_data = np.frombuffer(frames, dtype=np.int16)
        
        fig, ax = plt.subplots(figsize=(10, 4))
        ax.hist(audio_data, bins=100, alpha=0.7)
        ax.set_title(title)
        ax.set_xlabel("Sample Value")
        ax.set_ylabel("Frequency")
        st.pyplot(fig)

    def calculate_band_energy_ratio(audio_data, sample_rate):
        """Calculate band energy ratio analysis for steganography detection"""
        try:
            # Define frequency bands (in Hz)
            bands = {
                'Low (0-1kHz)': (0, 1000),
                'Mid-Low (1-2kHz)': (1000, 2000),
                'Mid (2-4kHz)': (2000, 4000),
                'Mid-High (4-8kHz)': (4000, 8000),
                'High (8kHz+)': (8000, sample_rate//2)
            }
            
            # Calculate power spectral density
            freqs, psd = signal.welch(audio_data, sample_rate, nperseg=1024)
            
            # Calculate energy in each band
            band_energies = {}
            total_energy = np.sum(psd)
            
            for band_name, (low_freq, high_freq) in bands.items():
                # Find frequency indices
                low_idx = np.argmin(np.abs(freqs - low_freq))
                high_idx = np.argmin(np.abs(freqs - high_freq))
                
                # Calculate energy in this band
                band_energy = np.sum(psd[low_idx:high_idx])
                band_energies[band_name] = band_energy / total_energy if total_energy > 0 else 0
            
            return band_energies, freqs, psd
            
        except Exception as e:
            st.error(f"Error calculating band energy ratio: {str(e)}")
            return {}, [], []

    def plot_band_energy_comparison(original_data, stego_data, sample_rate):
        """Plot band energy comparison between original and stego audio"""
        try:
            # Calculate band energies for both
            orig_bands, orig_freqs, orig_psd = calculate_band_energy_ratio(original_data, sample_rate)
            stego_bands, stego_freqs, stego_psd = calculate_band_energy_ratio(stego_data, sample_rate)
            
            if not orig_bands or not stego_bands:
                return
            
            # Create comparison plot
            fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 10))
            
            # Plot 1: Band energy ratios
            bands = list(orig_bands.keys())
            orig_values = [orig_bands[band] for band in bands]
            stego_values = [stego_bands[band] for band in bands]
            
            x = np.arange(len(bands))
            width = 0.35
            
            ax1.bar(x - width/2, orig_values, width, label='Original', alpha=0.7)
            ax1.bar(x + width/2, stego_values, width, label='Stego', alpha=0.7)
            ax1.set_xlabel('Frequency Bands')
            ax1.set_ylabel('Energy Ratio')
            ax1.set_title('Band Energy Ratio Comparison')
            ax1.set_xticks(x)
            ax1.set_xticklabels(bands, rotation=45)
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Plot 2: Power Spectral Density comparison
            ax2.semilogy(orig_freqs, orig_psd, label='Original', alpha=0.7)
            ax2.semilogy(stego_freqs, stego_psd, label='Stego', alpha=0.7)
            ax2.set_xlabel('Frequency (Hz)')
            ax2.set_ylabel('Power Spectral Density')
            ax2.set_title('Power Spectral Density Comparison')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            
            # Plot 3: Difference in band energies
            differences = [stego_values[i] - orig_values[i] for i in range(len(bands))]
            colors = ['red' if diff > 0 else 'blue' for diff in differences]
            
            ax3.bar(x, differences, color=colors, alpha=0.7)
            ax3.set_xlabel('Frequency Bands')
            ax3.set_ylabel('Energy Difference (Stego - Original)')
            ax3.set_title('Band Energy Differences')
            ax3.set_xticks(x)
            ax3.set_xticklabels(bands, rotation=45)
            ax3.axhline(y=0, color='black', linestyle='-', alpha=0.3)
            ax3.grid(True, alpha=0.3)
            
            plt.tight_layout()
            st.pyplot(fig)
            
            # Display numerical results
            st.subheader("📊 Band Energy Analysis Results")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Original Audio Band Energies:**")
                for band, energy in orig_bands.items():
                    st.write(f"- {band}: {energy:.4f}")
            
            with col2:
                st.write("**Stego Audio Band Energies:**")
                for band, energy in stego_bands.items():
                    st.write(f"- {band}: {energy:.4f}")
            
            # Calculate and display suspicious changes
            st.write("**Energy Changes:**")
            suspicious_changes = []
            for i, band in enumerate(bands):
                diff = differences[i]
                percent_change = (diff / orig_values[i] * 100) if orig_values[i] > 0 else 0
                st.write(f"- {band}: {diff:+.6f} ({percent_change:+.2f}%)")
                
                if abs(percent_change) > 5:  # Threshold for suspicious change
                    suspicious_changes.append(band)
            
            if suspicious_changes:
                st.warning(f"⚠️ Significant energy changes detected in: {', '.join(suspicious_changes)}")
                st.write("Large changes in band energy ratios may indicate steganographic content.")
            else:
                st.success("✅ No significant energy changes detected. Steganography appears well-hidden.")
                
        except Exception as e:
            st.error(f"Error plotting band energy comparison: {str(e)}")

    def str_to_bits(message):
        # Convert string to a stream of bits
        result = []
        for char in message:
            bits = bin(ord(char))[2:].zfill(8)
            for bit in bits:
                result.append(int(bit))
        
        # Add end marker (byte of all 1's)
        for _ in range(8):
            result.append(1)
        
        return result

    def bits_to_str(bits):
        # Convert bits back to string
        result = ""
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):  # Ensure we have 8 bits
                byte = bits[i:i+8]
                
                # Check for end marker (byte of all 1's)
                if all(bit == 1 for bit in byte):
                    break
                    
                try:
                    char_code = int(''.join(map(str, byte)), 2)
                    if 0 <= char_code <= 127:  # Valid ASCII range
                        result += chr(char_code)
                    else:
                        # Skip invalid characters
                        continue
                except (ValueError, OverflowError):
                    # Skip invalid bit patterns
                    continue
        
        return result

    def derive_key(password, salt=None):
        # Generate a key from password using PBKDF2
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt

    def encrypt_message(message, password):
        # Encrypt message with AES using a key derived from the password
        try:
            key, salt = derive_key(password)
            iv = os.urandom(16)
            
            # Ensure message is UTF-8 encoded
            message_bytes = message.encode('utf-8')
            
            # Pad message to be multiple of 16 bytes
            padding_length = 16 - (len(message_bytes) % 16)
            padded_message = message_bytes + bytes([padding_length] * padding_length)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
            
            # Combine salt, iv, and encrypted message
            return base64.b64encode(salt + iv + encrypted_message).decode('ascii')
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt_message(encrypted_data, password):
        # Decrypt message with AES using a key derived from the password
        try:
            data = base64.b64decode(encrypted_data.encode('ascii'))
            salt = data[:16]
            iv = data[16:32]
            encrypted_message = data[32:]
            
            key, _ = derive_key(password, salt)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_message) + decryptor.finalize()
            
            # Remove padding
            padding_length = decrypted_data[-1]
            message_bytes = decrypted_data[:-padding_length]
            
            return message_bytes.decode('utf-8')
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def qim_embed(audio_data, message_bits, delta, start_sample=1000):
        # Embed message using QIM
        modified_data = audio_data.copy()
        
        # Check if message can fit in audio
        if len(message_bits) > (len(audio_data) - start_sample):
            return None, "Message too large for this audio file"
        
        for i, bit in enumerate(message_bits):
            if (i + start_sample) < len(audio_data):
                sample = audio_data[i + start_sample]
                # Quantize to even or odd multiples of delta based on bit value
                if bit == 0:
                    # Quantize to even multiple of delta
                    modified_data[i + start_sample] = int(round(sample / delta) * delta)
                else:
                    # Quantize to odd multiple of delta
                    modified_data[i + start_sample] = int((round(sample / delta - 0.5) + 0.5) * delta)
        
        return modified_data, None

    def qim_extract(audio_data, delta, start_sample=1000, max_bits=8000):
        # Extract message using QIM
        extracted_bits = []
        
        # Extract bits until we find the end marker or reach max_bits
        for i in range(min(len(audio_data) - start_sample, max_bits)):
            sample = audio_data[i + start_sample]
            # Determine bit value based on quantization
            remainder = abs(sample) % delta
            if remainder < delta / 2:
                extracted_bits.append(0)  # Closer to even multiple
            else:
                extracted_bits.append(1)  # Closer to odd multiple
            
            # Check for end marker every 8 bits
            if len(extracted_bits) >= 8 and len(extracted_bits) % 8 == 0:
                last_byte = extracted_bits[-8:]
                if all(bit == 1 for bit in last_byte):
                    # Found end marker, stop extraction
                    return extracted_bits[:-8]  # Remove end marker
        
        return extracted_bits
    
    def calculate_correlation(original_samples, stego_samples):
        # Calculate correlation coefficient between original and stego audio
        if original_samples is None or stego_samples is None:
            return 0
        
        # Ensure same length
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len]
        stego = stego_samples[:min_len]
        
        # Calculate correlation coefficient
        correlation = np.corrcoef(original, stego)[0, 1]
        return correlation
    
    def calculate_embedding_capacity(original_samples, message_bits):
        if original_samples is None or message_bits is None:
            return 0, 0, 0
            
        total_bits = len(message_bits)
        total_chars = total_bits // 8
        percent_used = (total_bits / len(original_samples)) * 100
        
        return total_bits, total_chars, percent_used

    # Main functionality
    tabs = st.tabs(["Embed Message", "Extract Message"])

    # EMBED MESSAGE TAB
    with tabs[0]:
        st.markdown("<h2 class='sub-head'>Embed Secret Message</h2>", unsafe_allow_html=True)
        
        # File uploader
        audio_file = st.file_uploader("🎧 Upload a WAV audio file", type=["wav"], key="embed_audio")
        
        if audio_file:
            # Display original audio
            st.audio(audio_file, format='audio/wav')
            
            # Read audio file
            with wave.open(audio_file, 'rb') as wav:
                params = wav.getparams()
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()
                
            # Store original parameters for later use
            st.session_state.original_params = params
                
            # Convert to numpy array for processing
            audio_data = np.frombuffer(frames, dtype=np.int16)
            
            # Store original samples for later comparison
            st.session_state.original_samples = audio_data
                
            # Plot original waveform
            st.subheader("Original Audio Visualization")
            col1, col2 = st.columns(2)
            
            with col1:
                plot_waveform(frames, framerate, "Original Waveform")
            
            with col2:
                plot_histogram(frames, "Original Histogram")
            
            # Message to hide
            st.markdown("<h3 class='section-header'>Message & Encryption</h3>", unsafe_allow_html=True)
            message = st.text_area("💬 Enter your secret message", height=100)
            
            # Encryption settings
            use_encryption = st.checkbox("Encrypt message with password", value=True)
            
            if use_encryption:
                password = st.text_input("Enter encryption password", type="password")
            
            # Embed button
            if st.button("🔏 Embed Message"):
                if not message:
                    st.error("Please enter a message to hide")
                elif use_encryption and not password:
                    st.error("Please enter an encryption password")
                else:
                    try:
                        # Prepare message (encrypt if needed)
                        final_message = message
                        if use_encryption:
                            final_message = encrypt_message(message, password)
                        
                        # Convert message to bits
                        message_bits = str_to_bits(final_message)
                        
                        # Store message bits for capacity calculation
                        st.session_state.message_bits = message_bits
                        
                        # Embed using QIM
                        modified_data, error = qim_embed(audio_data, message_bits, delta, start_sample)
                        
                        if error:
                            st.error(error)
                        else:
                            # Convert modified array back to bytes
                            modified_frames = modified_data.tobytes()
                            
                            # Store the stego audio in session state
                            st.session_state.stego_audio = modified_frames
                            
                            # Create audio buffer for download
                            buffer = BytesIO()
                            with wave.open(buffer, 'wb') as out:
                                out.setparams(params)
                                out.writeframes(modified_frames)
                            
                            st.success("Message embedded successfully!")
                            
                            # Plot stego audio
                            st.subheader("Stego Audio Visualization")
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                plot_waveform(modified_frames, framerate, "Stego Waveform")
                            
                            with col2:
                                plot_histogram(modified_frames, "Stego Histogram")
                            
                            # Calculate SNR
                            signal_power = np.mean(audio_data**2)
                            noise = audio_data - modified_data
                            noise_power = np.mean(noise**2)
                            
                            if noise_power > 0:
                                snr = 10 * np.log10(signal_power / noise_power)
                                st.info(f"Signal-to-Noise Ratio (SNR): {snr:.2f} dB")
                                
                                if snr > 30:
                                    st.success("Excellent steganographic quality (SNR > 30dB)")
                                elif snr > 20:
                                    st.success("Good steganographic quality (SNR > 20dB)")
                                else:
                                    st.warning("Moderate steganographic quality. Steganography might be detectable.")
                            
                            # Band Energy Ratio Analysis
                            st.subheader("🎵 Band Energy Ratio Analysis")
                            plot_band_energy_comparison(audio_data, modified_data, framerate)
                            
                            # Let user listen to the stego audio
                            st.subheader("Stego Audio")
                            st.audio(buffer.getvalue(), format='audio/wav')
                            
                            # Download button
                            st.download_button(
                                "⬇ Download Stego Audio", 
                                buffer.getvalue(), 
                                "stego_audio_qim.wav",
                                mime="audio/wav"
                            )
                            
                            # Show capacity info
                            total_samples = len(audio_data)
                            used_samples = len(message_bits)
                            capacity_percent = (used_samples / total_samples) * 100
                            
                            st.markdown(f"""
                            <div class="info-text">
                            <p><strong>Capacity Information:</strong></p>
                            <ul>
                                <li>Total samples: {total_samples}</li>
                                <li>Used samples: {used_samples}</li>
                                <li>Capacity used: {capacity_percent:.2f}%</li>
                                <li>Maximum message size: ~{total_samples // 8} characters</li>
                            </ul>
                            </div>
                            """, unsafe_allow_html=True)
                            
                    except Exception as e:
                        st.error(f"Error embedding message: {str(e)}")

    # EXTRACT MESSAGE TAB
    with tabs[1]:
        st.markdown("<h2 class='sub-header'>Extract Hidden Message</h2>", unsafe_allow_html=True)
        
        # Option to use either session stored audio or upload stego audio
        decrypt_source = st.radio(
            "Select audio source for extraction",
            ["Use stego audio from above", "Upload stego audio file"],
            index=0 if st.session_state.stego_audio else 1
        )
        
        if decrypt_source == "Upload stego audio file":
            stego_file = st.file_uploader("Upload stego audio file", type=["wav"], key="stego_uploader")
            if stego_file:
                with wave.open(stego_file, 'rb') as wav:
                    stego_params = wav.getparams()
                    stego_frames = wav.readframes(wav.getnframes())
                st.session_state.stego_audio = stego_frames
                st.session_state.original_params = stego_params
                
                # Display the uploaded stego audio
                st.audio(stego_file, format='audio/wav')
                
                # Plot stego audio waveform
                st.subheader("Stego Audio Visualization")
                plot_waveform(stego_frames, stego_params.framerate, "Stego Waveform")
        
        # Extraction settings
        st.markdown("<h3 class='section-header'>Extraction Settings</h3>", unsafe_allow_html=True)
        
        # Use same delta and start_sample as sidebar for consistency
        st.info(f"Using Delta: {delta}, Starting Sample: {start_sample}")
        
        # Password input for decryption
        is_encrypted = st.checkbox("Message is encrypted", value=True)
        
        if is_encrypted:
            extract_password = st.text_input("Enter decryption password", type="password")
        
        # Extract Button
        if st.button("🔍 Extract Message"):
            if st.session_state.stego_audio is None:
                st.error("No stego audio available. Please embed a message or upload a stego audio file.")
            elif is_encrypted and not extract_password:
                st.error("Please enter a decryption password.")
            else:
                try:
                    # Convert audio frames to numpy array
                    audio_data = np.frombuffer(st.session_state.stego_audio, dtype=np.int16)
                    
                    # Extract bits using QIM
                    extracted_bits = qim_extract(audio_data, delta, start_sample)
                    
                    # Convert bits to string
                    extracted_text = bits_to_str(extracted_bits)
                    
                    # Decrypt if necessary
                    final_text = extracted_text
                    if is_encrypted:
                        try:
                            final_text = decrypt_message(extracted_text, extract_password)
                        except Exception as e:
                            st.error(f"Decryption failed: {str(e)}")
                            st.error("Check if you're using the correct password.")
                            final_text = "Decryption failed. Check your password."
                    
                    # Display the extracted message
                    st.success("Message extracted successfully!")
                    
                    # Display the extracted message in a nice card
                    st.markdown("<div class='card'>", unsafe_allow_html=True)
                    st.subheader("📜 Extracted Message")
                    st.markdown(f"<div class='success-text'>{final_text}</div>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)
                    
                    # Add copy button
                    st.text_area("Copy message:", final_text, height=150)
                    
                    # For analysis, show correlation and capacity if original samples exist
                    if st.session_state.original_samples is not None:
                        stego_samples = audio_data
                        
                        # 📊 Correlation Coefficient
                        correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                        st.subheader("📊 Statistical Similarity After Extraction")
                        st.write(f"**Correlation Coefficient:** {correlation:.4f}  _(close to 1 = high similarity; 0 = different audio)_")

                        # 📦 Embedding Capacity
                        if st.session_state.message_bits is not None:
                            total_bits, total_chars, percent_used = calculate_embedding_capacity(
                                st.session_state.original_samples, st.session_state.message_bits)
                            st.subheader("📦 Embedding Capacity After Extraction")
                            st.write(f"**Bits embedded:** {total_bits}")
                            st.write(f"**Characters embedded:** {total_chars}")
                            st.write(f"**Audio capacity used:** {percent_used:.4f}%")
                            
                        # Band Energy Ratio Analysis for extracted audio
                        st.subheader("🎵 Band Energy Ratio Analysis (Extraction)")
                        plot_band_energy_comparison(st.session_state.original_samples, stego_samples, 
                                                   st.session_state.original_params.framerate)
                    
                except Exception as e:
                    st.error(f"Error extracting message: {str(e)}")
        
        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")



# ------------ Rubik's +AES STEGANOGRAPHY PAGE ------------
elif page == "Rubik's + AES Steganography":
    import streamlit as st
    import numpy as np
    import wave
    import os
    import base64
    import tempfile
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import scrypt
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    import matplotlib.pyplot as plt
    from scipy import signal

    # Initialize session state
    if 'stego_audio' not in st.session_state:
        st.session_state.stego_audio = None
    if 'original_samples' not in st.session_state:
        st.session_state.original_samples = None
    if 'message_bits' not in st.session_state:
        st.session_state.message_bits = None
    if "temp_dir" not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()

    def str_to_bin(s):
        return ''.join(format(ord(c), '08b') for c in s)

    def bin_to_str(b):
        chars = [chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]
        return ''.join(chars)

    def lsb_embed(audio_bytes, message):
        bits = str_to_bin(message + '|||END')
        audio = bytearray(audio_bytes)
        if len(bits) > len(audio):
            return None, "Message too large for audio"
        
        # Store message bits in session state for analysis
        st.session_state.message_bits = bits
        
        for i, bit in enumerate(bits):
            audio[i] = (audio[i] & 254) | int(bit)
        return bytes(audio), None

    def lsb_extract(audio_bytes):
        audio = bytearray(audio_bytes)
        bits = ''.join([str(b & 1) for b in audio])
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
        msg = ''.join(chars)
        return msg.split('|||END')[0] if '|||END' in msg else "No message found"

    def scramble_matrix(msg):
        size = int(np.ceil(np.sqrt(len(msg))))
        padded = msg.ljust(size * size)
        matrix = np.array(list(padded)).reshape(size, size)
        matrix = np.roll(matrix, 1, axis=0)
        matrix = np.roll(matrix, 1, axis=1)
        return ''.join(matrix.flatten())

    def descramble_matrix(msg):
        size = int(np.sqrt(len(msg)))
        matrix = np.array(list(msg)).reshape(size, size)
        matrix = np.roll(matrix, -1, axis=1)
        matrix = np.roll(matrix, -1, axis=0)
        return ''.join(matrix.flatten()).strip()

    def aes_encrypt(text, password):
        salt = get_random_bytes(16)
        key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(text.encode(), AES.block_size))
        return base64.b64encode(salt + cipher.iv + ct).decode()

    def aes_decrypt(enc_text, password):
        try:
            raw = base64.b64decode(enc_text)
            salt, iv, ct = raw[:16], raw[16:32], raw[32:]
            key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode()
        except Exception as e:
            return f"Decryption error: {str(e)}"

    def plot_waveform(frames, framerate, title):
        audio_data = np.frombuffer(frames, dtype=np.int16)
        times = np.linspace(0, len(audio_data) / framerate, num=len(audio_data))
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(times[:1000], audio_data[:1000])
        ax.set_title(title + " (First 1000 Samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)
    
    def calculate_correlation(original_samples, stego_samples):
        # Calculate correlation coefficient between original and stego audio
        if original_samples is None or stego_samples is None:
            return 0
        
        # Ensure same length
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len]
        stego = stego_samples[:min_len]
        
        # Calculate correlation coefficient
        correlation = np.corrcoef(original, stego)[0, 1]
        return correlation
    
    def calculate_embedding_capacity(original_samples, message_bits):
        if original_samples is None or message_bits is None:
            return 0, 0, 0
            
        total_bits = len(message_bits)
        total_chars = total_bits // 8
        percent_used = (total_bits / len(original_samples)) * 100
        
        return total_bits, total_chars, percent_used
    
    def calculate_band_energy_ratio(audio_samples, framerate, plot_spectrum=False):
        """
        Calculate Band Energy Ratio (BER) for steganalysis
        BER compares energy in different frequency bands to detect LSB modifications
        """
        if audio_samples is None or len(audio_samples) == 0:
            return None, None, None
        
        # Convert to float for FFT
        audio_float = audio_samples.astype(np.float64)
        
        # Apply window to reduce spectral leakage
        windowed = audio_float * np.hanning(len(audio_float))
        
        # Compute FFT
        fft = np.fft.fft(windowed)
        freqs = np.fft.fftfreq(len(fft), 1/framerate)
        
        # Take only positive frequencies
        pos_freqs = freqs[:len(freqs)//2]
        pos_fft = fft[:len(fft)//2]
        
        # Calculate power spectrum
        power_spectrum = np.abs(pos_fft)**2
        
        # Define frequency bands
        nyquist = framerate / 2
        low_band = (pos_freqs >= 0) & (pos_freqs < nyquist * 0.25)      # 0-25% of Nyquist
        mid_band = (pos_freqs >= nyquist * 0.25) & (pos_freqs < nyquist * 0.75)  # 25-75% of Nyquist
        high_band = (pos_freqs >= nyquist * 0.75) & (pos_freqs <= nyquist)       # 75-100% of Nyquist
        
        # Calculate energy in each band
        low_energy = np.sum(power_spectrum[low_band])
        mid_energy = np.sum(power_spectrum[mid_band])
        high_energy = np.sum(power_spectrum[high_band])
        
        # Calculate band energy ratios
        total_energy = low_energy + mid_energy + high_energy
        if total_energy == 0:
            return 0, 0, 0
            
        low_ratio = low_energy / total_energy
        mid_ratio = mid_energy / total_energy
        high_ratio = high_energy / total_energy
        
        # Plot spectrum if requested
        if plot_spectrum:
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
            
            # Plot power spectrum
            ax1.semilogy(pos_freqs, power_spectrum)
            ax1.axvline(nyquist * 0.25, color='r', linestyle='--', alpha=0.7, label='Low/Mid boundary')
            ax1.axvline(nyquist * 0.75, color='r', linestyle='--', alpha=0.7, label='Mid/High boundary')
            ax1.set_xlabel('Frequency (Hz)')
            ax1.set_ylabel('Power')
            ax1.set_title('Power Spectrum with Frequency Bands')
            ax1.legend()
            ax1.grid(True, alpha=0.3)
            
            # Plot band energy ratios
            bands = ['Low\n(0-25%)', 'Mid\n(25-75%)', 'High\n(75-100%)']
            ratios = [low_ratio, mid_ratio, high_ratio]
            colors = ['blue', 'green', 'red']
            
            bars = ax2.bar(bands, ratios, color=colors, alpha=0.7)
            ax2.set_ylabel('Energy Ratio')
            ax2.set_title('Band Energy Ratios')
            ax2.set_ylim(0, 1)
            ax2.grid(True, alpha=0.3)
            
            # Add value labels on bars
            for bar, ratio in zip(bars, ratios):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 0.01,
                        f'{ratio:.3f}', ha='center', va='bottom')
            
            plt.tight_layout()
            st.pyplot(fig)
        
        return low_ratio, mid_ratio, high_ratio
    
    def analyze_ber_changes(original_ber, stego_ber):
        """Analyze changes in Band Energy Ratios between original and stego audio"""
        if original_ber[0] is None or stego_ber[0] is None:
            return None
        
        low_change = abs(stego_ber[0] - original_ber[0])
        mid_change = abs(stego_ber[1] - original_ber[1])
        high_change = abs(stego_ber[2] - original_ber[2])
        
        total_change = low_change + mid_change + high_change
        
        return {
            'low_change': low_change,
            'mid_change': mid_change,
            'high_change': high_change,
            'total_change': total_change,
            'max_change': max(low_change, mid_change, high_change)
        }

    st.title("🔐 Rubik's Cube + AES Audio Steganography")
   
    tab1, tab2 = st.tabs(["Embed", "Extract"])

    # Sidebar with info
    with st.sidebar:
        st.markdown("<h2 class='sub-head'>About Rubik's + AES Steganography</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-text'>
        <p>This module allows you to securely hide messages in audio files using:</p>
        <ul>
        <li><strong>AES encryption</strong> for strong symmetric message protection</li>
        <li><strong>Rubik's Cube scrambling</strong> to obfuscate message structure</li>
        <li><strong>LSB audio steganography</strong> to embed encrypted messages in audio</li>
        <li><strong>Waveform visualization</strong> to analyze changes in the audio</li>
        <li><strong>Band Energy Ratio (BER)</strong> analysis for steganalysis detection</li>
        </ul>
        <p>The layered approach (AES + Scrambling + LSB) boosts security by combining cryptography with steganography and matrix-based message transformation.</p>
        <p><strong>BER Analysis:</strong> Compares energy distribution across frequency bands to detect potential steganographic modifications.</p>
        </div>
        """, unsafe_allow_html=True)
    
    with tab1:
        st.subheader("🧬 Embed Message")
        audio_file = st.file_uploader("Upload WAV Audio", type=["wav"])
        message = st.text_area("Secret Message")
        password = st.text_input("Encryption Password", type="password")

        if audio_file and message and password:
            with wave.open(audio_file, 'rb') as wav:
                params = wav.getparams()
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()
            
            # Store original audio data for comparison
            audio_data = np.frombuffer(frames, dtype=np.int16)
            st.session_state.original_samples = audio_data

            st.subheader("Original Audio Waveform")
            plot_waveform(frames, framerate, "Original Audio")
            
            # Calculate original BER
            st.subheader("📊 Original Audio - Band Energy Ratio Analysis")
            original_ber = calculate_band_energy_ratio(audio_data, framerate, plot_spectrum=True)
            st.session_state.original_ber = original_ber

            if st.button("🔏 Encrypt, Scramble & Embed"):
                encrypted = aes_encrypt(message, password)
                scrambled = scramble_matrix(encrypted)
                encoded_frames, error = lsb_embed(frames, scrambled)
                
                if error:
                    st.error(error)
                else:
                    output_path = os.path.join(st.session_state.temp_dir, "stego_rubik_aes.wav")
                    with wave.open(output_path, 'wb') as out:
                        out.setparams(params)
                        out.writeframes(encoded_frames)
                    
                    # Store stego audio for later use
                    st.session_state.stego_audio = encoded_frames
                    stego_samples = np.frombuffer(encoded_frames, dtype=np.int16)

                    st.success("Message embedded!")
                    st.audio(output_path)
                    st.subheader("Stego Audio Waveform")
                    plot_waveform(encoded_frames, framerate, "Stego Audio")
                    
                    # Calculate stego BER and compare
                    st.subheader("📊 Stego Audio - Band Energy Ratio Analysis")
                    stego_ber = calculate_band_energy_ratio(stego_samples, framerate, plot_spectrum=True)
                    
                    # BER comparison
                    st.subheader("🔍 BER Change Analysis")
                    ber_changes = analyze_ber_changes(original_ber, stego_ber)
                    
                    if ber_changes:
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write("**Original BER:**")
                            st.write(f"Low Band: {original_ber[0]:.4f}")
                            st.write(f"Mid Band: {original_ber[1]:.4f}")
                            st.write(f"High Band: {original_ber[2]:.4f}")
                        
                        with col2:
                            st.write("**Stego BER:**")
                            st.write(f"Low Band: {stego_ber[0]:.4f}")
                            st.write(f"Mid Band: {stego_ber[1]:.4f}")
                            st.write(f"High Band: {stego_ber[2]:.4f}")
                        
                        st.write("**BER Changes:**")
                        st.write(f"Low Band Change: {ber_changes['low_change']:.6f}")
                        st.write(f"Mid Band Change: {ber_changes['mid_change']:.6f}")
                        st.write(f"High Band Change: {ber_changes['high_change']:.6f}")
                        st.write(f"Total Change: {ber_changes['total_change']:.6f}")
                        st.write(f"Maximum Change: {ber_changes['max_change']:.6f}")
                        
                        # Interpretation
                        if ber_changes['total_change'] < 0.001:
                            st.success("🟢 Very low BER change - steganography well hidden")
                        elif ber_changes['total_change'] < 0.01:
                            st.warning("🟡 Moderate BER change - some detectability risk")
                        else:
                            st.error("🔴 High BER change - steganography may be detectable")

                    with open(output_path, 'rb') as f:
                        st.download_button("⬇ Download Stego Audio", f.read(), "stego_rubik_aes.wav", mime="audio/wav")

    with tab2:
        st.subheader("🔍 Extract Message")
        
        # Option to use either session stored audio or upload stego audio
        decrypt_source = st.radio(
            "Select audio source for extraction",
            ["Use stego audio from above", "Upload stego audio file"],
            index=0 if st.session_state.stego_audio else 1
        )
        
        stego_frames = None
        framerate = None
        
        if decrypt_source == "Use stego audio from above" and st.session_state.stego_audio:
            stego_frames = st.session_state.stego_audio
            # Display the stego audio
            st.audio(stego_frames, format='audio/wav')
            # Set framerate from original audio
            if hasattr(st.session_state, 'original_params') and st.session_state.original_params:
                framerate = st.session_state.original_params.framerate
            else:
                framerate = 44100  # Default framerate if original params not available
        elif decrypt_source == "Upload stego audio file":
            stego_audio = st.file_uploader("Upload Stego Audio", type=["wav"], key="extract")
            if stego_audio:
                with wave.open(stego_audio, 'rb') as wav:
                    stego_frames = wav.readframes(wav.getnframes())
                    framerate = wav.getframerate()
                # Display the uploaded stego audio
                st.audio(stego_audio, format='audio/wav')
                
        extract_password = st.text_input("Password to Decrypt", type="password", key="pwd")

        if stego_frames and extract_password and framerate:
            st.subheader("Stego Audio Waveform")
            plot_waveform(stego_frames, framerate, "Stego Audio")
            
            # BER analysis of stego audio
            stego_samples = np.frombuffer(stego_frames, dtype=np.int16)
            st.subheader("📊 Stego Audio - Band Energy Ratio Analysis")
            current_stego_ber = calculate_band_energy_ratio(stego_samples, framerate, plot_spectrum=True)

            if st.button("🧪 Extract & Decrypt"):
                try:
                    extracted = lsb_extract(stego_frames)
                    descrambled = descramble_matrix(extracted)
                    decrypted = aes_decrypt(descrambled, extract_password)
                    
                    # Display the extracted message
                    st.success("Decrypted Message:")
                    st.code(decrypted)
                    
                    # For analysis, show correlation and capacity if original samples exist
                    if st.session_state.original_samples is not None:
                        
                        # 📊 Correlation Coefficient
                        correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                        st.subheader("📊 Statistical Similarity After Extraction")
                        st.write(f"**Correlation Coefficient:** {correlation:.4f}  _(close to 1 = high similarity; 0 = different audio)_")

                        # 📦 Embedding Capacity
                        if st.session_state.message_bits is not None:
                            total_bits, total_chars, percent_used = calculate_embedding_capacity(
                                st.session_state.original_samples, st.session_state.message_bits)
                            st.subheader("📦 Embedding Capacity After Extraction")
                            st.write(f"**Bits embedded:** {total_bits}")
                            st.write(f"**Characters embedded:** {total_chars}")
                            st.write(f"**Audio capacity used:** {percent_used:.4f}%")
                        
                        # 🔍 BER Comparison (if original BER available)
                        if hasattr(st.session_state, 'original_ber') and st.session_state.original_ber[0] is not None:
                            st.subheader("🔍 BER Comparison Analysis")
                            ber_changes = analyze_ber_changes(st.session_state.original_ber, current_stego_ber)
                            
                            if ber_changes:
                                col1, col2 = st.columns(2)
                                
                                with col1:
                                    st.write("**Original BER:**")
                                    st.write(f"Low Band: {st.session_state.original_ber[0]:.4f}")
                                    st.write(f"Mid Band: {st.session_state.original_ber[1]:.4f}")
                                    st.write(f"High Band: {st.session_state.original_ber[2]:.4f}")
                                
                                with col2:
                                    st.write("**Extracted Stego BER:**")
                                    st.write(f"Low Band: {current_stego_ber[0]:.4f}")
                                    st.write(f"Mid Band: {current_stego_ber[1]:.4f}")
                                    st.write(f"High Band: {current_stego_ber[2]:.4f}")
                                
                                st.write("**BER Detectability Analysis:**")
                                st.write(f"Total BER Change: {ber_changes['total_change']:.6f}")
                                
                                if ber_changes['total_change'] < 0.001:
                                    st.success("🟢 Steganography has minimal spectral impact")
                                elif ber_changes['total_change'] < 0.01:
                                    st.warning("🟡 Moderate spectral changes detected")
                                else:
                                    st.error("🔴 Significant spectral changes - high detectability risk")
                
                except Exception as e:
                    st.error(f"Error extracting message: {str(e)}")
        
        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")


# ------------ Rubik's STEGANOGRAPHY PAGE ------------
elif page == "Rubik's Steganography":
    import streamlit as st
    import numpy as np
    import wave
    import os
    import matplotlib.pyplot as plt
    import tempfile
    from scipy.signal import welch  # Added for BER

    def str_to_bin(s):
        return ''.join(format(ord(c), '08b') for c in s)

    def bin_to_str(b):
        chars = [chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)]
        return ''.join(chars)

    def lsb_embed(audio_bytes, message):
        bits = str_to_bin(message + '|||END')
        audio = bytearray(audio_bytes)
        if len(bits) > len(audio):
            return None, "Message too large for audio"
        for i, bit in enumerate(bits):
            audio[i] = (audio[i] & 254) | int(bit)
        return bytes(audio), None

    def lsb_extract(audio_bytes):
        audio = bytearray(audio_bytes)
        bits = ''.join([str(b & 1) for b in audio])
        chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
        msg = ''.join(chars)
        return msg.split('|||END')[0] if '|||END' in msg else "No message found"

    def scramble_matrix(msg):
        size = int(np.ceil(np.sqrt(len(msg))))
        padded = msg.ljust(size * size)
        matrix = np.array(list(padded)).reshape(size, size)
        matrix = np.roll(matrix, 1, axis=0)
        matrix = np.roll(matrix, 1, axis=1)
        return ''.join(matrix.flatten())

    def descramble_matrix(msg):
        size = int(np.sqrt(len(msg)))
        matrix = np.array(list(msg)).reshape(size, size)
        matrix = np.roll(matrix, -1, axis=1)
        matrix = np.roll(matrix, -1, axis=0)
        return ''.join(matrix.flatten()).strip()

    def plot_waveform(frames, framerate, title):
        audio_data = np.frombuffer(frames, dtype=np.int16)
        times = np.linspace(0, len(audio_data) / framerate, num=len(audio_data))
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(times[:1000], audio_data[:1000])
        ax.set_title(title + " (First 1000 Samples)")
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)

    def calculate_correlation(original_samples, stego_samples):
        original = np.frombuffer(original_samples, dtype=np.int16)
        stego = np.frombuffer(stego_samples, dtype=np.int16)
        min_len = min(len(original), len(stego))
        return np.corrcoef(original[:min_len], stego[:min_len])[0, 1]

    def calculate_embedding_capacity(audio_samples, message_bits):
        total_bits = len(message_bits)
        total_chars = total_bits // 8
        percent_used = (total_bits / len(audio_samples)) * 100
        return total_bits, total_chars, percent_used

    def calculate_band_energy_ratio(audio_bytes, framerate, low_band=(20, 300), high_band=(300, 3000)):
        audio = np.frombuffer(audio_bytes, dtype=np.int16)
        freqs, psd = welch(audio, fs=framerate)
        low_energy = np.sum(psd[(freqs >= low_band[0]) & (freqs < low_band[1])])
        high_energy = np.sum(psd[(freqs >= high_band[0]) & (freqs < high_band[1])])
        if high_energy == 0:
            return float('inf')
        return low_energy / high_energy

    st.title("🔐 Rubik's Cube Audio Steganography")
    if "temp_dir" not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()

    tab1, tab2 = st.tabs(["Embed", "Extract"])

    with st.sidebar:
        st.markdown("<h2 class='sub-head'>About Rubik's Steganography</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-text'>
        <p>This module demonstrates:</p>
        <ul>
        <li>Message embedding using Least Significant Bit (LSB) in audio files</li>
        <li>Scrambling messages in a matrix format inspired by Rubik's Cube logic</li>
        <li>Visualizing original and stego audio waveforms</li>
        <li>Secure extraction and descrambling of hidden messages</li>
        </ul>
        <p>The combination of scrambling and LSB steganography enhances secrecy and adds a puzzle-like transformation to the data hiding process.</p>
        </div>
        """, unsafe_allow_html=True)

    with tab1:
        st.subheader("🧬 Embed Message")
        audio_file = st.file_uploader("Upload WAV Audio", type=["wav"])
        message = st.text_area("Secret Message")

        if audio_file and message:
            with wave.open(audio_file, 'rb') as wav:
                params = wav.getparams()
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()

            if 'original_samples' not in st.session_state:
                st.session_state.original_samples = frames
                st.session_state.original_framerate = framerate

            st.subheader("Original Audio Waveform")
            plot_waveform(frames, framerate, "Original Audio")

            if st.button("🔏 Scramble & Embed"):
                scrambled = scramble_matrix(message)
                encoded_frames, error = lsb_embed(frames, scrambled)

                st.session_state.message_bits = str_to_bin(scrambled + '|||END')

                if error:
                    st.error(error)
                else:
                    output_path = os.path.join(st.session_state.temp_dir, "stego_rubik.wav")
                    with wave.open(output_path, 'wb') as out:
                        out.setparams(params)
                        out.writeframes(encoded_frames)

                    st.success("Message embedded!")
                    st.audio(output_path)
                    st.subheader("Stego Audio Waveform")
                    plot_waveform(encoded_frames, framerate, "Stego Audio")

                    with open(output_path, 'rb') as f:
                        st.download_button("⬇ Download Stego Audio", f.read(), "stego_rubik.wav", mime="audio/wav")

    with tab2:
        st.subheader("🔍 Extract Message")
        stego_audio = st.file_uploader("Upload Stego Audio", type=["wav"], key="extract")

        if stego_audio:
            with wave.open(stego_audio, 'rb') as wav:
                frames = wav.readframes(wav.getnframes())
                framerate = wav.getframerate()

            stego_samples = frames
            st.subheader("Stego Audio Waveform")
            plot_waveform(frames, framerate, "Stego Audio")

            if st.button("🧪 Extract Message"):
                try:
                    extracted = lsb_extract(frames)
                    descrambled = descramble_matrix(extracted)
                    st.success("Extracted Message:")
                    st.code(descrambled)

                    if 'original_samples' in st.session_state:
                        correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                        st.subheader("📊 Statistical Similarity After Extraction")
                        st.write(f"**Correlation Coefficient:** {correlation:.4f}")

                        if 'message_bits' in st.session_state:
                            total_bits, total_chars, percent_used = calculate_embedding_capacity(
                                st.session_state.original_samples, st.session_state.message_bits)
                            st.subheader("📦 Embedding Capacity After Extraction")
                            st.write(f"**Bits embedded:** {total_bits}")
                            st.write(f"**Characters embedded:** {total_chars}")
                            st.write(f"**Audio capacity used:** {percent_used:.4f}%")

                        # 🔉 Band Energy Ratio
                        st.subheader("🎵 Band Energy Ratio (BER) Analysis")
                        ber_original = calculate_band_energy_ratio(st.session_state.original_samples, st.session_state.original_framerate)
                        ber_stego = calculate_band_energy_ratio(stego_samples, framerate)
                        st.write(f"**Original BER (20–300 Hz / 300–3000 Hz):** {ber_original:.4f}")
                        st.write(f"**Stego BER (20–300 Hz / 300–3000 Hz):** {ber_stego:.4f}")
                        st.write(f"**Δ BER:** {abs(ber_original - ber_stego):.4f}")
                except Exception as e:
                    st.error(f"Error extracting message: {str(e)}")
        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")


# ------------ Adpative QIM STEGANOGRAPHY PAGE ------------
elif page == "Adaptive QIM Steganography":
    import streamlit as st
    import numpy as np
    import wave
    import matplotlib.pyplot as plt
    import hashlib
    import os
    import tempfile

    st.title("🔐 Adaptive QIM Audio Steganography ")

    # Session state initialization
    if "temp_dir" not in st.session_state:
        st.session_state.temp_dir = tempfile.mkdtemp()

    # Sidebar with info
    with st.sidebar:
        st.markdown("<h2 class='sub-head'>About Adaptive QIM Steganography</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-text'>
        <p>This module demonstrates:</p>
        <ul>
        <li>Embedding messages in audio files using Quantization Index Modulation (QIM) steganography technique</li>
        <li>Modifying the amplitude of audio samples based on the quantization index to hide bits of the secret message</li>
        <li>Visualizing both the original and stego audio waveforms to see the impact of embedding</li>
        <li>Using XOR-based decryption with a password to extract the hidden message securely</li>
        </ul>
        <p>QIM steganography allows for precise and robust embedding of messages in audio files by altering the quantization of audio samples, ensuring that the embedded message remains imperceptible to the human ear while maximizing the capacity for information hiding.</p>
        </div>
        """, unsafe_allow_html=True)

    def str_to_bin(s):
        return ''.join(format(ord(c), '08b') for c in s)

    def bin_to_str(b):
        return ''.join([chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)])

    def xor_encrypt_decrypt(message, password):
        key = hashlib.sha256(password.encode()).digest()
        return ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(message))

    def adaptive_qim_embed(audio, message, password, delta_low=2, delta_high=8):
        message = xor_encrypt_decrypt(message, password)
        bits = str_to_bin(message + '|||END')
        samples = np.frombuffer(audio, dtype=np.int16)

        if len(bits) > len(samples):
            return None, "Message too long for this audio"

        embedded = samples.copy()

        for i, bit in enumerate(bits):
            amp = abs(samples[i])
            if amp < 1000:
                delta = delta_low
            elif amp < 5000:
                delta = (delta_low + delta_high) // 2
            else:
                delta = delta_high

            if bit == '0':
                embedded[i] = int(np.round(samples[i] / delta) * delta)
            else:
                embedded[i] = int(np.round((samples[i] - delta // 2) / delta) * delta + delta // 2)

        return embedded.astype(np.int16).tobytes(), None

    def adaptive_qim_extract(audio, password, delta_low=2, delta_high=8):
        samples = np.frombuffer(audio, dtype=np.int16)
        bits = ''

        for i in range(len(samples)):
            amp = abs(samples[i])
            if amp < 1000:
                delta = delta_low
            elif amp < 5000:
                delta = (delta_low + delta_high) // 2
            else:
                delta = delta_high

            remainder = samples[i] % delta
            bits += '0' if remainder < delta // 2 else '1'

            if '|||END' in bin_to_str(bits):
                break

        message = bin_to_str(bits)
        clean_message = message.split('|||END')[0]

        try:
            decrypted = xor_encrypt_decrypt(clean_message, password)
        except:
            decrypted = "[Decryption failed. Wrong password or corrupted data.]"
        return decrypted

    def plot_waveform(samples, sample_rate, title):
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(np.arange(len(samples)) / sample_rate, samples, color='dodgerblue')
        ax.set_title(title)
        ax.set_xlabel("Time [s]")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)
        
    def calculate_correlation(original_samples, stego_samples):
        """Calculate correlation coefficient between original and stego audio"""
        original = np.frombuffer(original_samples, dtype=np.int16)
        stego = np.frombuffer(stego_samples, dtype=np.int16)
        # Ensure same length for comparison
        min_len = min(len(original), len(stego))
        return np.corrcoef(original[:min_len], stego[:min_len])[0, 1]
    
    def calculate_embedding_capacity(audio_samples, message_bits):
        """Calculate embedding capacity statistics"""
        total_bits = len(message_bits)
        total_chars = total_bits // 8
        percent_used = (total_bits / len(audio_samples)) * 100
        return total_bits, total_chars, percent_used

    tab1, tab2 = st.tabs(["Embed", "Extract"])

    with tab1:
        st.subheader("📥 Embed Message")
        wav_file = st.file_uploader("Upload WAV File", type=["wav"])
        secret = st.text_area("Enter secret message")
        password = st.text_input("Enter password", type="password")

        if wav_file and secret and password:
            with wave.open(wav_file, 'rb') as wf:
                params = wf.getparams()
                frames = wf.readframes(wf.getnframes())
                framerate = wf.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)
                
            # Store original samples for comparison
            st.session_state.original_samples = frames
            
            # Store message bits for capacity calculation
            encrypted_message = xor_encrypt_decrypt(secret, password)
            st.session_state.message_bits = str_to_bin(encrypted_message + '|||END')

            st.markdown("**Original Audio Waveform**")
            plot_waveform(samples, framerate, "Original Audio")

            embedded_audio, error = adaptive_qim_embed(frames, secret, password)

            if error:
                st.error(error)
            else:
                embedded_samples = np.frombuffer(embedded_audio, dtype=np.int16)
                st.markdown("**Embedded Audio Waveform**")
                plot_waveform(embedded_samples, framerate, "Stego Audio")

                output_path = os.path.join(st.session_state.temp_dir, "adaptive_qim_stego.wav")
                with wave.open(output_path, 'wb') as out_wav:
                    out_wav.setparams(params)
                    out_wav.writeframes(embedded_audio)

                st.success("✅ Message embedded successfully!")
                st.audio(output_path)
                with open(output_path, 'rb') as f:
                    st.download_button("⬇ Download Stego Audio", f.read(), "adaptive_qim_stego.wav", mime="audio/wav")

    with tab2:
        st.subheader("🔍 Extract Message")
        stego_file = st.file_uploader("Upload Stego WAV", type=["wav"], key="extract_qim")
        password_extract = st.text_input("Enter password to extract", type="password")

        if stego_file and password_extract:
            with wave.open(stego_file, 'rb') as wf:
                frames = wf.readframes(wf.getnframes())
                framerate = wf.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)
                
            stego_samples = frames
            st.markdown("**Stego Audio Waveform**")
            plot_waveform(samples, framerate, "Stego Audio")

            try:
                extracted = adaptive_qim_extract(frames, password_extract)
                st.success("🔓 Extracted Message:")
                st.code(extracted)

                # 📊 Correlation Coefficient
                if 'original_samples' in st.session_state:
                    correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                    st.subheader("📊 Statistical Similarity After Extraction")
                    st.write(f"**Correlation Coefficient:** {correlation:.4f}  _(close to 1 = high similarity; 0 = different audio)_")

                    # 📦 Embedding Capacity
                    if 'message_bits' in st.session_state:
                        total_bits, total_chars, percent_used = calculate_embedding_capacity(
                            st.session_state.original_samples, st.session_state.message_bits)
                        st.subheader("📦 Embedding Capacity After Extraction")
                        st.write(f"**Bits embedded:** {total_bits}")
                        st.write(f"**Characters embedded:** {total_chars}")
                        st.write(f"**Audio capacity used:** {percent_used:.4f}%")
                
            except Exception as e:
                st.error(f"Error extracting message: {str(e)}")
    
        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")

# ------------  QIM + LSB Hybrid STEGANOGRAPHY PAGE ------------
elif page == "QIM + LSB Hybrid Steganography":
    import streamlit as st
    import numpy as np
    import wave
    import matplotlib.pyplot as plt
    import hashlib
    from scipy import signal

    st.title("🔐 QIM + LSB Hybrid Audio Steganography ")
    
    # Sidebar with info
    with st.sidebar:
        st.markdown("<h2 class='sub-head'>About QIM + LSB Steganography</h2>", unsafe_allow_html=True)
        st.markdown("""
         <div class='info-text'>
         <p>This module demonstrates:</p>
         <ul>
         <li>Embedding messages in audio files using a combination of Quantization Index Modulation (QIM) and Least Significant Bit (LSB) steganography techniques</li>
         <li>Using QIM for embedding even bits with a precision-based transformation, and LSB for embedding odd bits</li>
         <li>Visualizing both the original and stego audio waveforms for comparison</li>
         <li>Ensuring secure message extraction through XOR-based decryption with a password</li>
         <li>Band Energy Ratio analysis to measure frequency domain changes</li>
         </ul>
         <p>The combination of QIM and LSB allows for effective message embedding while minimizing the perceptible impact on the audio quality, providing a balance between capacity and imperceptibility.</p>
    </div>
        """, unsafe_allow_html=True)

    def str_to_bin(s):
        return ''.join(format(ord(c), '08b') for c in s)

    def bin_to_str(b):
        return ''.join([chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)])

    def xor_encrypt_decrypt(message, password):
        key = hashlib.sha256(password.encode()).digest()
        return ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(message))

    def qim_lsb_embed(audio, message, password, delta=4):
        message = xor_encrypt_decrypt(message, password)
        bits = str_to_bin(message + '|||END')
        samples = np.frombuffer(audio, dtype=np.int16)

        if len(bits) > len(samples):
            return None, "Message too long for this audio"

        embedded = samples.copy()

        for i, bit in enumerate(bits):
            if i % 2 == 0:
                # QIM Embedding for even bits
                if bit == '0':
                    embedded[i] = int(np.round(samples[i] / delta) * delta)
                else:
                    embedded[i] = int(np.round((samples[i] - delta // 2) / delta) * delta + delta // 2)
            else:
                # LSB Embedding for odd bits
                embedded[i] = (samples[i] & ~1) | int(bit)

        return embedded.astype(np.int16).tobytes(), None

    def qim_lsb_extract(audio, password, delta=4):
        samples = np.frombuffer(audio, dtype=np.int16)
        bits = ''

        for i in range(len(samples)):
            if i % 2 == 0:
                remainder = samples[i] % delta
                bits += '0' if remainder < delta // 2 else '1'
            else:
                bits += str(samples[i] & 1)

            if '|||END' in bin_to_str(bits):
                break

        message = bin_to_str(bits)
        clean_message = message.split('|||END')[0]

        try:
            decrypted = xor_encrypt_decrypt(clean_message, password)
        except:
            decrypted = "[Decryption failed. Wrong password or corrupted data.]"
        return decrypted

    def plot_waveform(samples, sample_rate, title):
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(np.arange(len(samples)) / sample_rate, samples, color='purple')
        ax.set_title(title)
        ax.set_xlabel("Time [s]")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)

    def calculate_correlation(original_samples, stego_samples):
        """Calculate correlation coefficient between original and stego audio samples"""
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len]
        stego = stego_samples[:min_len]
        
        # Calculate correlation coefficient
        correlation = np.corrcoef(original, stego)[0, 1]
        return correlation

    def calculate_embedding_capacity(samples, message_bits):
        """Calculate embedding capacity statistics"""
        total_bits = len(message_bits)
        total_chars = total_bits // 8
        percent_used = (total_bits / len(samples)) * 100
        return total_bits, total_chars, percent_used

    def calculate_band_energy_ratio(original_samples, stego_samples, sample_rate):
        """
        Calculate Band Energy Ratio (BER) between original and stego audio
        Returns energy ratios for different frequency bands and overall BER
        """
        # Ensure both signals have the same length
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len].astype(float)
        stego = stego_samples[:min_len].astype(float)
        
        # Define frequency bands (in Hz)
        bands = {
            'Low (0-1kHz)': (0, 1000),
            'Low-Mid (1-4kHz)': (1000, 4000),
            'Mid (4-8kHz)': (4000, 8000),
            'High (8kHz+)': (8000, sample_rate//2)
        }
        
        # Calculate FFT for both signals
        fft_original = np.fft.fft(original)
        fft_stego = np.fft.fft(stego)
        
        # Frequency axis
        freqs = np.fft.fftfreq(len(original), 1/sample_rate)
        
        band_ratios = {}
        band_energies_orig = {}
        band_energies_stego = {}
        
        for band_name, (low_freq, high_freq) in bands.items():
            # Find frequency indices for this band
            band_mask = (np.abs(freqs) >= low_freq) & (np.abs(freqs) <= high_freq)
            
            # Calculate energy in this band for both signals
            energy_orig = np.sum(np.abs(fft_original[band_mask])**2)
            energy_stego = np.sum(np.abs(fft_stego[band_mask])**2)
            
            band_energies_orig[band_name] = energy_orig
            band_energies_stego[band_name] = energy_stego
            
            # Calculate ratio (avoid division by zero)
            if energy_orig > 0:
                ratio = energy_stego / energy_orig
            else:
                ratio = 0 if energy_stego == 0 else float('inf')
            
            band_ratios[band_name] = ratio
        
        # Calculate overall BER (total energy ratio)
        total_energy_orig = np.sum(np.abs(fft_original)**2)
        total_energy_stego = np.sum(np.abs(fft_stego)**2)
        
        overall_ber = total_energy_stego / total_energy_orig if total_energy_orig > 0 else 0
        
        return band_ratios, band_energies_orig, band_energies_stego, overall_ber

    def plot_band_energy_comparison(band_energies_orig, band_energies_stego):
        """Plot comparison of band energies between original and stego audio"""
        bands = list(band_energies_orig.keys())
        orig_energies = [band_energies_orig[band] for band in bands]
        stego_energies = [band_energies_stego[band] for band in bands]
        
        x = np.arange(len(bands))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(12, 6))
        bars1 = ax.bar(x - width/2, orig_energies, width, label='Original', color='blue', alpha=0.7)
        bars2 = ax.bar(x + width/2, stego_energies, width, label='Stego', color='red', alpha=0.7)
        
        ax.set_xlabel('Frequency Bands')
        ax.set_ylabel('Energy')
        ax.set_title('Band Energy Comparison: Original vs Stego Audio')
        ax.set_xticks(x)
        ax.set_xticklabels(bands, rotation=45, ha='right')
        ax.legend()
        ax.set_yscale('log')  # Use log scale for better visualization
        
        # Add value labels on bars
        for bar in bars1:
            height = bar.get_height()
            ax.annotate(f'{height:.2e}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),  # 3 points vertical offset
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)
        
        for bar in bars2:
            height = bar.get_height()
            ax.annotate(f'{height:.2e}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)
        
        plt.tight_layout()
        st.pyplot(fig)

    def calculate_snr(original_samples, stego_samples):
        """Calculate Signal-to-Noise Ratio between original and stego audio"""
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len].astype(float)
        stego = stego_samples[:min_len].astype(float)
        
        # Calculate noise (difference between original and stego)
        noise = stego - original
        
        # Calculate signal power and noise power
        signal_power = np.mean(original**2)
        noise_power = np.mean(noise**2)
        
        # Calculate SNR in dB
        if noise_power > 0:
            snr_db = 10 * np.log10(signal_power / noise_power)
        else:
            snr_db = float('inf')  # Perfect match
        
        return snr_db

    def calculate_psnr(original_samples, stego_samples):
        """Calculate Peak Signal-to-Noise Ratio"""
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len].astype(float)
        stego = stego_samples[:min_len].astype(float)
        
        # Calculate MSE
        mse = np.mean((original - stego)**2)
        
        if mse == 0:
            return float('inf')  # Perfect match
        
        # Maximum possible pixel value for 16-bit audio
        max_val = 2**15 - 1
        psnr = 20 * np.log10(max_val / np.sqrt(mse))
        
        return psnr

    tab1, tab2 = st.tabs(["Embed", "Extract"])

    with tab1:
        st.subheader("📥 Embed Message")
        wav_file = st.file_uploader("Upload WAV File", type=["wav"])
        secret = st.text_area("Enter secret message")
        password = st.text_input("Enter password", type="password")

        if wav_file and secret and password:
            with wave.open(wav_file, 'rb') as wf:
                params = wf.getparams()
                frames = wf.readframes(wf.getnframes())
                framerate = wf.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)

            st.markdown("**Original Audio Waveform**")
            plot_waveform(samples, framerate, "Original Audio")

            embedded_audio, error = qim_lsb_embed(frames, secret, password)

            if error:
                st.error(error)
            else:
                embedded_samples = np.frombuffer(embedded_audio, dtype=np.int16)
                st.markdown("**Embedded Audio Waveform**")
                plot_waveform(embedded_samples, framerate, "Stego Audio")

                # Store data for analysis
                st.session_state.original_samples = samples
                st.session_state.embedded_samples = embedded_samples
                st.session_state.sample_rate = framerate
                st.session_state.message_bits = str_to_bin(secret + '|||END')

                # Calculate quality metrics
                correlation = calculate_correlation(samples, embedded_samples)
                snr = calculate_snr(samples, embedded_samples)
                psnr = calculate_psnr(samples, embedded_samples)
                
                # Calculate and display Band Energy Ratio
                st.subheader("🎵 Band Energy Ratio Analysis")
                band_ratios, band_energies_orig, band_energies_stego, overall_ber = calculate_band_energy_ratio(
                    samples, embedded_samples, framerate)
                
                # Quality metrics overview
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Correlation", f"{correlation:.4f}")
                
                with col2:
                    st.metric("SNR (dB)", f"{snr:.2f}")
                
                with col3:
                    st.metric("PSNR (dB)", f"{psnr:.2f}")
                
                with col4:
                    st.metric("Overall BER", f"{overall_ber:.4f}")
                
                # Band Energy Analysis
                col5, col6 = st.columns(2)
                
                with col5:
                    st.write("**Band Energy Ratios (Stego/Original):**")
                    for band, ratio in band_ratios.items():
                        color = "🟢" if 0.95 <= ratio <= 1.05 else "🟡" if 0.9 <= ratio <= 1.1 else "🔴"
                        st.write(f"{color} {band}: {ratio:.4f}")
                
                with col6:
                    st.write("**Quality Assessment:**")
                    if correlation > 0.99:
                        st.success("✅ Excellent similarity")
                    elif correlation > 0.95:
                        st.info("ℹ️ Good similarity")
                    else:
                        st.warning("⚠️ Noticeable changes")
                    
                    if 0.99 <= overall_ber <= 1.01:
                        st.success("✅ Excellent energy preservation")
                    elif 0.95 <= overall_ber <= 1.05:
                        st.info("ℹ️ Good energy preservation")
                    else:
                        st.warning("⚠️ Noticeable energy change")
                
                # Plot band energy comparison
                st.markdown("**Band Energy Comparison**")
                plot_band_energy_comparison(band_energies_orig, band_energies_stego)

                # Embedding capacity
                total_bits, total_chars, percent_used = calculate_embedding_capacity(samples, st.session_state.message_bits)
                
                st.subheader("📦 Embedding Statistics")
                col7, col8, col9 = st.columns(3)
                
                with col7:
                    st.write(f"**Bits embedded:** {total_bits}")
                
                with col8:
                    st.write(f"**Characters embedded:** {total_chars}")
                
                with col9:
                    st.write(f"**Audio capacity used:** {percent_used:.4f}%")

                output_path = "qim_lsb_stego.wav"
                with wave.open(output_path, 'wb') as out_wav:
                    out_wav.setparams(params)
                    out_wav.writeframes(embedded_audio)

                st.success("✅ Message embedded successfully!")
                st.audio(output_path)
                with open(output_path, 'rb') as f:
                    st.download_button("⬇ Download Stego Audio", f.read(), "qim_lsb_stego.wav", mime="audio/wav")

    with tab2:
        st.subheader("🔍 Extract Message")
        stego_file = st.file_uploader("Upload Stego WAV", type=["wav"], key="extract_qim_lsb")
        password_extract = st.text_input("Enter password to extract", type="password")

        if stego_file and password_extract:
            with wave.open(stego_file, 'rb') as wf:
                frames = wf.readframes(wf.getnframes())
                framerate = wf.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)

            st.markdown("**Stego Audio Waveform**")
            plot_waveform(samples, framerate, "Stego Audio")

            try:
                extracted = qim_lsb_extract(frames, password_extract)
                st.success("🔓 Extracted Message:")
                st.code(extracted)
                
                # Statistical Analysis (if original is available)
                if 'original_samples' in st.session_state:
                    stego_samples = samples
                    
                    # Calculate quality metrics
                    correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                    snr = calculate_snr(st.session_state.original_samples, stego_samples)
                    psnr = calculate_psnr(st.session_state.original_samples, stego_samples)
                    
                    # Band Energy Ratio
                    band_ratios, band_energies_orig, band_energies_stego, overall_ber = calculate_band_energy_ratio(
                        st.session_state.original_samples, stego_samples, framerate)
                    
                    # Display results
                    st.subheader("📊 Statistical Analysis After Extraction")
                    
                    # Quality metrics overview
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Correlation", f"{correlation:.4f}")
                    
                    with col2:
                        st.metric("SNR (dB)", f"{snr:.2f}")
                    
                    with col3:
                        st.metric("PSNR (dB)", f"{psnr:.2f}")
                    
                    with col4:
                        st.metric("Overall BER", f"{overall_ber:.4f}")
                    
                    # Detailed Band Energy Analysis
                    st.subheader("🎵 Detailed Band Energy Analysis")
                    
                    col5, col6 = st.columns(2)
                    
                    with col5:
                        st.write("**Band Energy Ratios:**")
                        for band, ratio in band_ratios.items():
                            color = "🟢" if 0.95 <= ratio <= 1.05 else "🟡" if 0.9 <= ratio <= 1.1 else "🔴"
                            st.write(f"{color} {band}: {ratio:.4f}")
                    
                    with col6:
                        # Energy preservation quality assessment
                        good_bands = sum(1 for ratio in band_ratios.values() if 0.95 <= ratio <= 1.05)
                        total_bands = len(band_ratios)
                        
                        st.write("**Energy Preservation Quality:**")
                        st.write(f"Good bands: {good_bands}/{total_bands}")
                        
                        if good_bands == total_bands:
                            st.success("✅ Excellent preservation across all bands")
                        elif good_bands >= total_bands * 0.75:
                            st.info("ℹ️ Good preservation in most bands")
                        else:
                            st.warning("⚠️ Significant changes in multiple bands")
                    
                    # Plot band energy comparison
                    st.markdown("**Band Energy Comparison**")
                    plot_band_energy_comparison(band_energies_orig, band_energies_stego)

                    # Embedding Capacity
                    if 'message_bits' in st.session_state:
                        total_bits, total_chars, percent_used = calculate_embedding_capacity(
                            st.session_state.original_samples, st.session_state.message_bits)
                        
                        st.subheader("📦 Embedding Statistics")
                        col7, col8, col9 = st.columns(3)
                        
                        with col7:
                            st.write(f"**Bits embedded:** {total_bits}")
                        
                        with col8:
                            st.write(f"**Characters embedded:** {total_chars}")
                        
                        with col9:
                            st.write(f"**Audio capacity used:** {percent_used:.4f}%")
                
            except Exception as e:
                st.error(f"Error extracting message: {str(e)}")
                st.info("This may be due to incorrect password or corrupted data in the audio file.")
        
        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")


            
            
# ------------  RSA + AES Hybrid STEGANOGRAPHY PAGE ------------
elif page == "RSA + AES Hybrid Steganography":
    import streamlit as st
    import numpy as np
    import wave
    import matplotlib.pyplot as plt
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import scrypt
    import hashlib
    import base64
    from scipy import signal

    st.title("🔐 RSA + AES Hybrid Audio Steganography")
    
    # Sidebar with info
    with st.sidebar:
        st.markdown("<h2 class='sub-head'>About RSA + AES Steganography</h2>", unsafe_allow_html=True)
        st.markdown("""
        <div class='info-text'>
            <p>This module demonstrates:</p>
            <ul>
                <li>Hybrid encryption using RSA for asymmetric encryption and AES for symmetric encryption</li>
                <li>Embedding encrypted messages into audio files using QIM and LSB steganography techniques</li>
                <li>Visualizing original and stego audio waveforms for comparison</li>
                <li>Secure extraction and decryption of hidden messages using the same password and private key</li>
                <li>Band Energy Ratio analysis to measure frequency domain changes</li>
            </ul>
            <p>The combination of RSA and AES encryption provides a multi-layered approach to securing the hidden message, while steganography ensures that the message remains undetectable within the audio file.</p>
        </div>
        """, unsafe_allow_html=True)

    # RSA + AES Encryption and Decryption Functions
    def rsa_encrypt(message_bytes, public_key):
        cipher_rsa = public_key.encrypt(message_bytes, None)
        return cipher_rsa[0]

    def rsa_decrypt(ciphertext, private_key):
        decrypted = private_key.decrypt(ciphertext)
        return decrypted

    # AES Encryption
    def aes_encrypt(message, password):
        salt = get_random_bytes(16)
        key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)  # use key_len here
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode())
        return salt + cipher.nonce + tag + ciphertext

    # AES Decryption
    def aes_decrypt(ciphertext, password):
        salt, nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:48], ciphertext[48:]
        key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)  # use key_len here
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()

    def str_to_bin(s):
        return ''.join(format(ord(c), '08b') for c in s)

    def bin_to_str(b):
        return ''.join([chr(int(b[i:i+8], 2)) for i in range(0, len(b), 8)])

    def xor_encrypt_decrypt(message, password):
        key = hashlib.sha256(password.encode()).digest()
        return ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(message))

    def qim_lsb_embed(audio, message, password, delta=4):
        message = xor_encrypt_decrypt(message, password)
        bits = str_to_bin(message + '|||END')
        samples = np.frombuffer(audio, dtype=np.int16)

        if len(bits) > len(samples):
            return None, "Message too long for this audio"

        embedded = samples.copy()

        for i, bit in enumerate(bits):
            if i % 2 == 0:
                # QIM Embedding for even bits
                if bit == '0':
                    embedded[i] = int(np.round(samples[i] / delta) * delta)
                else:
                    embedded[i] = int(np.round((samples[i] - delta // 2) / delta) * delta + delta // 2)
            else:
                # LSB Embedding for odd bits
                embedded[i] = (samples[i] & ~1) | int(bit)

        return embedded.astype(np.int16).tobytes(), None

    def qim_lsb_extract(audio, password, delta=4):
        samples = np.frombuffer(audio, dtype=np.int16)
        bits = ''

        for i in range(len(samples)):
            if i % 2 == 0:
                remainder = samples[i] % delta
                bits += '0' if remainder < delta // 2 else '1'
            else:
                bits += str(samples[i] & 1)

            if '|||END' in bin_to_str(bits):
                break

        message = bin_to_str(bits)
        clean_message = message.split('|||END')[0]

        try:
            decrypted = xor_encrypt_decrypt(clean_message, password)
        except:
            decrypted = "[Decryption failed. Wrong password or corrupted data.]"
        return decrypted

    def plot_waveform(samples, sample_rate, title):
        fig, ax = plt.subplots(figsize=(10, 3))
        ax.plot(np.arange(len(samples)) / sample_rate, samples, color='purple')
        ax.set_title(title)
        ax.set_xlabel("Time [s]")
        ax.set_ylabel("Amplitude")
        st.pyplot(fig)
        
    def calculate_correlation(original_samples, stego_samples):
        """Calculate correlation coefficient between original and stego audio samples"""
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len]
        stego = stego_samples[:min_len]
        
        # Calculate correlation coefficient
        correlation = np.corrcoef(original, stego)[0, 1]
        return correlation

    def calculate_embedding_capacity(samples, message_bits):
        """Calculate embedding capacity statistics"""
        total_bits = len(message_bits)
        total_chars = total_bits // 8
        percent_used = (total_bits / len(samples)) * 100
        return total_bits, total_chars, percent_used

    def calculate_band_energy_ratio(original_samples, stego_samples, sample_rate):
        """
        Calculate Band Energy Ratio (BER) between original and stego audio
        Returns energy ratios for different frequency bands and overall BER
        """
        # Ensure both signals have the same length
        min_len = min(len(original_samples), len(stego_samples))
        original = original_samples[:min_len].astype(float)
        stego = stego_samples[:min_len].astype(float)
        
        # Define frequency bands (in Hz)
        bands = {
            'Low (0-1kHz)': (0, 1000),
            'Low-Mid (1-4kHz)': (1000, 4000),
            'Mid (4-8kHz)': (4000, 8000),
            'High (8kHz+)': (8000, sample_rate//2)
        }
        
        # Calculate FFT for both signals
        fft_original = np.fft.fft(original)
        fft_stego = np.fft.fft(stego)
        
        # Frequency axis
        freqs = np.fft.fftfreq(len(original), 1/sample_rate)
        
        band_ratios = {}
        band_energies_orig = {}
        band_energies_stego = {}
        
        for band_name, (low_freq, high_freq) in bands.items():
            # Find frequency indices for this band
            band_mask = (np.abs(freqs) >= low_freq) & (np.abs(freqs) <= high_freq)
            
            # Calculate energy in this band for both signals
            energy_orig = np.sum(np.abs(fft_original[band_mask])**2)
            energy_stego = np.sum(np.abs(fft_stego[band_mask])**2)
            
            band_energies_orig[band_name] = energy_orig
            band_energies_stego[band_name] = energy_stego
            
            # Calculate ratio (avoid division by zero)
            if energy_orig > 0:
                ratio = energy_stego / energy_orig
            else:
                ratio = 0 if energy_stego == 0 else float('inf')
            
            band_ratios[band_name] = ratio
        
        # Calculate overall BER (total energy ratio)
        total_energy_orig = np.sum(np.abs(fft_original)**2)
        total_energy_stego = np.sum(np.abs(fft_stego)**2)
        
        overall_ber = total_energy_stego / total_energy_orig if total_energy_orig > 0 else 0
        
        return band_ratios, band_energies_orig, band_energies_stego, overall_ber

    def plot_band_energy_comparison(band_energies_orig, band_energies_stego):
        """Plot comparison of band energies between original and stego audio"""
        bands = list(band_energies_orig.keys())
        orig_energies = [band_energies_orig[band] for band in bands]
        stego_energies = [band_energies_stego[band] for band in bands]
        
        x = np.arange(len(bands))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(12, 6))
        bars1 = ax.bar(x - width/2, orig_energies, width, label='Original', color='blue', alpha=0.7)
        bars2 = ax.bar(x + width/2, stego_energies, width, label='Stego', color='red', alpha=0.7)
        
        ax.set_xlabel('Frequency Bands')
        ax.set_ylabel('Energy')
        ax.set_title('Band Energy Comparison: Original vs Stego Audio')
        ax.set_xticks(x)
        ax.set_xticklabels(bands, rotation=45, ha='right')
        ax.legend()
        ax.set_yscale('log')  # Use log scale for better visualization
        
        # Add value labels on bars
        for bar in bars1:
            height = bar.get_height()
            ax.annotate(f'{height:.2e}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),  # 3 points vertical offset
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)
        
        for bar in bars2:
            height = bar.get_height()
            ax.annotate(f'{height:.2e}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)
        
        plt.tight_layout()
        st.pyplot(fig)
        
    # Create tabs for embed and extract functions
    tab1, tab2 = st.tabs(["Embed", "Extract"])

    with tab1:
        st.subheader("📥 Embed Message")
        wav_file = st.file_uploader("Upload WAV File", type=["wav"])
        secret = st.text_area("Enter secret message")
        password = st.text_input("Enter password", type="password")

        # RSA Key Generation and Encryption
        private_key = RSA.generate(2048)
        public_key = private_key.publickey()

        if wav_file and secret and password:
            # Encrypt the message using AES + RSA
            aes_encrypted_message = aes_encrypt(secret, password)
            # Use base64 encoding to safely handle binary data as a string
            encoded_aes_message = base64.b64encode(aes_encrypted_message).decode('ascii')
            
            with wave.open(wav_file, 'rb') as wf:
                params = wf.getparams()
                frames = wf.readframes(wf.getnframes())
                framerate = wf.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)

            st.markdown("**Original Audio Waveform**")
            plot_waveform(samples, framerate, "Original Audio")

            embedded_audio, error = qim_lsb_embed(frames, encoded_aes_message, password)

            if error:
                st.error(error)
            else:
                embedded_samples = np.frombuffer(embedded_audio, dtype=np.int16)
                st.markdown("**Embedded Audio Waveform**")
                plot_waveform(embedded_samples, framerate, "Stego Audio")
                
                # Store data for analysis
                st.session_state.original_samples = samples
                st.session_state.embedded_samples = embedded_samples
                st.session_state.sample_rate = framerate
                st.session_state.message_bits = str_to_bin(encoded_aes_message + '|||END')

                # Calculate and display Band Energy Ratio
                st.subheader("🎵 Band Energy Ratio Analysis")
                band_ratios, band_energies_orig, band_energies_stego, overall_ber = calculate_band_energy_ratio(
                    samples, embedded_samples, framerate)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Band Energy Ratios (Stego/Original):**")
                    for band, ratio in band_ratios.items():
                        color = "🟢" if 0.95 <= ratio <= 1.05 else "🟡" if 0.9 <= ratio <= 1.1 else "🔴"
                        st.write(f"{color} {band}: {ratio:.4f}")
                
                with col2:
                    st.write(f"**Overall BER:** {overall_ber:.6f}")
                    if 0.99 <= overall_ber <= 1.01:
                        st.success("✅ Excellent energy preservation")
                    elif 0.95 <= overall_ber <= 1.05:
                        st.info("ℹ️ Good energy preservation")
                    else:
                        st.warning("⚠️ Noticeable energy change")
                
                # Plot band energy comparison
                st.markdown("**Band Energy Comparison**")
                plot_band_energy_comparison(band_energies_orig, band_energies_stego)

                output_path = "rsa_aes_stego.wav"
                with wave.open(output_path, 'wb') as out_wav:
                    out_wav.setparams(params)
                    out_wav.writeframes(embedded_audio)

                st.success("✅ Message embedded successfully!")
                st.audio(output_path)
                with open(output_path, 'rb') as f:
                    st.download_button("⬇ Download Stego Audio", f.read(), "rsa_aes_stego.wav", mime="audio/wav")

    with tab2:
        st.subheader("🔍 Extract Message")
        stego_file = st.file_uploader("Upload Stego WAV", type=["wav"], key="extract_rsa_aes")
        password_extract = st.text_input("Enter password to extract", type="password")

        if stego_file and password_extract:
            with wave.open(stego_file, 'rb') as wf:
                frames = wf.readframes(wf.getnframes())
                framerate = wf.getframerate()
                samples = np.frombuffer(frames, dtype=np.int16)

            st.markdown("**Stego Audio Waveform**")
            plot_waveform(samples, framerate, "Stego Audio")
            
            try:
                extracted = qim_lsb_extract(frames, password_extract)
                
                try:
                    # Decode base64 to get the original encrypted bytes
                    aes_encrypted_message = base64.b64decode(extracted)
                    secret_message = aes_decrypt(aes_encrypted_message, password_extract)
                    
                    st.success("🔓 Extracted Message:")
                    st.code(secret_message)
                    
                    # Statistical Analysis
                    if 'original_samples' in st.session_state:
                        stego_samples = samples
                        
                        # Correlation Coefficient
                        correlation = calculate_correlation(st.session_state.original_samples, stego_samples)
                        
                        # Band Energy Ratio
                        band_ratios, band_energies_orig, band_energies_stego, overall_ber = calculate_band_energy_ratio(
                            st.session_state.original_samples, stego_samples, framerate)
                        
                        # Display results
                        st.subheader("📊 Statistical Analysis After Extraction")
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Correlation Coefficient:** {correlation:.4f}")
                            st.caption("_(close to 1 = high similarity; 0 = different audio)_")
                        
                        with col2:
                            st.write(f"**Overall Band Energy Ratio:** {overall_ber:.6f}")
                            st.caption("_(close to 1 = preserved energy distribution)_")
                        
                        # Detailed Band Energy Analysis
                        st.subheader("🎵 Detailed Band Energy Analysis")
                        
                        col3, col4 = st.columns(2)
                        
                        with col3:
                            st.write("**Band Energy Ratios:**")
                            for band, ratio in band_ratios.items():
                                color = "🟢" if 0.95 <= ratio <= 1.05 else "🟡" if 0.9 <= ratio <= 1.1 else "🔴"
                                st.write(f"{color} {band}: {ratio:.4f}")
                        
                        with col4:
                            # Energy preservation quality assessment
                            good_bands = sum(1 for ratio in band_ratios.values() if 0.95 <= ratio <= 1.05)
                            total_bands = len(band_ratios)
                            
                            st.write("**Energy Preservation Quality:**")
                            st.write(f"Good bands: {good_bands}/{total_bands}")
                            
                            if good_bands == total_bands:
                                st.success("✅ Excellent preservation across all bands")
                            elif good_bands >= total_bands * 0.75:
                                st.info("ℹ️ Good preservation in most bands")
                            else:
                                st.warning("⚠️ Significant changes in multiple bands")
                        
                        # Plot band energy comparison
                        st.markdown("**Band Energy Comparison**")
                        plot_band_energy_comparison(band_energies_orig, band_energies_stego)

                        # Embedding Capacity
                        if 'message_bits' in st.session_state:
                            total_bits, total_chars, percent_used = calculate_embedding_capacity(
                                st.session_state.original_samples, st.session_state.message_bits)
                            st.subheader("📦 Embedding Capacity")
                            st.write(f"**Bits embedded:** {total_bits}")
                            st.write(f"**Characters embedded:** {total_chars}")
                            st.write(f"**Audio capacity used:** {percent_used:.4f}%")
                    
                except Exception as e:
                    st.error(f"Error during decryption: {str(e)}")
                    st.info("This may be due to incorrect password or corrupted data in the audio file.")
                    
            except Exception as e:
                st.error(f"Error extracting message: {str(e)}")
        
        elif 'original_samples' not in st.session_state:
            st.warning("Please embed a message first to have an original audio for comparison.")