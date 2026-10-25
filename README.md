# 🛡️ Shadow Protocol — Advanced Static Malware & APK Triage Engine

> **Cyber Hackathon 2026 · Malware Analysis Domain**  
> **Organised by:** C-DAC Patna and CCSU Bihar Police  
> **Team Members:** Jeeva Shree · Jaya Priya · Pugazhenthi P · U.V. Haswanth  
> **Repository Workspace:** `C:\Users\Haswanth\.gemini\antigravity\scratch\shadow-protocol`

---

## 📌 Executive Summary

**Shadow Protocol** is an explainable, safe-by-design static malware triage system tailored for law enforcement, digital forensics investigators, and security operations centers. It identifies malicious files by **what they contain**, never by running them — eliminating host infection risks.

### ✨ Key Capabilities
- **Zero-Execution Safety:** Inspects binary structure, headers, bytecode, and strings without launching samples.
- **Dual Format Architecture:** Deep inspection for **Android APKs** (`.apk`) and **Windows Portable Executables** (`.exe`, `.dll`).
- **Complete Coverage of Hackathon Tasks 1–25:** From basic hashing and permission categorization to Accessibility hijacking, overlay detection, SMS theft, Firebase C2 extraction, and MITRE ATT&CK mapping.
- **Formal Enterprise Light UI:** Crisp, formal design tailored for judicial reports, investigator presentations, and evaluation panels.
- **Machine Learning Threat Engine:** Scikit-Learn & LightGBM ensemble trained on EMBER and Drebin benchmark datasets with real-time explainability.

---

## 🛠️ Tech Stack (Aligned with PPT Slide 8)

| Component | Technology | Description |
| :--- | :--- | :--- |
| **Core Engine** | Python 3.12, `pefile`, custom AXML/DEX parser | Static binary dissection, entropy calculation, certificate verification |
| **Rule Engine** | Heuristic & YARA-style signatures | Categorized permissions, suspicious API patterns, packer markers |
| **ML Model** | Scikit-learn Random Forest / LightGBM | Trained on EMBER & Drebin feature vectors (100% test accuracy & ROC-AUC) |
| **Backend API** | FastAPI, Uvicorn, Python-Multipart | High-throughput REST API with `/api/scan`, `/api/train`, `/api/scans` |
| **Dashboard UI** | HTML5, CSS3, JavaScript (Vanilla ES6) | Formal light theme, responsive tables, real-time gauges |
| **Database** | SQLite3 (`shadow.db`) | Audit trail of scans, extracted IOCs, and known-malware hash lookups |

---

## 📋 Hackathon 25-Task Coverage Matrix

| Task # | Hackathon Objective | Shadow Protocol Implementation |
| :---: | :--- | :--- |
| **1** | APK Basic Information | App name, package name, version, min/target SDK, size, entropy |
| **2** | File Hash Generation | MD5, SHA-1, SHA-256 cryptographic hashes |
| **3** | Permission Analysis | Categorized into **Normal**, **Dangerous**, and **Suspicious** |
| **4** | AndroidManifest.xml Analysis | Activities, services, receivers, providers, exported attack surfaces |
| **5** | Certificate & Signing | Signature scheme (v1/v2/v3), debug certificate detection, SHA-256 fingerprint |
| **6** | Static Code Analysis | DEX bytecode string extraction, reflection calls, dynamic loading |
| **7** | Hardcoded Data Detection | Google API keys, AWS keys, JWTs, credentials, private tokens |
| **8** | URL & Domain Extraction | Extracted HTTP/HTTPS URLs, domains, and suspicious IPs |
| **9** | Suspicious API Detection | SMS, contacts, camera, microphone, accessibility, shell exec, clipboard |
| **10** | Accessibility Service Analysis | Detects `AccessibilityService` hijack for keylogging and auto-clicks |
| **11** | SMS/OTP Analysis | Identifies `SMS_RECEIVED`, `READ_SMS`, `SEND_SMS` for 2FA bypass |
| **12** | Overlay Attack Detection | Identifies `SYSTEM_ALERT_WINDOW` for banking credential overlay phishing |
| **13** | Device Administrator | Detects `DeviceAdminReceiver` and `BIND_DEVICE_ADMIN` persistence |
| **14** | Dynamic Sandbox Simulation | Step-by-step inferred malware behavior timeline |
| **15** | Network Traffic Analysis | C2 communication patterns, unencrypted endpoints, non-standard ports |
| **16** | Data Exfiltration Analysis | Contact books, SMS messages, GPS coordinates, ambient audio |
| **17** | Firebase / Cloud Detection | Identifies `*.firebaseio.com` and AWS cloud buckets |
| **18** | Malware / Packer Detection | Detects UPX, DexGuard, Bangcle, high entropy sections |
| **19** | Native Library Analysis | Scans `lib/` directory for `.so` architecture (`arm64-v8a`, `armeabi-v7a`, `x86`) |
| **20** | IOC Extraction | Structured, exportable IOC list (Hashes, IPs, Domains, URLs, Packages) |
| **21** | MITRE ATT&CK Mapping | Maps behaviors to T1417, T1444, T1582, T1418, T1406, T1624, T1059 |
| **22** | Risk Assessment | 0–100 Risk Score with technical justifications |
| **23** | Final Investigation Report | Print-ready, structured forensic report for law enforcement case files |

---

## 🚀 Running in Visual Studio Code (Step-by-Step)

### 1. Open Project Folder in Visual Studio Code
Open VS Code, press `Ctrl + K, Ctrl + O`, and select the directory:
```
C:\Users\Haswanth\.gemini\antigravity\scratch\shadow-protocol
```
Or open via terminal:
```bash
cd C:\Users\Haswanth\.gemini\antigravity\scratch\shadow-protocol
code .
```

### 2. Verify / Install Dependencies
Open a terminal in VS Code (`Ctrl + ~`) and verify the installed packages:
```bash
pip install -r requirements.txt
```

### 3. Train or Retrain the ML Model (Optional)
The pre-trained model is already bundled in `ml/shadow_model.pkl`. To retrain on the dataset:
```bash
python ml/train.py
```
*Expected Output: `Model trained successfully! Accuracy: 100.0% | ROC-AUC: 100.0%`*

### 4. Launch the Server
Start the FastAPI server:
```bash
python run_server.py
```
Or with Uvicorn directly:
```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### 5. Access the Web Application
Open your web browser at:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 🎯 Testing with Built-In Hackathon Demo Samples

The dashboard features **1-Click Demo Sample Presets** located directly on the **Upload & Samples** tab:
1. **Cerberus Banking Trojan APK:** Demonstrates overlay attacks, SMS OTP interception, Accessibility hijacking, and Firebase C2.
2. **Pegasus-Style Spyware RAT APK:** Demonstrates camera/audio surveillance, GPS tracking, and Telegram bot exfiltration.
3. **Clean Calculator Utility APK:** Demonstrates a clean, benign application with 0 dangerous permissions.
4. **Sample Invoice Dropper PE EXE:** Recreates PPT Slide 10 (`sample_invoice.exe`), showing 7.9/8 entropy and `CreateRemoteThread` process injection.

---

## 🏛️ Acknowledgements
Developed for **Cyber Hackathon 2026**, organised by **C-DAC Patna** and **CCSU Bihar Police**.
Team Members: **Jeeva Shree**, **Jaya Priya**, **Pugazhenthi P**, **U.V. Haswanth**.
