<div align="center">

# 🛡️ Hybrid AI Intrusion Detection System

### *Lightweight, real-time, ML-powered web & network intrusion detection*

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-SocketIO-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Sniffing-005f73?style=for-the-badge&logo=wireshark&logoColor=white)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen?style=for-the-badge)](#-license)

<br>

**A hybrid Machine Learning + signature-based IDS that watches live network traffic,**
**flags known attacks, catches zero-day anomalies, and detects web-layer exploits — all in a live dashboard.**

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [How It Works](#-how-it-works)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [Training Your Own Model](#-training-your-own-model)
- [Running the Dashboard](#-running-the-dashboard)
- [Detection Capabilities](#-detection-capabilities)
- [Roadmap](#-roadmap)
- [Disclaimer](#-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**Hybrid AI Intrusion Detection System (Hybrid-AI-IDS)** is a lightweight network security tool that combines:

- 🌲 **Random Forest** — for detecting *known* attack signatures found in labeled traffic (e.g. CICIDS2017 dataset)
- 🌐 **Isolation Forest** — for catching *zero-day / anomalous* traffic that doesn't match any known pattern
- 🧩 **Regex Signature Matching** — for catching classic **web-layer attacks** (SQLi, XSS, Path Traversal / RCE) directly from HTTP payloads

All of this feeds into a live **Flask + Socket.IO dashboard** that streams alerts in real time, complete with attacker IP, geolocation, timestamp, and attack classification.

> Think of it as a mini SOC (Security Operations Center) you can run on your own laptop. 💻🔐

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🧠 **Hybrid Detection Engine** | Combines supervised (RandomForest) + unsupervised (IsolationForest) learning for both known & unknown threats |
| 🕸️ **Web Attack Signatures** | Lightweight regex engine flags SQL Injection, XSS, and Path Traversal / RCE attempts in HTTP payloads |
| 📡 **Live Packet Sniffing** | Uses Scapy to capture and analyze traffic in real time |
| 📊 **Real-Time Dashboard** | Flask-SocketIO powered UI pushes alerts instantly — no page refresh needed |
| 🌍 **IP Geolocation** | Automatically resolves attacker IPs to country/city/ISP (with private-network detection) |
| ⚙️ **Custom Training Pipeline** | Scripts to merge, clean, and train on your own CICIDS2017-style datasets |
| 🎨 **Colorful CLI Output** | Terminal alerts are color-coded by severity for quick triage |

---

## 🧬 How It Works

```
┌────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│   Live Traffic  │ --> │  Feature Extract  │ --> │  Scaler + PCA       │
│   (Scapy sniff) │     │  (flow features)  │     │  (dim. reduction)   │
└────────────────┘     └──────────────────┘     └─────────┬──────────┘
                                                            │
                        ┌───────────────────────────────────┴───────────────────────────────────┐
                        ▼                                                                         ▼
              ┌───────────────────┐                                                  ┌──────────────────────┐
              │   Random Forest    │  --- Known Attack? --->  🚨                     │  Isolation Forest      │
              │  (supervised)       │                                                 │  (anomaly detection)   │
              └───────────────────┘                                                  └──────────┬────────────┘
                                                                                                   │
                                                                                    Zero-Day Anomaly? ---> 🚨

     ┌───────────────────────────────────────────────────────────────────────┐
     │  Parallel Track: HTTP Payload → Regex Signatures (SQLi / XSS / RCE)   │  ---> 🚨
     └───────────────────────────────────────────────────────────────────────┘

                                        ▼
                        ┌───────────────────────────────┐
                        │   Flask-SocketIO Dashboard      │
                        │   (live alert feed + geo-IP)    │
                        └───────────────────────────────┘
```

---

## 📂 Project Structure

```
Hybrid-AI-Intrusion-Detection-System/
│
├── app.py               # 🚀 Main Flask + SocketIO dashboard & live sniffing engine
├── train_models.py       # 🧠 Trains the RandomForest + IsolationForest hybrid pipeline
├── merge_csvs.py         # 🔗 Merges multiple CICIDS2017-style CSVs into one dataset
├── prepare_data.py       # 🧹 Cleans data & generates synthetic DDoS samples
├── requirements.txt       # 📦 Python dependencies
├── templates/            # 🎨 Dashboard HTML templates
├── models/                # 💾 Saved trained pipeline (ids_pipeline.joblib) — generated after training
└── data/                  # 📊 Place your CICIDS2017 CSVs here
```

---

## 🛠️ Tech Stack

<div align="center">

| Layer | Technology |
|---|---|
| **Backend** | Python, Flask, Flask-SocketIO |
| **Machine Learning** | Scikit-learn (RandomForest, IsolationForest, PCA, StandardScaler) |
| **Packet Capture** | Scapy |
| **Data Processing** | Pandas, NumPy |
| **Model Persistence** | Joblib |
| **Geolocation** | ipapi.co REST API |

</div>

---

## 🚀 Getting Started

### 1️⃣ Clone the repository

```bash
git clone https://github.com/zohaibjaved-zj/Hybrid-AI-Intrusion-Detection-System.git
cd Hybrid-AI-Intrusion-Detection-System
```

### 2️⃣ Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

> ⚠️ **Note:** Scapy requires elevated (root/admin) privileges to sniff packets, and on some systems needs `libpcap`/`Npcap` installed.

---

## 🧠 Training Your Own Model

The pipeline expects a **CICIDS2017-style** dataset with flow-based features.

**Step 1 — Add your data**

Place your CICIDS2017 CSV files inside a `data/` folder.

**Step 2 — Merge & prepare**

```bash
python merge_csvs.py
python prepare_data.py
```

**Step 3 — Train the hybrid model**

```bash
python train_models.py
```

This trains:
- ✅ a **Random Forest** classifier (multi-class known-attack detection)
- ✅ an **Isolation Forest** (trained only on `BENIGN` traffic, for zero-day anomaly detection)

...and saves everything to:

```
models/ids_pipeline.joblib
```

---

## 📡 Running the Dashboard

> ⚠️ Run with elevated privileges since Scapy needs raw socket access.

```bash
sudo python app.py        # Linux/macOS
python app.py              # Windows (run terminal as Administrator)
```

Then open your browser at:

```
http://localhost:5000
```

You'll see a live-updating feed of:

- 🕒 Timestamp
- 🌍 Attacker IP + Geolocation
- 🏷️ Attack Type (Known / Zero-Day / Web Attack)
- 📈 Running totals & uptime

To test the web-attack detector, try sending SQLi/XSS-style payloads to your local instance on port `5000`.

---

## 🎯 Detection Capabilities

<div align="center">

| Detection Type | Method | Example |
|---|---|---|
| 🔴 **Known Attacks** | Random Forest (supervised) | DoS, PortScan, Botnet, Brute Force, etc. (per CICIDS2017 labels) |
| 🟠 **Zero-Day Anomalies** | Isolation Forest (unsupervised) | Traffic that deviates from learned "normal" baseline |
| 🟣 **Web Attacks** | Regex Signatures | SQL Injection, XSS, Path Traversal / RCE |

</div>

---

## 🗺️ Roadmap

- [ ] Add deep learning model option (LSTM/CNN for sequential flow data)
- [ ] Dockerize the full stack for one-command deployment
- [ ] Add authentication to the dashboard
- [ ] Export alerts to CSV / SIEM integration (e.g. Splunk, ELK)
- [ ] Expand web-attack signature set (SSRF, XXE, command injection variants)
- [ ] Add automated test suite

---

## ⚠️ Disclaimer

This project is intended for **educational and research purposes** — for use on networks and systems you **own or have explicit authorization to monitor**. Do not deploy this tool against networks or systems without proper authorization. The maintainers are not responsible for misuse.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — feel free to use, modify, and distribute with attribution.

---

<div align="center">

### ⭐ Support

If you find this project useful, please consider giving the repository a ⭐ star!
</div>

## 👨‍💻 Author

[**Muhammad Zohaib**](https://github.com/zohaibjaved-zj)

</div>
