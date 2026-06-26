# ⚡ THREAT RADAR
**Live URL Security Analysis Tool — Powered by VirusTotal API**

![Python](https://img.shields.io/badge/Python-3.8+-00FF66?style=flat-square&logo=python&logoColor=black)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal_v3-00FF66?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-00FF66?style=flat-square)

## Overview
Threat Radar is a desktop security tool that analyzes any URL in real time against VirusTotal's global threat database, aggregating results from 70+ professional security engines simultaneously.

## Features

### Real-Time Threat Analysis
- Scans any URL against VirusTotal's live database instantly
- Aggregates results from 70+ global security engines in one scan
- Automatically submits new URLs for live analysis if not previously scanned
- Displays detailed engine-by-engine breakdown of flagged threats

### Intelligent Threshold Scoring System
| Score | Level | Meaning |
|-------|-------|---------|
| 0 – 9 | ✅ SECURE | No threat signals detected |
| 10 – 24 | 🔵 LOW RISK | Minor signals, generally safe |
| 25 – 49 | 🟡 MEDIUM | Suspicious activity, proceed with caution |
| 50 – 74 | 🟠 HIGH RISK | Significant threat from multiple engines |
| 75 – 100 | 🔴 CRITICAL | Confirmed critical threat |

### Built-in API Key Setup
- First launch prompts for your VirusTotal API key
- Key is saved locally on your machine
- Change your key anytime via the ⚙ API KEY button

## Installation
```bash
pip install customtkinter requests
```

## Setup
1. Get your free API key from [virustotal.com](https://www.virustotal.com) → Profile → API Key
2. Run the program — it will ask for your key on first launch
3. Paste your key and click **SAVE & LAUNCH**

```bash
python ThreatRadar.py
```

## Built With
- **Python 3** — Core language
- **CustomTkinter** — Modern desktop UI
- **VirusTotal API v3** — Global threat intelligence

## Disclaimer
This tool is intended for legitimate security and educational use only.
