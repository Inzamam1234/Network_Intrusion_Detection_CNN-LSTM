# 🛡️ Real-Time Network Intrusion Detection System (NIDS)

This project detects **network attacks in real-time** using **Deep Learning**.  
It classifies network traffic into:

- Normal
- DoS (Denial of Service)
- Probe (Scanning / Data Gathering)
- R2L (Remote-to-Local Attack)
- U2R (User-to-Root Attack)

Our system works automatically — it monitors live network traffic, analyzes it, and alerts if an attack is detected.

---

## 🎯 Project Purpose

Traditional security tools (like firewalls or rule-based IDS) can only detect **known attacks**.  
They **fail** when a new or modified attack appears.

Our system uses **Deep Learning**, which learns patterns from data.  
So it can detect:
- Known attacks ✅
- Slightly modified attacks ✅
- Unknown (new) attacks ✅ *(to some level)*

---

## 📊 Dataset Used

We used the **NSL-KDD network intrusion dataset**, which contains labeled traffic data.

| Class | Meaning | Frequency |
|------|---------|-----------|
| Normal | Safe network behavior | High |
| DoS | Flooding / service disruption | High |
| Probe | Network scanning | Medium |
| R2L | External user trying to gain internal access | Low |
| U2R | Normal user trying to become root/admin | Very Low |

⚠️ R2L and U2R are **very rare**, so detecting them is challenging.

---

## 🧠 Model Used: Hybrid CNN + LSTM

We combined two deep learning models:

| Model Part | Purpose |
|-----------|---------|
| **CNN (Convolution Neural Network)** | Learns feature patterns in network data |
| **LSTM (Long Short-Term Memory Network)** | Understands sequence/behavior patterns |

This hybrid approach improves detection accuracy.

---
## 🔄 Workflow (How the System Works)

1.Capture network packets (Live)

2.Convert packet data into numerical features

3.Send features into CNN + LSTM model

4.Model predicts: Normal or type of attack

5.Display result in web dashboard + log it
---

## 🖥️ Dashboard (User Interface)

The dashboard shows:

- Current network traffic status
- Alerts when an attack is detected
- Attack type (DoS / Probe / R2L / U2R)
- Timestamp and logging history

Easy to monitor — no technical background needed.

---

## 🧪 Results Summary

- The system detects **Normal, DoS, and Probe** attacks very well.
- Detection of **R2L and U2R** is **improved but still challenging** (because they are rare).
- Still, our system performs **better than rule-based IDS**, which cannot detect new or unknown attacks.

---

## 🏁 Conclusion

Our project:

✔ Detects network attacks **in real time**  
✔ Uses **Deep Learning**, so it adapts to new attack patterns  
✔ Helps protect networks where manual monitoring is not possible  
✔ Provides a **simple dashboard** for easy monitoring  

This system can be used in:
- Local networks
- Colleges and labs
- Offices
- Home networks
- Mini SOC (Security Operation Centers)

---
