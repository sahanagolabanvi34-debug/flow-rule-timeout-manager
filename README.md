# 🚀 Flow Rule Timeout Manager

**Computer Networks Project — SDN Flow Rule Lifecycle Management**

---

## 📌 Overview

This project simulates **timeout-based flow rule management** in Software Defined Networking (SDN), similar to OpenFlow controllers like Ryu.

It demonstrates how flow rules are installed, updated, and removed based on **idle timeout, hard timeout, and network traffic conditions**, along with a full **GUI dashboard, analysis engine, and testing framework**.

---

## ✨ Features

* 📊 Flow Table Visualization (real-time updates)
* ⏱ Idle Timeout & Hard Timeout simulation
* 📦 Packet Simulator (manual + burst traffic)
* 🧭 Lifecycle Timeline (rule events tracking)
* 📈 Statistics Dashboard
* 🔬 Behavior Analysis Engine
* ✅ Regression Test Suite (22 test cases)

---

## 🧠 Key Concepts

| Concept      | Explanation                                         |
| ------------ | --------------------------------------------------- |
| Idle Timeout | Rule expires if no packet matches within N seconds  |
| Hard Timeout | Rule expires after fixed time regardless of traffic |
| Lifecycle    | ACTIVE → (IDLE_EXPIRED / HARD_EXPIRED) → REMOVED    |
| Timeout = 0  | Disables that timeout                               |

---

## 🗂 Project Structure

```
flow_rule_timeout_manager/
├── controller/
│   ├── __init__.py
│   └── flow_timeout_manager.py
├── tests/
│   ├── __init__.py
│   └── test_flow_timeout.py
├── logs/
├── gui.py
├── demo.py
├── analyze.py
├── requirements.txt
└── README.md
```

---

## ▶️ How to Run

### 1️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 2️⃣ Run GUI Dashboard

```bash
python gui.py
```

### 3️⃣ Run Demo (Lifecycle Simulation)

```bash
python demo.py
```

### 4️⃣ Run Analysis

```bash
python analyze.py
```

### 5️⃣ Run Tests

```bash
python -m pytest tests/ -v
```

---

## 📁 Output (logs/)

* `flow_manager.log` → event logs
* `audit_log.json` → removed rules
* `analysis_report.json` → experiment results

---

## 🎯 Key Insight

> Idle timeout depends on traffic and resets with packet arrival, whereas hard timeout is an absolute timer and expires regardless of traffic.

---

## 👨‍💻 Author

**Kushal G**
PES1UG24AM145
