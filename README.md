<h1 align="center">Security Log Analyzer</h1>


## 📑​| Description
SecLA (Security Log Analyzer) functions as a security log reader that integrates with on-premises AI systems, but without the need to rely on large language models for raw processing. Instead, it combines predefined security rules with lightweight, on-premises SLMs (Small Language Models) for contextual interpretation, enabling fast analysis that preserves privacy since it does not depend on external services. 

<br>

---

## ✨ | Updates (v1.1)
* **Terminal UI (TUI):** Built with `rich`, your entire table is rendered at once, as it generates superior performance efficiency.
* **Anti-Markdown JSON Shield:** Regex-hardened response parser in `slm_Analyzer.py` to prevent JSON decoding crashes across different SLM families.
* **Automated Telemetry & Benchmarking:** Tracks inference speed (`tokens/s`) per log entry and automatically exports structured results to `.csv`.
* **Attack Simulation Engine:** Includes `generator_Dummy_Logs.py` to synthesize realistic SSH authentication logs (`Accepted publickey` vs. `Failed password` attacks).

<br>


---
## 💿​| How to Install and Use
Prerequisites: Ensure you have Python3 and Ollama installed and running on your system.
  
1. Clone the repository and setup the environment:

    ```bash
    git clone https://github.com/Macenajp/Security-Log-Analyzer.git 
    cd Security-Log-Analyzer
    python3 -m venv venv

    source venv/bin/activate  # On Linux
    .\venv\Scripts\activate # On Windows

    pip install requests rich
    ```

2. Download the default SLM (using the terminal):
    ```bash
    ollama pull phi4-mini   
    ```


3. Run the analyzer:
    ```bash
    python generator_Dummy_Logs.py  # Generates a local 'test_auth.log' with simulated attacks
    ```
    ```bash
    python main.py
    ```
<br>

---
## 📡​| Hardware Viability & Benchmarks
#### Models:
Models were evaluated across two distinct hardware profiles to measure inference speed (tokens/s), JSON schema compliance, and contextual severity accuracy (distinguishing root/admin attacks as HIGH vs. standard user attacks as MEDIUM).

**Tested Environments**
* **Setup A (Main Workstation):** AMD Ryzen 7 5700X | 24 GB RAM DDR4 (2400 MHz (16gb + 8gb)) | NVIDIA RTX 4060 8GB VRAM (Windows 11)

* **Setup B (Notebook):** Intel Core i3-1315U | 8 GB RAM DDR4 (3200 MHz Single-Channel) | Intel UHD Graphics (EndeavourOS Linux)

*Benchmark Results*

| Model | Parameters | Setup A | Setup B | Accuracy & Notes |
|----------|----------|----------|----------|----------|
| PHI4-Mini (default) | 4B | ~50.39t/s | ~7.87t/s | 100% Accuracy; Properly separates HIGH (admin / root) from MEDIUM (standard user) 
| Gemma3| 4B | ~77.71t/s | ~7.61t/s| Fast, but over-flags 100% of suspicious events as HIGH severity (BRUTE_FORCE)
| GLM-4 | 9B | ~31.13t/s | N/A | Stable JSON output, but ~1.6x slower than Phi-4 Mini and flags 100% of events as HIGH
| QWEN3.5 | 4B | ERROR | ERROR | Collapses under strict Ollama API native JSON formatting restrictions, returning errors in 100% of requests

> **⚡ Architectural Overview of the Rendering UI (Live vs. Batch):** 
> During testing of version 1.1, real-time line-by-line rendering (rich.live) was evaluated against static batch rendering. The continuous redrawing of the terminal at 10 Hz caused the average inference throughput with the PHI4-Mini to experience a performance drop of ~6.48%. To extract 100% of the hardware’s raw performance, SecLA renders the table in batch mode by default as soon as the analysis batch is complete.
