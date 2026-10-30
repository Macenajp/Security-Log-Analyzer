<h1 align="center">Security Log Analyzer</h1>


## 📑​| Description
SecLA (Security Log Analyzer) functions as a security log reader that integrates with on-premises AI systems, but without the need to rely on large language models for raw processing. Instead, it combines predefined security rules with lightweight, on-premises SLMs (Small Language Models) for contextual interpretation, enabling fast analysis that preserves privacy since it does not depend on external services. 

<br>

---

## 🚀 | Updates (v1.3.2)

* **Multi-Format Engine Completion:** The system now successfully ingests and parses hybrid logs in a single stream, combining Web (Nginx/Apache), Auth (SSH), and System (Syslog/Kernel) events.
* **Kernel Threat Detection:** The AI engine is now capable of identifying internal system failures, such as `kernel panics` and `segfaults`, automatically classifying them under the `SYSTEM_FAILURE` threat category.
* **Smart API Bypassing:** Internal events lacking an external IP address (tagged as `LOCAL_SYSTEM`) dynamically bypass the VirusTotal API checks, preventing invalid requests and saving API quotas.
* **Interactive Event Dashboard:** The `scripts/dashboard.py` tool provides instant, read-only SQLite database querying with logical severity filtering and a one-click automated CSV export feature using professional ISO 8601 12-hour timestamps.

<br>

---
## 📡​| How to Install and Use
Prerequisites: Ensure you have Python3 and Ollama installed and running on your system.
  
1. Clone the repository and setup the environment:

    ```bash
    git clone https://github.com/Macenajp/Security-Log-Analyzer.git 
    cd Security-Log-Analyzer
    py -m venv venv # Or, you can use: python3 -m venv venv

    source venv/bin/activate    # On Linux
    .\venv\Scripts\activate     # On Windows

    py -m pip install requests rich python-dotenv # Or, you can use: pip install requests rich python-dotenv
    ```

2. Create a file named ".env" (without the quotation marks) in the project root directory and add your VirusTotal key:
   ```bash
   VT_API_KEY=your_VirusTotal_key_here
   ```

3. Download the default SLM (using the terminal):
    ```bash
    ollama pull gemma3:4b   
    ```


4. Run the analyzer:
    ```bash
    python generator_dummy_logs.py  # Generates a local 'test_auth.log' with simulated attacks
    ```
    ```bash
    python main.py
    ```
<br>

---
## 💻​| Hardware Viability & Benchmarks
#### Models:
Models were evaluated across two distinct hardware profiles to measure inference speed (tokens/s), JSON schema compliance, and contextual severity accuracy (distinguishing root/admin attacks as HIGH vs. standard user attacks as MEDIUM).

**Tested Environments**
* **Setup A (Main Workstation):** AMD Ryzen 7 5700X | 24 GB RAM DDR4 (2400 MHz (16gb + 8gb)) | NVIDIA RTX 4060 8GB VRAM (Windows 11)

* **Setup B (Notebook):** Intel Core i3-1315U | 8 GB RAM DDR4 (3200 MHz Single-Channel) | Intel UHD Graphics (EndeavourOS Linux)

*Benchmark Results*

| Model | Parameters | Setup A | Setup B | Accuracy & Notes |
|----------|----------|----------|----------|----------|
| Gemma3 (default) | 4B | ~77.71t/s | ~7.61t/s |  **100% Accuracy (Top Performer):** Flawless zero-shot deduction for multi-format logs. Perfectly separated HIGH severities (Path Traversal/SQLi) from MEDIUM severities (HTTP 403 blocks). |
| PHI4-Mini | 4B | ~50.39t/s | ~7.87t/s | **24% Accuracy:** Suffers from context collapse with web logs. Failed severity obedience entirely, incorrectly flagging 100% of anomalies as HIGH. |
| GLM-4 | 9B | ~31.13t/s | N/A | Stable JSON output, but ~1.6x slower than Phi-4 Mini and flags 100% of events as HIGH
| QWEN3.5 | 4B | ERROR | ERROR | Collapses under strict Ollama API native JSON formatting restrictions, returning errors in 100% of requests

> **⚡ Architectural Overview of the Rendering UI (Live vs. Batch):** 
> During testing of version 1.1, real-time line-by-line rendering (rich.live) was evaluated against static batch rendering. The continuous redrawing of the terminal at 10 Hz caused the average inference throughput with the PHI4-Mini to experience a performance drop of ~6.48%. To extract 100% of the hardware’s raw performance, SecLA renders the table in batch mode by default as soon as the analysis batch is complete.
> <br>

---

📜 **See the complete history of visual and technical updates in the [CHANGELOG](CHANGELOG.md)**
