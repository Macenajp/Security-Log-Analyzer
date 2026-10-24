### English Version:
# 📈 SecLA - Changelog and Visual Evolution

This document tracks structural and interface updates to the Security Log Analyzer (SecLA) and will be updated regularly to reflect any details and/or content added to the project.

---

## [v1.2] - Threat Intelligence & Smart Caching
**Focus:** Data enrichment, API integration and protection, and conditional visual formatting.

* **VirusTotal Integration:** The system now automatically checks the reputation of each attacker IP extracted by AI.
* **Disk Cache (`vt_cache.json`):** Implementation of a cache for IPs that have already been checked, reducing API quota consumption from dozens to just 1 request per unique IP.
* **Enhanced UI:**
  * Added a `VirusTotal` column to the terminal table to display the results of the VirusTotal API analysis.
  * Alert-based color coding (Green for 0 detections, Red for confirmed threats).
  * Modern, clean visual design and color scheme for better readability

> **<img width="1023" height="578" alt="Image" src="https://github.com/user-attachments/assets/d5d81bf1-f9cb-4850-8631-af4f36d956f6" />**

<br>

---

## [v1.1] - TUI & Telemetry
**Focus:** Structured data visualization and hardware benchmarks.

* Replaced the raw JSON output in the terminal with a batch-rendered table interface using the `rich` library.
* Implementation of the telemetry system (`tokens/sec`).
* Creation of automatic export to `benchmark_[model].csv`.
* Improvement of the JSON parser via Regex to prevent breaks caused by AI-injected *markdown*.

> **<img width="1023" height="578" alt="Image" src="https://github.com/user-attachments/assets/e64a20b4-78c2-4a5c-86f4-fc109b1affee" />**

<br>

---

## [MVP] - Proof of Concept
**Focus:** Basic integration between Python, logs, and Ollama.

* Log reader (`log_Reader.py`) focused on SSH failures.
* Simple call via `requests` to the local `phi4-mini` model running via Ollama.
* Output displayed as plain text/raw JSON in the terminal.