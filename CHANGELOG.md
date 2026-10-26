# 📈 SecLA - Changelog and Visual Evolution

This document tracks structural and interface updates to the Security Log Analyzer (SecLA) and will be updated regularly to reflect any details and/or content added to the project.

---
## [v1.2.2] - UI/UX Refinement & PEP 8 Standardization
**Focus:** Visual consistency, readability, and Python coding standards.

* **Standardization:** Refactored all variables and functions to strictly follow PEP 8 `snake_case` naming conventions.
* **New table:** A secondary `summary_table` was created to make it easier to view the results.
* **Design Selection:** The layout has been improved, and some colors have been changed to make the text easier to read and understand.

> **<img width="1023" height="707" alt="Image" src="https://github.com/user-attachments/assets/b7aa8643-f345-492f-9cbe-d293bd66d630" />**
> 📝 **Architecture Note (Preparation for v1.3):**
> Although initially structured as a visual update, v1.2.2 introduced the multi-format engine in `log_reader.py` (new Nginx/Apache regex) and a strict rule precedence hierarchy in `slm_analyzer.py`.
> 
> **Impact:** This complexity has changed the hardware landscape. The `phi4-mini` model (the former standard) saw its accuracy drop from 100% to 24% when processing web logs, losing its ability to distinguish severity levels. In contrast, `gemma3:4b` has definitively taken the lead as the standard engine, achieving 80% in initial overall accuracy tests and, more recently, 100% overall accuracy and 100% compliance with severity levels (distinguishing HIGH-severity attacks from common MEDIUM-severity errors), all while operating significantly faster (~77 t/s).

<br>

---
## [v1.2.1] - Architectural Restructuring
**Focus:** Code organization, scalability, and workspace maintainability.

* Reorganized the project into a modular folder structure (`core/`, `scripts/`, `data/`).
* Created an exclusive subfolder for telemetry reports (`data/benchmarks/`).
* Updated internal Python imports to reflect the new flat-to-modular architecture.

<br>

---

## [v1.2] - Threat Intelligence & Smart Caching
**Focus:** Data enrichment, API integration and protection, and conditional visual formatting.

* **VirusTotal Integration:** The system now automatically checks the reputation of each attacker IP extracted by AI.
* **Disk Cache (`vt_cache.json`):** Implementation of a cache for IPs that have already been checked, reducing API quota consumption from dozens to just 1 request per unique IP.
* **Enhanced UI:**
  * Added a `VirusTotal` column to the terminal table to display the results of the VirusTotal API analysis.
  * Alert-based color coding (Green for 0 detections, Red for confirmed threats).
  * Modern, clean visual design and color scheme for better readability

> **<img width="1023" height="578" alt="Image" src="https://github.com/user-attachments/assets/1e9ccca9-f0ca-4c85-a856-122d50b9a77d" />**

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
