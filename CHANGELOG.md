# 📈 SecLA - Changelog and Visual Evolution

This document tracks structural and interface updates to the Security Log Analyzer (SecLA) and will be updated regularly to reflect any details and/or content added to the project.

---
## [v1.3.1] - Internationalization & Interactive Dashboard
**Focus:** Global accessibility, database consumption, and rapid reporting.

* **Translation:** Translated all internal code elements (functions, variables, comments, and docstrings) to English, cementing the project's open-source global reach.
* **Dashboard Script:** Created `scripts/dashboard.py` for instant, read-only SQLite database querying using logical mathematical sorting (`CASE` statement for HIGH, MEDIUM, LOW).
* **Export Tool:** Implemented a CSV export function utilizing `datetime.strftime` to generate unique, timestamped files in a 12-hour format (example: logs_`%Y-%m-%d_%I-%M-%S-%p`_ALL.csv).

> **<img width="1023" height="543" alt="Image" src="https://github.com/user-attachments/assets/62ad1127-0fa9-477b-a408-ecb3bba43115" />**

<br>


---
## [v1.3] - Multi-Format Engine & Data Persistence
**Focus:** Log ingestion expansion, strict AI reasoning, and relational database storage.

* **Multi-Format Regex Engine:** Expanded `core/log_reader.py` to ingest web server logs (Nginx/Apache), successfully capturing HTTP 403, HTTP 404, SQL Injections, and directory scanning.
* **SQLite Persistence:** Built `core/database.py` to automatically store all AI-processed logs into a local relational database (`data/secla_logs.db`), moving away from static CSV limitations and preparing for future analytical dashboards.
* **Hierarchical AI Prompting:** Redesigned the `slm_analyzer.py` prompt with a strict 5-rule precedence hierarchy. The `gemma3:4b` model now accurately classifies SQLi, Path Traversal, and separates severities across HIGH, MEDIUM, and LOW (e.g., 404 Not Found) without ambiguity.
* **Web Attack Simulator:** Upgraded `scripts/generator_dummy_logs.py` to synthesize realistic HTTP traffic, including normal 200/404 responses and 403 malicious injections.

> **<img width="1023" height="376" alt="Image" src="https://github.com/user-attachments/assets/384c1d1c-2d11-4392-bdf4-58fc45d2290b" />**

<br>


---
## [v1.2.2] - UI/UX Refinement & PEP 8 Standardization
**Focus:** Visual consistency, readability, and Python coding standards.

* **Multi-Format Regex Engine:** Expansion of `log_reader.py` to detect anomalous web traffic (Nginx/Apache), including patterns such as `403`, `.env`, and SQL injections.
* **Hierarchical AI Prompting:** Implementation of strict precedence rules in `slm_analyzer.py` to eliminate ambiguities in threat classification (deductive zero-shot).
* **UI/UX Refinement:** Dynamically centered main dashboard, color formatting in a separate table for VirusTotal, and addition of a secondary Summary Table.
* **PEP 8 Standardization:** 100% refactoring of the code to `snake_case`.

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
