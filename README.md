<h1 align="center">Security Log Analyzer</h1>


## 📑​| Description
SecLA (Security Log Analyzer) functions as a security log reader that integrates with on-premises AI systems, but without the need to rely on large language models for raw processing. Instead, it combines predefined security rules with lightweight, on-premises SLMs (Small Language Models) for contextual interpretation, enabling fast analysis that preserves privacy since it does not depend on external services. 

<br>

## 💿​| How to Install and Use
Prerequisites: Ensure you have Python3 and Ollama installed and running on your system.
  
1. Clone the repository and setup the environment:

    ```bash
    git clone https://github.com/Macenajp/Security-Log-Analyzer.git 
    cd Security-Log-Analyzer
    python3 -m venv venv

    source venv/bin/activate  # On Linux
    .\venv\Scripts\activate # On Windows

    pip install requests
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


## 📡​| SLM models currently being tested
#### Models:
- 📌​| Phi-4 Mini (3.8B); It averaged approximately 7.5 tokens per second, which is 2 tokens per second more than Gemma and Qwen.
- Gemma 3 (4B)
- Qwen3 (4B)

Metrics Evaluated: Tokens/second (latency), False Positive Rate (FPR), and JSON Structure compliance.

#### Tested hardware configuration:
- Processor: I3-1315U
- RAM: 8 GB, 3200 MHz (single channel)
- Graphics: Intel Raptor Lake-P (UHD Graphics)
