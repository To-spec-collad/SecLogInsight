# SecLogInsight

AI-assisted screening of SSH security logs with rule-based and LLM analysis.

SecLogInsight is a lightweight tool for screening OpenSSH authentication logs. It parses raw log lines into structured events, applies a rule-based engine to flag suspicious events, and optionally calls a large language model (LLM) to review borderline cases, aiming to reduce alert fatigue and missed detections.

## Features

- Rule-based screening of OpenSSH auth logs (parser + rules)
- Optional LLM review (default: ZhipuAI GLM-4-Flash) for uncertain events
- Graceful degradation: rule-only mode when the LLM is missing or unreachable
- Web interface (app.py) and command-line evaluation scripts

## Installation

pip install -r requirements.txt

## Configuration

Set your API key as an environment variable (never hard-code it in source):

Windows (PowerShell): $env:ZHIPU_API_KEY = "your-key"
Linux/macOS: export ZHIPU_API_KEY="your-key"

The LLM module is optional: without a key, the tool runs in rule-only mode.

## Usage

python app.py          # web interface
python evaluate_tool_llm.py   # evaluation on labeled sample

## Experimental results

On a 100-line labeled sample of OpenSSH logs:

| Mode | Precision | Recall | F1 |
| --- | --- | --- | --- |
| Rule-only | 1.000 | 0.800 | 0.889 |
| Rule + LLM | 0.857 | 0.900 | 0.878 |

## License

MIT
