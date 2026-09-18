# SecLogInsight

AI-assisted screening of SSH security logs with rule-based and LLM analysis.

SecLogInsight is a lightweight tool for screening OpenSSH authentication logs. It
parses raw log lines into structured events, applies a rule-based engine to flag
suspicious events, and optionally calls a large language model (LLM) to review
borderline cases, aiming to reduce alert fatigue and missed detections.

## Features

- Rule-based screening of OpenSSH auth logs (parser + rules)
- Optional LLM review (default: ZhipuAI GLM-4-Flash) for uncertain events
- Graceful degradation: rule-only mode when the LLM is missing or unreachable
- Web interface (app.py) and command-line evaluation scripts

## Installation

```bash
pip install -r requirements.txt
