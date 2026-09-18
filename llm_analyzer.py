# llm_analyzer.py
import json
import requests

PROMPT_TEMPLATE = """你是一名网络安全分析师。请分析下面的安全日志，只输出严格的JSON格式：
{"risk_level": "low|medium|high", "risk_type": "类型", "reason": "一句话理由", "suggest": "建议"}
不要输出其他内容。

日志：
{log}"""

class LLMAnalyzer:
    def __init__(self, api_url="", api_key="", timeout=10, model="glm-4-flash"):
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout
        self.model = model

    def enabled(self):
        return bool(self.api_url and self.api_key)

    def analyze(self, log_text):
        """返回结构化结果；任何失败都自动降级，不崩"""
        if not self.enabled():
            return {"risk_level": "low", "risk_type": "规则模式",
                    "reason": "未配置LLM，仅规则检测", "suggest": "配置API后启用AI分析"}
        try:
            resp = requests.post(
                self.api_url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json={"model": self.model,
                      "messages": [{"role": "user", "content": PROMPT_TEMPLATE.replace("{log}", log_text)}]},
                timeout=self.timeout,
            )
            content = resp.json()["choices"][0]["message"]["content"]
            return self._parse(content)
        except requests.exceptions.Timeout:
            return {"risk_level": "medium", "risk_type": "超时降级",
                    "reason": "LLM请求超时，已降级为规则结果", "suggest": "检查网络或缩短日志"}
        except Exception as e:
            return {"risk_level": "low", "risk_type": "错误降级",
                    "reason": f"LLM异常：{str(e)[:50]}", "suggest": "检查API配置"}

    def _parse(self, content):
        """容错解析模型输出JSON（处理非法JSON）"""
        try:
            return json.loads(content)
        except Exception:
            pass
        try:
            start, end = content.index("{"), content.rindex("}") + 1
            return json.loads(content[start:end])
        except Exception:
            return {"risk_level": "low", "risk_type": "解析失败",
                    "reason": "模型输出非合法JSON", "suggest": "重试"}

if __name__ == "__main__":
    a = LLMAnalyzer()
    print(a.analyze("Mar 5 10:15:30 sshd: Failed password for root from 203.0.113.7"))