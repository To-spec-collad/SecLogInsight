# robustness_test.py
from llm_analyzer import LLMAnalyzer
from unittest.mock import patch
import requests

# ① 无LLM模式降级
a = LLMAnalyzer()
r = a.analyze("Mar 5 test log")
print("① 无LLM模式:", r["risk_type"], "->", r["reason"])

# ② 非法JSON容错（直接测_parse）
a2 = LLMAnalyzer("http://example.com", "fake_key")
r2 = a2._parse("这不是JSON{{{乱七八糟")
print("② 非法JSON降级:", r2["risk_type"])

# ③ 合法JSON正常解析
r3 = a2._parse('{"risk_level": "high", "risk_type": "暴力破解", "reason": "多次失败"}')
print("③ 合法JSON解析:", r3["risk_level"])

# ④ 超时降级（模拟网络超时）
with patch("requests.post", side_effect=requests.exceptions.Timeout()):
    r4 = a2.analyze("Mar 5 test log")
    print("④ 超时降级:", r4["risk_type"])

# ⑤ 网络异常降级（模拟断网）
with patch("requests.post", side_effect=Exception("network down")):
    r5 = a2.analyze("Mar 5 test log")
    print("⑤ 网络异常降级:", r5["risk_type"], "->", r5["reason"][:40])