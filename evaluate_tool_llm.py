# evaluate_tool_llm.py（内联LLM版，不依赖llm_analyzer.py）
import time
import json
import requests
import pandas as pd
from parser import parse_file
from rules import run_all_rules

API_URL = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
API_KEY = "25a86012863849a08117afc16c25a3f1.utxHfpxNMHYRZ0JS"   # ← 替换成你的key
MODEL = "glm-4-flash"

PROMPT_TEMPLATE = """你是一名网络安全分析师。请分析下面的安全日志，只输出严格的JSON格式：
{"risk_level": "low|medium|high", "risk_type": "类型", "reason": "一句话理由", "suggest": "建议"}
不要输出其他内容。

日志：
{log}"""

def llm_judge(log_text):
    """直接调用智谱，返回risk_level"""
    try:
        resp = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
            json={"model": MODEL,
                  "messages": [{"role": "user", "content": PROMPT_TEMPLATE.replace("{log}", log_text)}]},
            timeout=30,
        )
        content = resp.json()["choices"][0]["message"]["content"]
        try:
            data = json.loads(content)
        except Exception:
            start, end = content.index("{"), content.rindex("}") + 1
            data = json.loads(content[start:end])
        return data.get("risk_level", "low")
    except Exception as e:
        print("LLM请求失败:", str(e)[:100])
        return "low"

df = parse_file("data/experiment_set.log", "ssh")
df = run_all_rules(df)
gold = pd.read_csv("data/gold_standard.csv")["gold_label"]
pred = df["label"].map({"suspicious": 1, "normal": 0}).copy()

t0 = time.time()
llm_promoted = 0
# 规则判normal的交给LLM复核（补漏报）
for i, row in df.iterrows():
    if pred[i] == 1:
        continue
    rl = llm_judge(row["message"])
    if rl in ("medium", "high"):
        pred[i] = 1
        llm_promoted += 1
elapsed = time.time() - t0

tp = ((pred == 1) & (gold == 1)).sum()
fp = ((pred == 1) & (gold == 0)).sum()
fn = ((pred == 0) & (gold == 1)).sum()
tn = ((pred == 0) & (gold == 0)).sum()
precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0
fpr = fp / (fp + tn) if fp + tn else 0
f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0

print(f"总耗时: {elapsed:.3f} 秒（含LLM请求）")
print(f"LLM补召回: {llm_promoted} 条")
print(f"混淆矩阵: TP={tp} FP={fp} FN={fn} TN={tn}")
print(f"Precision={precision:.3f}  Recall={recall:.3f}  FPR={fpr:.3f}  F1={f1:.3f}")
# ---- 误报分析 ----
fp_rows = df.loc[(pred == 1) & (gold == 0)]
print(f"\n误报样本（{len(fp_rows)}条）：")
for msg in fp_rows["message"].head(10):
    print("  ", msg)

# ---- 漏报分析 ----
fn_rows = df.loc[(pred == 0) & (gold == 1)]
print(f"\n漏报样本（{len(fn_rows)}条）：")
for msg in fn_rows["message"].head(10):
    print("  ", msg)