# app.py
import streamlit as st
import pandas as pd
import tempfile, os
from parser import parse_file
from rules import run_all_rules
from llm_analyzer import LLMAnalyzer

st.set_page_config(page_title="SecLogInsight", page_icon="🛡️")
st.title("SecLogInsight - 安全日志AI筛查工具")

with st.sidebar:
    st.header("LLM配置")
    api_url = st.text_input("API地址", value="https://open.bigmodel.cn/api/paas/v4/chat/completions")
    api_key = st.text_input("API Key", type="password")
    model = st.text_input("模型名", value="glm-4-flash")
    timeout = st.slider("超时(秒)", 1, 30, 10)
    st.caption("不配置则使用纯规则模式")

uploaded = st.file_uploader("上传日志文件（txt/csv/log）", type=["txt", "csv", "log"])
log_type = st.radio("日志类型", ["ssh", "firewall"])

if uploaded is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as f:
        f.write(uploaded.getvalue())
        tmp_path = f.name
    df = parse_file(tmp_path, log_type)
    os.unlink(tmp_path)

    df = run_all_rules(df)
    analyzer = LLMAnalyzer(api_url, api_key, timeout, model)

    if analyzer.enabled():
        for i, row in df[df["label"] == "suspicious"].iterrows():
            llm_res = analyzer.analyze(row["message"])
            df.at[i, "llm_risk"] = llm_res["risk_level"]
            df.at[i, "llm_reason"] = llm_res["reason"]

    st.subheader(f"共解析 {len(df)} 条日志，其中可疑 {len(df[df['label']=='suspicious'])} 条")
    st.dataframe(df)
    st.download_button("导出CSV报告", df.to_csv(index=False).encode("utf-8-sig"), "report.csv", "text/csv")