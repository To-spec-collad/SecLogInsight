# rules.py
import pandas as pd
from collections import Counter

# 规则1参数：同一源IP失败N次 → 暴力破解
BRUTE_FORCE_THRESHOLD = 5
SENSITIVE_USERS = {"root", "admin", "administrator", "oracle", "postgres"}
WORK_START, WORK_END = 6, 22
# 规则4：高危动作，出现即命中（单次攻击也不漏）
HIGH_RISK_ACTIONS = {"failed password", "invalid user", "authentication failure",
                     "break-in", "connection refused"}

def extract_hour(ts: str) -> int:
    try:
        return int(ts.split()[2].split(":")[0])
    except Exception:
        return -1

def detect_high_risk_action(df: pd.DataFrame) -> pd.DataFrame:
    """规则4：高危动作直接命中"""
    out = df.copy()
    out["rule_high_action"] = out["action"].str.lower().isin(HIGH_RISK_ACTIONS)
    return out

def detect_failed_login(df: pd.DataFrame) -> pd.DataFrame:
    """规则1：暴力破解——同源IP失败次数>=阈值"""
    out = df.copy()
    out["rule_brute"] = False
    cnt = Counter(out.loc[out["action"] == "Failed password", "src_ip"])
    for ip, n in cnt.items():
        if n >= BRUTE_FORCE_THRESHOLD:
            out.loc[out["src_ip"] == ip, "rule_brute"] = True
    return out

def detect_sensitive_user(df: pd.DataFrame) -> pd.DataFrame:
    """规则2：敏感用户名"""
    out = df.copy()
    out["rule_sensitive_user"] = out["user"].isin(SENSITIVE_USERS)
    return out

def detect_off_hours(df: pd.DataFrame) -> pd.DataFrame:
    """规则3：非工作时间登录"""
    out = df.copy()
    out["hour"] = out["timestamp"].apply(extract_hour)
    out["rule_off_hour"] = ~out["hour"].between(WORK_START, WORK_END)
    return out

def run_all_rules(df: pd.DataFrame) -> pd.DataFrame:
    """执行全部规则，汇总风险标签"""
    out = df.copy()
    out = detect_high_risk_action(out)
    out = detect_failed_login(out)
    out = detect_sensitive_user(out)
    out = detect_off_hours(out)
    out["label"] = "normal"
    hit = out["rule_high_action"] | out["rule_brute"] | out["rule_sensitive_user"] | out["rule_off_hour"]
    out.loc[hit, "label"] = "suspicious"
    out["hit_rules"] = (out["rule_high_action"].astype(int) + out["rule_brute"].astype(int)
                        + out["rule_sensitive_user"].astype(int) + out["rule_off_hour"].astype(int))
    return out