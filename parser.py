# parser.py
import re
import pandas as pd

SCHEMA = ["timestamp", "src_ip", "dst_ip", "port", "protocol", "action", "user", "message", "label"]

# 动作关键词（按优先级排列）
ACTIONS = ["Accepted", "Failed password", "authentication failure", "Connection closed",
           "Connection refused", "Invalid user", "session opened", "break-in", "Failed"]

def parse_ssh_line(line: str) -> dict:
    """解析单行SSH日志（auth.log / syslog格式）"""
    rec = {k: "" for k in SCHEMA}
    rec["protocol"] = "SSH"
    rec["message"] = line.strip()
    # 时间戳：Dec 10 07:11:42
    m = re.search(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if m:
        rec["timestamp"] = m.group(1)
    # 动作：优先匹配完整短语
    for act in ACTIONS:
        if act.lower() in line.lower():
            rec["action"] = act
            break
    # 用户名：优先 user=xxx（pam格式）→ for invalid user xxx → for xxx from
    m = re.search(r"user=(\S+)", line)
    if m:
        rec["user"] = m.group(1)
    else:
        m = re.search(r"for invalid user (\S+)", line)
        if m:
            rec["user"] = m.group(1)
        else:
            m = re.search(r"for (\S+) from", line)
            if m:
                rec["user"] = m.group(1)
    # 源IP：优先 rhost=xxx → from x.x.x.x → 任意IP
    m = re.search(r"rhost=(\S+)", line)
    if m:
        rec["src_ip"] = m.group(1)
    else:
        m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
        if m:
            rec["src_ip"] = m.group(1)
        else:
            ips = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", line)
            if ips:
                rec["src_ip"] = ips[0]
    return rec

def parse_firewall_line(line: str) -> dict:
    """解析单行防火墙日志（示例格式：proto=... src=... dst=... dport=... action=...）"""
    rec = {k: "" for k in SCHEMA}
    rec["protocol"] = "FW"
    rec["message"] = line.strip()
    for key, tag in [("protocol", "proto="), ("src_ip", "src="), ("dst_ip", "dst="),
                     ("port", "dport="), ("action", "action=")]:
        m = re.search(re.escape(tag) + r"(\S+)", line)
        if m:
            rec[key] = m.group(1)
    return rec

def parse_file(path: str, log_type: str = "ssh") -> pd.DataFrame:
    """解析整个日志文件为统一schema的DataFrame"""
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = parse_ssh_line(line) if log_type == "ssh" else parse_firewall_line(line)
            rows.append(rec)
    return pd.DataFrame(rows, columns=SCHEMA)

if __name__ == "__main__":
    demo_lines = [
        "Dec 10 06:55:30 LabSZ sshd[24240]: Failed password for invalid user root from 202.100.179.208 port 56138 ssh2",
        "Dec 10 06:54:47 LabSZ sshd[24240]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=202.100.179.208  user=root",
        "Dec 10 06:55:32 LabSZ sshd[24240]: Connection closed by 202.100.179.208 [preauth]",
        "Dec 10 08:00:01 LabSZ sshd[5678]: Accepted password for alice from 192.168.1.10 port 50001 ssh2",
    ]
    df = pd.DataFrame([parse_ssh_line(l) for l in demo_lines])
    print(df[["timestamp", "src_ip", "action", "user"]].to_string(index=False))