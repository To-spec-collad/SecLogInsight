# prepare_experiment.py
import random
import pandas as pd

random.seed(42)   # 固定随机种子，保证可复现

# 1. 读真实攻击日志（OpenSSH_2k.log 本身就是攻击流量数据集）
with open("data/OpenSSH_2k.log", "r", encoding="utf-8", errors="ignore") as f:
    attack_lines = [l.strip() for l in f if l.strip()]

# 2. 抽样40条攻击样本
attacks = random.sample(attack_lines, 40)

# 3. 生成60条正常登录日志（白天工作时间、内网IP、合法用户名）
users = ["alice", "bob", "carol", "dave", "erin", "frank"]
ips = [f"192.168.1.{i}" for i in range(10, 50)]
normal_lines = []
for i in range(60):
    user = random.choice(users)
    ip = random.choice(ips)
    month = random.choice(["Sep", "Oct", "Nov"])
    day = random.randint(1, 28)
    hh = random.randint(8, 19)          # 工作时间
    mm, ss = random.randint(0, 59), random.randint(0, 59)
    port = random.randint(40000, 60000)
    normal_lines.append(
        f"{month} {day:2d} {hh:02d}:{mm:02d}:{ss:02d} LabSZ sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for {user} from {ip} port {port} ssh2"
    )

# 4. 混合并打乱顺序
all_data = [(l, 1) for l in attacks] + [(l, 0) for l in normal_lines]
random.shuffle(all_data)

# 5. 输出实验集 + 金标准
with open("data/experiment_set.log", "w", encoding="utf-8") as f:
    for l, _ in all_data:
        f.write(l + "\n")

gold = pd.DataFrame({"idx": range(len(all_data)),
                     "gold_label": [g for _, g in all_data]})  # 1=攻击, 0=正常
gold.to_csv("data/gold_standard.csv", index=False)

print(f"总样本: {len(all_data)}  攻击: {len(attacks)}  正常: {len(normal_lines)}")
print("已生成: data/experiment_set.log + data/gold_standard.csv")