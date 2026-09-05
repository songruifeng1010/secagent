# 训练数据准备

此目录只用于本地训练，数据集不会随 GitHub 源码分发。原因是 CSE-CIC-IDS2018 处理后文件可能超过 2GB，GitHub 单文件限制为 100MB。`.gitignore` 已经阻止 CSV、TXT、模型和 CSE 处理目录被误提交。

每个适配器都要求使用者准备明确的训练/测试文件；不要把不同数据集直接拼接。建议流程如下：

```powershell
# 1. 进入项目根目录并安装可选训练依赖
pip install -r requirements-ml.txt

# 2. 准备 NSL-KDD / UNSW-NB15 官方训练与测试文件，放入本目录
# 3. 如使用 CSE-CIC-IDS2018，先把 AWS S3 的处理后 CSV 下载到 dataset/cic_processed/
aws s3 sync --no-sign-request --region us-east-1 `
  "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/" `
  ".\dataset\cic_processed\" --exclude "*" --include "*.csv"

# 4. 生成 CSE 的可审计训练/测试划分
python scripts/data_pipeline/prepare_cic_ids_2018.py
```

Linux/macOS 的 AWS 命令将反引号换成反斜杠，目标目录改为 `./dataset/cic_processed/`。如果网络或 AWS 下载不可用，可以只准备 NSL-KDD 或 UNSW-NB15，不影响核心对话和告警功能。

目录建议如下：

```text
dataset/
├── KDDTrain+.txt                 # NSL-KDD 训练集
├── KDDTest+.txt                  # NSL-KDD 测试集
├── UNSW_NB15_training-set.csv    # UNSW-NB15 训练集
├── UNSW_NB15_testing-set.csv     # UNSW-NB15 测试集
├── unsw_nb15/                    # 也支持 train.csv / test.csv
├── cic_processed/                # AWS 下载的处理后 CSV
└── cic_ids_2018/                 # 脚本生成的可训练划分
    ├── train.csv
    ├── test.csv
    └── manifest.json
```

NSL-KDD 官方文件通常使用以下命名：

- `KDDTrain+.txt`：官方训练集
- `KDDTest+.txt`：官方测试集

将文件原样放入此目录即可；SecAgentX 会自动识别官方 `.txt` 命名，也兼容重命名后的 `KDDTrain.csv` / `KDDTest.csv`。它会严格按这两个官方划分训练与评估：只在训练集拟合特征缩放器和 SMOTE，测试集只用于最终评估。缺少任一文件时，训练脚本会直接失败，不会生成合成数据或使用测试集反向训练。

UNSW-NB15 适配器会自动去除 `id` 和 `attack_cat`，CSE-CIC-IDS2018 会去除时间戳/Flow ID 等高基数标识，避免标签或编号泄漏。CSE-CIC-IDS2018 原始数据通常按日期和场景分文件，先运行以下命令按日期整理（最新 3 天作为测试集），适配器不会自行随机切分：

```bash
python scripts/data_pipeline/prepare_cic_ids_2018.py
```

脚本会生成 `dataset/cic_ids_2018/manifest.json`，记录输入文件、日期划分、行数和标签分布。
当前机器内存不足以一次性读取全部 CSE 数据时，可在训练命令中显式限制每个划分的读取行数，例如 `--max-rows 1000000`；报告会记录这是受限样本训练，不能当作全量结果。

准备完成后，在项目根目录执行：

```bash
pip install -r requirements-ml.txt
python scripts/retrain_model.py --algo xgboost --version v1

# 其他数据集
python scripts/retrain_model.py --dataset unsw-nb15 --algo xgboost --version v1
python scripts/retrain_model.py --dataset cic-ids-2018 --algo xgboost --version v1
```

模型和评估报告会写入 `model/`；请在部署前审阅报告中的数据源、测试指标和过拟合检查结果。

训练生成的 `.joblib` 和 `_report.json` 只保留在本机。发布代码时只提交本说明和 `manifest.json`，不要使用 `git add -f` 强行加入数据或模型文件。
