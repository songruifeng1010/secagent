#!/usr/bin/env python3
"""将 CSE-CIC-IDS2018 处理后 CSV 整理为可审计的 train/test 文件。

默认按文件日期排序，将最新 3 个日期作为测试集，其余日期作为训练集。
使用 pandas 分块读取，不会把全部数据一次性加载到内存，也不会随机切分。
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


DATE_RE = re.compile(r"(\d{2})-(\d{2})-(\d{4})")
BENIGN = {"benign", "normal", "0", "normal traffic"}


def file_date(path: Path) -> datetime:
    match = DATE_RE.search(path.name)
    if not match:
        raise ValueError(f"无法从文件名识别日期: {path.name}")
    day, month, year = match.groups()
    return datetime(int(year), int(month), int(day))


def normalize_chunk(chunk: pd.DataFrame) -> tuple[pd.DataFrame, str]:
    chunk.columns = [str(column).strip() for column in chunk.columns]
    label_col = next((c for c in chunk.columns if c.lower() == "label"), None)
    if label_col is None:
        raise ValueError("CSE-CIC-IDS2018 文件缺少 Label 列")
    drop = []
    for column in chunk.columns:
        key = column.lower().replace(" ", "")
        if key in {"timestamp", "flowid", "unnamed:0"}:
            drop.append(column)
    chunk = chunk.drop(columns=drop, errors="ignore")
    chunk = chunk.rename(columns={label_col: "label"})
    chunk["label"] = chunk["label"].astype(str).str.strip().str.lower().map(
        lambda value: "normal" if value in BENIGN else "attack"
    )
    return chunk, label_col


def append_file(source: Path, target: Path, chunksize: int) -> tuple[int, Counter, list[str]]:
    rows = 0
    labels: Counter = Counter()
    dropped_columns: list[str] = []
    first = not target.exists()
    for chunk in pd.read_csv(source, chunksize=chunksize, low_memory=False, on_bad_lines="skip"):
        chunk, label_col = normalize_chunk(chunk)
        dropped_columns.extend(
            column for column in ("Timestamp", "Flow ID", "Unnamed: 0") if column not in chunk.columns
        )
        labels.update(chunk["label"].value_counts().to_dict())
        chunk.to_csv(target, mode="w" if first else "a", header=first, index=False)
        first = False
        rows += len(chunk)
    return rows, labels, sorted(set(dropped_columns))


def main() -> int:
    parser = argparse.ArgumentParser(description="整理 CSE-CIC-IDS2018 处理后 CSV")
    parser.add_argument("--source", default="dataset/cic_processed")
    parser.add_argument("--output", default="dataset/cic_ids_2018")
    parser.add_argument("--test-days", type=int, default=3,
                        help="按日期排序后保留多少个最新日期作为测试集，默认 3")
    parser.add_argument("--chunksize", type=int, default=50000)
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    source = (project_root / args.source).resolve()
    output = (project_root / args.output).resolve()
    files = sorted(source.glob("*.csv"), key=file_date)
    if len(files) < 2:
        raise SystemExit(f"至少需要 2 个 CSE CSV 文件，当前找到 {len(files)} 个: {source}")
    dates = sorted({file_date(path).date() for path in files})
    if args.test_days < 1 or args.test_days >= len(dates):
        raise SystemExit(f"--test-days 必须在 1 到 {len(dates) - 1} 之间")
    test_dates = set(dates[-args.test_days:])
    train_files = [path for path in files if file_date(path).date() not in test_dates]
    test_files = [path for path in files if file_date(path).date() in test_dates]

    output.mkdir(parents=True, exist_ok=True)
    train_path, test_path = output / "train.csv", output / "test.csv"
    for path in (train_path, test_path):
        if path.exists():
            path.unlink()

    summary = {
        "dataset": "cic-ids-2018",
        "split_strategy": "chronological_file_split",
        "test_days": [date.isoformat() for date in sorted(test_dates)],
        "train_files": [path.name for path in train_files],
        "test_files": [path.name for path in test_files],
        "train_rows": 0,
        "test_rows": 0,
        "label_counts": {"train": {}, "test": {}},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    for split, paths, target in (("train", train_files, train_path), ("test", test_files, test_path)):
        counts = Counter()
        dropped: set[str] = set()
        for index, path in enumerate(paths, 1):
            print(f"[{split} {index}/{len(paths)}] {path.name}")
            rows, labels, removed = append_file(path, target, args.chunksize)
            summary[f"{split}_rows"] += rows
            counts.update(labels)
            dropped.update(removed)
            print(f"  rows={rows:,} labels={dict(labels)}")
        summary["label_counts"][split] = dict(counts)
        summary.setdefault("dropped_columns", {})[split] = sorted(dropped)

    (output / "manifest.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
