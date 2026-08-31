#!/usr/bin/env python3
"""对模型/Provider 导出的安全预测执行金标准门禁。"""
import argparse
import json
from pathlib import Path

from backend.evaluation.benchmark import evaluate_predictions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("predictions", type=Path, help="预测 JSON 数组文件")
    parser.add_argument("--output", type=Path, help="可选评分报告路径")
    args = parser.parse_args()
    predictions = json.loads(args.predictions.read_text(encoding="utf-8"))
    if not isinstance(predictions, list):
        raise SystemExit("predictions 必须是 JSON 数组")
    report = evaluate_predictions(predictions)
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
