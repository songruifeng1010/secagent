#!/usr/bin/env python3
"""
SecAgentX ML 模型重训脚本（生产级）

用法:
    python scripts/retrain_model.py                    # 使用 NSL-KDD 重训 xgboost
    python scripts/retrain_model.py --algo lightgbm   # 指定算法
    python scripts/retrain_model.py --n-samples 20000 # 指定样本数
    python scripts/retrain_model.py --version v3      # 指定版本号

功能:
    1. 加载/生成训练数据
    2. 训练指定算法模型（含超参优化、SMOTE、阈值调优）
    3. 生产级验证：交叉验证 + 混淆矩阵 + 过拟合检测
    4. 带版本号保存模型 + 元数据报告
"""
import os
import sys
import json
import time
import argparse
from datetime import datetime, timezone
import numpy as np

# 项目根目录
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

def detect_overfitting(trainer, X_train, y_train, X_test, y_test) -> dict:
    """过拟合检测：比较训练集与测试集准确率差距。"""
    y_train_pred, _ = trainer.predict(X_train)
    y_test_pred, _ = trainer.predict(X_test)
    from sklearn.metrics import accuracy_score
    train_acc = accuracy_score(y_train, y_train_pred)
    test_acc = accuracy_score(y_test, y_test_pred)
    gap = train_acc - test_acc
    return {
        "train_accuracy": round(train_acc, 4),
        "test_accuracy": round(test_acc, 4),
        "gap": round(gap, 4),
        "overfitting": gap > 0.05,  # 训练-测试差距 >5% 视为过拟合
    }

def main():
    parser = argparse.ArgumentParser(description="SecAgentX ML 模型重训")
    parser.add_argument("--algo", default="xgboost", choices=["xgboost", "lightgbm", "random_forest", "ensemble"])
    parser.add_argument("--n-samples", type=int, default=15000)
    parser.add_argument("--version", default=f"v{datetime.now().strftime('%Y%m%d')}")
    parser.add_argument("--no-save", action="store_true", help="只评估不保存")
    args = parser.parse_args()

    print("=" * 60)
    print(f"  SecAgentX ML 模型重训 | 算法={args.algo} | 版本={args.version}")
    print("=" * 60)

    from backend.ml_model.pipeline import MLPipeline
    from backend.ml_model.trainer import MLTrainer

    # 1. 加载数据
    t0 = time.time()
    print("\n[1/4] 加载训练数据...")
    pipeline = MLPipeline(use_smote=True)
    data = pipeline.run_pipeline(n_samples=args.n_samples)
    print(f"      数据源: {data['info']}")
    print(f"      特征数: {len(pipeline.feature_names)}")

    # 2. 训练
    print(f"\n[2/4] 训练 {args.algo} 模型...")
    trainer = MLTrainer(use_bayes_opt=True, threshold_tuning=True)
    trainer.train(
        data['X_train'], data['y_train'],
        data['X_test'], data['y_test'],
        algorithm=args.algo,
        feature_names=data['feature_names'],
    )
    print(f"      训练完成 | 耗时: {trainer.training_time:.1f}s")

    # 3. 生产级验证
    print(f"\n[3/4] 生产级验证...")
    m = trainer.metrics
    print(f"      准确率: {m.accuracy:.4f}")
    print(f"      精确率: {m.precision:.4f}")
    print(f"      召回率: {m.recall:.4f}")
    print(f"      F1:     {m.f1_score:.4f}")
    print(f"      误报率: {m.false_positive_rate:.4f}")
    print(f"      ROC-AUC: {m.roc_auc:.4f}")
    print(f"      最优阈值: {trainer.threshold:.3f}")

    of = detect_overfitting(trainer, data['X_train'], data['y_train'], data['X_test'], data['y_test'])
    print(f"      过拟合检测: 训练={of['train_accuracy']:.4f} 测试={of['test_accuracy']:.4f} "
          f"差距={of['gap']:.4f} {'⚠️ 有过拟合风险' if of['overfitting'] else '✅ 正常'}")

    if of['overfitting']:
        print("\n⚠️ 警告: 模型存在过拟合，建议降低复杂度或增加数据")
        if args.no_save:
            sys.exit(1)

    # 4. 保存（带版本）
    if args.no_save:
        print("\n[4/4] 评估模式，不保存模型")
        return

    print(f"\n[4/4] 保存模型 (版本: {args.version})...")
    model_path = os.path.join(PROJECT_ROOT, "model", f"threat_model_{args.algo}_{args.version}.joblib")
    trainer.save(model_path, scaler=pipeline.scaler, feature_names=pipeline.feature_names)

    # 生成元数据报告
    report = {
        "version": args.version,
        "algorithm": args.algo,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "data_source": data['info'],
        "n_features": len(pipeline.feature_names),
        "metrics": m.to_dict(),
        "threshold": trainer.threshold,
        "overfitting_check": of,
        "best_params": trainer.best_params,
        "feature_names": pipeline.feature_names,
    }
    report_path = model_path.replace(".joblib", "_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"      ✅ 模型已保存: {model_path}")
    print(f"      ✅ 报告已保存: {report_path}")
    print(f"\n总耗时: {time.time()-t0:.1f}s")

if __name__ == "__main__":
    main()

