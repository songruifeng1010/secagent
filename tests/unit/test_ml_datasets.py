"""ML 多数据集适配器的文件发现与标签标准化测试。"""

from pathlib import Path

import pandas as pd

from backend.ml_model.datasets import get_dataset_adapter, list_dataset_specs


def test_registry_contains_three_datasets():
    assert {spec.name for spec in list_dataset_specs()} == {
        "nsl-kdd", "unsw-nb15", "cic-ids-2018"
    }


def test_nsl_kdd_official_txt_names_are_supported(tmp_path: Path):
    values = ["0", "tcp", "http", "SF"] + ["0"] * 37 + ["normal", "0"]
    row = ",".join(values) + "\n"
    (tmp_path / "KDDTrain+.txt").write_text(row, encoding="utf-8")
    (tmp_path / "KDDTest+.txt").write_text(row, encoding="utf-8")

    train, test, metadata = get_dataset_adapter("nsl-kdd", tmp_path).load_and_validate()
    assert len(train) == len(test) == 1
    assert train.iloc[0]["label"] == "normal"
    assert metadata["train_rows"] == 1


def test_unsw_nb15_normalizes_label_and_drops_id(tmp_path: Path):
    frame = pd.DataFrame({"id": [1], "dur": [0.2], "proto": ["tcp"], "label": [1]})
    frame.to_csv(tmp_path / "UNSW_NB15_training-set.csv", index=False)
    frame.to_csv(tmp_path / "UNSW_NB15_testing-set.csv", index=False)

    train, _, _ = get_dataset_adapter("unsw-nb15", tmp_path).load_and_validate()
    assert "id" not in train.columns
    assert train.iloc[0]["label"] == "attack"


def test_cic_ids_normalizes_benign_label(tmp_path: Path):
    frame = pd.DataFrame({"Flow ID": ["x"], "Timestamp": ["now"], "Bytes": [3], "Label": ["BENIGN"]})
    (tmp_path / "cic_ids_2018").mkdir()
    frame.to_csv(tmp_path / "cic_ids_2018" / "train.csv", index=False)
    frame.to_csv(tmp_path / "cic_ids_2018" / "test.csv", index=False)

    train, _, _ = get_dataset_adapter("cic-ids-2018", tmp_path).load_and_validate()
    assert "Flow ID" not in train.columns
    assert "Timestamp" not in train.columns
    assert train.iloc[0]["label"] == "normal"
