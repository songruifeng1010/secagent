"""Core installations must expose ML metadata without the optional training stack."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class OptionalMLTests(unittest.TestCase):
    def test_metadata_and_api_without_training_dependencies(self):
        root = Path(__file__).resolve().parents[2]
        code = r'''
import importlib.abc
import sys
class BlockML(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'pandas', 'sklearn', 'imblearn', 'joblib', 'xgboost', 'lightgbm'}:
            raise ModuleNotFoundError(fullname)
sys.meta_path.insert(0, BlockML())
from backend.ml_model import scan_model_artifacts
from backend.ml_model.datasets import list_dataset_specs
assert len(list_dataset_specs()) == 3
assert len(scan_model_artifacts('nonexistent-model-directory')) == 3
assert 'backend.ml_model.trainer' not in sys.modules
assert 'backend.ml_model.pipeline' not in sys.modules
import os
import tempfile
from pathlib import Path
with tempfile.TemporaryDirectory() as folder:
    db = str(Path(folder) / 'core.db')
    os.environ.update({
        'SECAGENTX_HOME': folder,
        'SECAGENTX_ACTIVE_PROVIDER': 'mock',
        'SECAGENTX_LLM_API_BASE': 'mock://local',
        'SECAGENTX_LLM_MODEL': 'mock-llm',
        'SECAGENTX_LLM_ALLOW_NO_KEY': 'true',
        'LLM_PROVIDER': 'mock', 'FIREWALL_BACKEND': 'mock',
        'SECAGENTX_DB_PATH': db, 'DATABASE_URL': 'sqlite:///' + db,
        'SECAGENTX_CLI_QUIET': '1',
    })
    from fastapi.testclient import TestClient
    from backend.interface.api_server import create_app
    with TestClient(create_app(), raise_server_exceptions=False) as client:
        for url in ('/api/ml/status', '/api/ml/models', '/api/ml/datasets'):
            response = client.get(url)
            assert response.status_code == 200, (url, response.status_code)
        status = client.get('/api/ml/status').json()
        assert status['available'] is False
        assert status['loaded'] is False
        assert len(client.get('/api/ml/datasets').json()['datasets']) == 3
'''
        env = dict(os.environ, PYTHONPATH=str(root))
        result = subprocess.run([sys.executable, '-c', code], cwd=root,
                                env=env, capture_output=True, text=True, timeout=50)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
