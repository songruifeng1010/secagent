"""构建 wheel 时将 Web、知识库和默认配置复制进命名空间资源目录。"""

from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


ROOT = Path(__file__).resolve().parent


class build_py(_build_py):
    def run(self):
        super().run()
        destination = Path(self.build_lib) / "backend" / "_assets"
        # build/ 可能来自上一次构建；先清理命名资源目录，避免已删除的
        # 前端模块或旧哈希静态文件被再次打入 wheel。
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "config.yaml", destination / "config.yaml")
        shutil.copytree(
            ROOT / "knowledge_data",
            destination / "knowledge_data",
            dirs_exist_ok=True,
        )
        frontend = ROOT / "frontend"
        if not (frontend / "dist" / "index.html").is_file():
            raise RuntimeError(
                "frontend/dist 缺失；发布 wheel 前必须先执行 `npm ci && npm run build`"
            )
        shutil.copytree(
            frontend,
            destination / "frontend",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                "node_modules", ".vite", "coverage", ".npm-cache*", ".node-tmp*",
                "playwright-report", "playwright.config.js", "test-results",
                "e2e", "__tests__",
            ),
        )


setup(cmdclass={"build_py": build_py})
