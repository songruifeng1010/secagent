param(
    [string]$Wheelhouse = ".\wheelhouse"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
    throw "未找到 pipx。请先安装 pipx，或使用 .venv\Scripts\python.exe -m pip install --no-index --find-links=wheelhouse secagentx。"
}

$resolvedWheelhouse = (Resolve-Path -LiteralPath $Wheelhouse).Path
$wheels = @(Get-ChildItem -LiteralPath $resolvedWheelhouse -Filter "secagentx-*.whl" -File)
if ($wheels.Count -ne 1) {
    throw "wheelhouse 必须包含且仅包含一个 SecAgentX wheel；请选择对应版本。"
}
$wheel = $wheels[0]

Write-Host "使用离线包安装 $($wheel.Name) ..." -ForegroundColor Cyan
$oldNoIndex = $env:PIP_NO_INDEX
$oldFindLinks = $env:PIP_FIND_LINKS
try {
    $env:PIP_NO_INDEX = "1"
    $env:PIP_FIND_LINKS = ([System.Uri]($resolvedWheelhouse + [IO.Path]::DirectorySeparatorChar)).AbsoluteUri
    pipx install --pip-args "--no-index" $wheel.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "离线安装失败（退出码 $LASTEXITCODE），请检查 wheelhouse 是否包含当前系统及 Python 版本的全部依赖。"
    }
} finally {
    $env:PIP_NO_INDEX = $oldNoIndex
    $env:PIP_FIND_LINKS = $oldFindLinks
}
Write-Host "安装完成。运行：secagentx chat" -ForegroundColor Green
