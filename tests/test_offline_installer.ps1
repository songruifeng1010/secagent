# 离线安装脚本的故障注入测试：用函数替代 pipx，不执行安装或网络请求。
$ErrorActionPreference = 'Stop'
$folder = Join-Path ([IO.Path]::GetTempPath()) ('secagentx wheels ' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $folder > $null
New-Item -ItemType File -Path (Join-Path $folder 'secagentx-4.0.0-py3-none-any.whl') > $null
$global:secagentOfflineTestExit = 7
$global:secagentOfflineTestArgs = @()
function pipx {
    $global:secagentOfflineTestArgs = $args
    if ($env:PIP_NO_INDEX -ne '1') { throw 'Network must be disabled' }
    if ($env:PIP_FIND_LINKS -notmatch '^file:') { throw 'Expected file URI' }
    $global:LASTEXITCODE = $global:secagentOfflineTestExit
}
$beforeNoIndex = $env:PIP_NO_INDEX
$beforeFindLinks = $env:PIP_FIND_LINKS
$installer = Join-Path $PSScriptRoot '../scripts/install_offline.ps1'
try {
    $failed = $false
    try { & $installer -Wheelhouse $folder } catch {
        if ($_.Exception.Message -notmatch '7') { throw }
        $failed = $true
    }
    if (-not $failed) { throw 'Failure was reported as success' }
    $global:secagentOfflineTestExit = 0
    & $installer -Wheelhouse $folder
    if ($global:secagentOfflineTestArgs -contains '--force') { throw 'Unexpected force install' }
    if ($global:secagentOfflineTestArgs[-1] -ne (Join-Path $folder 'secagentx-4.0.0-py3-none-any.whl')) {
        throw 'Path with spaces was split'
    }
    if ($env:PIP_NO_INDEX -ne $beforeNoIndex -or $env:PIP_FIND_LINKS -ne $beforeFindLinks) {
        throw 'Installer changed caller environment'
    }
    Write-Output 'Offline installer: failure, success, spaces and environment restoration passed'
} finally {
    # 只删除本次创建的两个确切路径，不递归操作。
    Remove-Item -LiteralPath (Join-Path $folder 'secagentx-4.0.0-py3-none-any.whl')
    Remove-Item -LiteralPath $folder
}
