@echo off
setlocal
set "SECAGENTX_ROOT=%~dp0"
if exist "%SECAGENTX_ROOT%.venv\Scripts\python.exe" (
  set "SECAGENTX_PYTHON=%SECAGENTX_ROOT%.venv\Scripts\python.exe"
) else (
  set "SECAGENTX_PYTHON=py -3"
)
pushd "%SECAGENTX_ROOT%"
%SECAGENTX_PYTHON% -m backend %*
set "SECAGENTX_EXIT=%ERRORLEVEL%"
popd
exit /b %SECAGENTX_EXIT%
