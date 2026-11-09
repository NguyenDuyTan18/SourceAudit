@echo off
if "%~1"=="" (
  node "%~dp0scan.mjs" --help
) else (
  node "%~dp0scan.mjs" %*
)
