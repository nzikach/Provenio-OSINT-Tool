# Сборка Provenio.exe одной командой:   powershell -ExecutionPolicy Bypass -File build.ps1
# Результат: dist\Provenio.exe (один файл, без установки Python).
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# 1. Виртуальное окружение со всем нужным для сборки
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Создаю виртуальное окружение .venv..."
    py -3 -m venv .venv
}
$py = ".venv\Scripts\python.exe"
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r requirements-build.txt

# 2. Проверки перед сборкой
& $py -m unittest discover -s tests -q
if ($LASTEXITCODE -ne 0) { throw "Тесты не прошли — сборка остановлена" }

# 3. Иконка
& $py assets\make_icon.py

# 4. Сборка
& $py -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name Provenio `
    --icon assets\provenio.ico `
    --version-file assets\version_info.txt `
    --add-data "provenio_sites.json;." `
    --exclude-module tkinter `
    --exclude-module unittest `
    --collect-all webview `
    provenio_ui.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller завершился с ошибкой" }

$exe = Get-Item "dist\Provenio.exe"
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
Write-Host ""
Write-Host ("Готово: {0}  ({1:N1} МБ)" -f $exe.FullName, ($exe.Length / 1MB))
Write-Host "SHA-256: $hash"
