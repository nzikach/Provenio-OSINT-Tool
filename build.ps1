# Сборка Provenio.exe одной командой:   powershell -ExecutionPolicy Bypass -File build.ps1
# Результат: dist\Provenio.exe (один файл, без установки Python).
# -SourceBootloader: собрать загрузчик PyInstaller из исходников (нужен MSVC — есть в GitHub Actions).
# Стандартный загрузчик одинаков у всех PyInstaller-программ, включая вредоносные, поэтому
# часть антивирусов ложно срабатывает на него. Собственный загрузчик убирает эти срабатывания.
param([switch]$SourceBootloader)
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
if ($SourceBootloader) {
    Write-Host "Собираю загрузчик PyInstaller из исходников..."
    $env:PYINSTALLER_COMPILE_BOOTLOADER = "1"
    & $py -m pip install --force-reinstall --no-deps --no-binary pyinstaller --no-cache-dir "pyinstaller>=6.10"
    if ($LASTEXITCODE -ne 0) { throw "Не удалось собрать загрузчик PyInstaller" }
}

# 2. Проверки перед сборкой
& $py -m unittest discover -s tests -q
if ($LASTEXITCODE -ne 0) { throw "Тесты не прошли — сборка остановлена" }

# 3. Иконка
& $py assets\make_icon.py

# 4. Сборка
& $py -m PyInstaller --noconfirm --clean --onefile --windowed --noupx `
    --name Provenio `
    --icon assets\provenio.ico `
    --version-file assets\version_info.txt `
    --add-data "provenio_sites.json;." `
    --add-data "assets\world-110m.json;assets" `
    --add-data "legal;legal" `
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
