@echo off
REM SPDX-FileCopyrightText: 2026 Virantis
REM SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
REM
REM Vooda installer / updater for Windows.
REM   install.bat                 Interactive menu
REM   install.bat install --prod  Production mode  (http://localhost:3000)
REM   install.bat install --dev   Development mode (http://localhost:3001, hot reload)
REM   install.bat update          Pull latest + rebuild, preserving ALL data
REM   install.bat check           Check dependencies only
REM   install.bat --help
setlocal enabledelayedexpansion
cd /d "%~dp0"

if not exist "docker-compose.yml" (
  echo [X] Run this from the Vooda repo root ^(docker-compose.yml not found^).
  exit /b 1
)

set "CMD=%~1"
set "OPT=%~2"

if /i "%CMD%"==""       goto menu
if /i "%CMD%"=="menu"   goto menu
if /i "%CMD%"=="-h"     goto usage
if /i "%CMD%"=="--help" goto usage
if /i "%CMD%"=="help"   goto usage
if /i "%CMD%"=="check"  ( call :check_deps & exit /b !errorlevel! )
if /i "%CMD%"=="update" goto do_update
if /i "%CMD%"=="install" (
  if /i "%OPT%"=="--prod" ( set "MODE=prod" & goto do_install )
  if /i "%OPT%"=="prod"   ( set "MODE=prod" & goto do_install )
  if /i "%OPT%"=="--dev"  ( set "MODE=dev"  & goto do_install )
  if /i "%OPT%"=="dev"    ( set "MODE=dev"  & goto do_install )
  set /p M="prod or dev? [prod/dev]: "
  if /i "!M!"=="dev" ( set "MODE=dev" ) else ( set "MODE=prod" )
  goto do_install
)
goto usage

:menu
echo.
echo Vooda installer
echo   1^) Install - production  ^(real build, http://localhost:3000^)
echo   2^) Install - development ^(next dev + hot reload, http://localhost:3001^)
echo   3^) Update  - pull latest + rebuild, keep all data
echo   4^) Check dependencies only
echo   5^) Quit
set /p CHOICE="Choose [1-5]: "
if "%CHOICE%"=="1" ( set "MODE=prod" & goto do_install )
if "%CHOICE%"=="2" ( set "MODE=dev"  & goto do_install )
if "%CHOICE%"=="3" goto do_update
if "%CHOICE%"=="4" ( call :check_deps & goto :eof )
goto :eof

:check_deps
echo [*] Checking dependencies...
where docker >nul 2>&1
if errorlevel 1 ( echo [X] docker not found - install Docker Desktop: https://docs.docker.com/get-docker/ & exit /b 1 )
docker compose version >nul 2>&1
if errorlevel 1 ( echo [X] Docker Compose v2 not found - update Docker Desktop. & exit /b 1 )
docker info >nul 2>&1
if errorlevel 1 ( echo [X] Docker daemon not running - start Docker Desktop and re-run. & exit /b 1 )
where git >nul 2>&1
if errorlevel 1 ( echo [!] git not found - required for 'update', not for a first install. )
echo [OK] docker + compose present
exit /b 0

:setup_env
REM Create .env, generate POSTGRES_PASSWORD/SECRET_KEY if empty, set host URLs (uses %MODE%).
powershell -NoProfile -ExecutionPolicy Bypass -Command "$m='%MODE%'; $f='.env'; if(-not(Test-Path $f)){Copy-Item '.env.example' $f; Write-Host '[OK] Created .env from .env.example'}; $c=Get-Content $f -Raw; function G($k){if($c -match ('(?m)^'+[regex]::Escape($k)+'=(.*)$')){$Matches[1]}else{''}}; function S($k,$v){if($c -match ('(?m)^'+[regex]::Escape($k)+'=.*$')){$script:c=[regex]::Replace($c,('(?m)^'+[regex]::Escape($k)+'=.*$'),($k+'='+$v))}else{$script:c=$c.TrimEnd()+[Environment]::NewLine+$k+'='+$v}}; if(-not(G 'POSTGRES_PASSWORD')){$b=New-Object byte[] 32;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);S 'POSTGRES_PASSWORD' ([Convert]::ToBase64String($b));Write-Host '[OK] Generated POSTGRES_PASSWORD'}; if(-not(G 'SECRET_KEY')){$b=New-Object byte[] 32;[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b);S 'SECRET_KEY' (($b|ForEach-Object{$_.ToString('x2')}) -join '');Write-Host '[OK] Generated SECRET_KEY'}; if($m -eq 'dev'){$w='3001';$a='8001'}else{$w='3000';$a='8000'}; S 'WEB_BASE_URL' ('http://localhost:'+$w); S 'CORS_ORIGINS' ('http://localhost:'+$w); S 'OAUTH_REDIRECT_BASE' ('http://localhost:'+$a+'/api/v1/integrations/oauth'); Set-Content -NoNewline -Path $f -Value $c"
exit /b 0

:do_install
call :check_deps
if errorlevel 1 exit /b 1
call :setup_env
if /i "%MODE%"=="dev" (
  copy /y "docker-compose.override.example.yml" "docker-compose.override.yml" >nul
) else (
  copy /y "docker-compose.override.prod.example.yml" "docker-compose.override.yml" >nul
)
echo [OK] Selected %MODE% mode
echo [*] Building and starting the stack ^(first run can take a few minutes^)...
docker compose up -d --build
if errorlevel 1 ( echo [X] docker compose up failed - see output above. & exit /b 1 )
call :wait_healthy
echo [*] Seeding the default org + admin account...
docker compose exec -T api python -m infra.scripts.seed
call :print_access
goto :eof

:do_update
call :check_deps
if errorlevel 1 exit /b 1
where git >nul 2>&1
if errorlevel 1 ( echo [X] git is required for update. & exit /b 1 )
if not exist ".git" ( echo [X] Not a git checkout - pull manually. Your data is untouched. & exit /b 1 )
echo [*] Updating the repo ^(your .env and override are git-ignored and preserved^)...
git pull --ff-only
if errorlevel 1 ( echo [X] git pull failed - resolve manually and re-run. Your data is untouched. & exit /b 1 )
findstr /c:"3001:3000" "docker-compose.override.yml" >nul 2>&1 && ( set "MODE=dev" ) || ( set "MODE=prod" )
call :backup_db
echo [*] Rebuilding images with the new code...
docker compose build
echo [*] Recreating containers - data volumes preserved, migrations run on startup...
docker compose up -d
call :wait_healthy
echo [OK] Update complete. Volumes kept: pgdata, redis_data, storage_data.
call :print_access
goto :eof

:backup_db
if not exist "backups" mkdir "backups"
for /f %%t in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd-HHmmss"') do set "TS=%%t"
echo [*] Backing up the database to backups\vooda-db-%TS%.sql ...
docker compose exec -T db sh -c "PGPASSWORD=$POSTGRES_PASSWORD pg_dump -U $POSTGRES_USER -d $POSTGRES_DB" > "backups\vooda-db-%TS%.sql" 2>nul
if errorlevel 1 ( echo [!] Could not take a DB backup - continuing ^(update never deletes volumes^). ) else ( echo [OK] DB backup written. )
exit /b 0

:wait_healthy
echo [*] Waiting for the API to become healthy...
set /a _i=0
:wh_loop
set "CID="
for /f %%i in ('docker compose ps -q api 2^>nul') do set "CID=%%i"
if defined CID (
  for /f %%s in ('docker inspect -f "{{.State.Health.Status}}" !CID! 2^>nul') do set "HS=%%s"
  if "!HS!"=="healthy" ( echo [OK] API healthy & exit /b 0 )
)
set /a _i+=1
if !_i! GEQ 60 ( echo [!] API not healthy after ~3 min - check: docker compose logs api & exit /b 0 )
timeout /t 3 /nobreak >nul
goto wh_loop

:print_access
if /i "%MODE%"=="dev" ( set "WEBP=3001" & set "APIP=8001" ) else ( set "WEBP=3000" & set "APIP=8000" )
echo.
echo Vooda is up ^(%MODE% mode^).
echo   Web UI   : http://localhost:!WEBP!
echo   API docs : http://localhost:!APIP!/api/docs
echo   Health   : http://localhost:!APIP!/api/health
echo   Login    : admin@vooda.ai - password was printed by the seed step above.
echo   Change the admin password before exposing this to a network.
echo.
exit /b 0

:usage
echo Vooda installer ^(Windows^)
echo.
echo Usage:
echo   install.bat                 Interactive menu
echo   install.bat install --prod  Production mode  ^(http://localhost:3000^)
echo   install.bat install --dev   Development mode ^(http://localhost:3001^)
echo   install.bat update          Pull latest + rebuild, preserving all data
echo   install.bat check           Check dependencies only
echo   install.bat --help          This help
exit /b 0
