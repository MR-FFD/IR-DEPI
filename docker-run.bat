@echo off
REM IR-DEPI | Docker Run Script for Windows

echo ======================================
echo   IR-DEPI | Docker Deployment
echo ======================================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo X Docker is not installed. Please install Docker Desktop first.
    exit /b 1
)

echo [OK] Docker is installed
echo.

REM Parse command line arguments
if "%1"=="" set build
if "%1"=="build" goto build
if "%1"=="up" goto up
if "%1"=="down" goto down
if "%1"=="logs" goto logs
if "%1"=="restart" goto restart
if "%1"=="shell" goto shell
if "%1"=="test" goto test

echo Usage: %0 {build^|up^|down^|logs^|restart^|shell^|test}
exit /b 1

:build
echo Building Docker image...
docker-compose build
echo Build complete!
goto end

:up
echo Starting IR-DEPI container...
docker-compose up -d
echo Container started!
echo    View logs: docker-compose logs -f
echo    Stop: docker-compose down
goto end

:down
echo Stopping IR-DEPI container...
docker-compose down
echo Container stopped!
goto end

:logs
echo Showing logs...
docker-compose logs -f
goto end

:restart
echo Restarting IR-DEPI container...
docker-compose restart
echo Container restarted!
goto end

:shell
echo Opening shell in container...
docker-compose exec ir-depi /bin/bash
goto end

:test
echo Running tests inside container...
docker-compose run --rm ir-depi python test_api_keys.py
docker-compose run --rm ir-depi python test_threat_intel.py
goto end

:end
echo.
echo ======================================