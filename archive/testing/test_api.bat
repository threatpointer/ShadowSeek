@echo off
echo Testing API endpoints...

echo.
echo Testing /api/bridge/test endpoint...
curl -v http://localhost:5000/api/bridge/test

echo.
echo Testing /api/status endpoint...
curl -v http://localhost:5000/api/status

echo.
echo Testing /api/binaries endpoint...
curl -v http://localhost:5000/api/binaries

echo.
echo Testing /api/tasks endpoint...
curl -v http://localhost:5000/api/tasks

echo.
echo Done! 