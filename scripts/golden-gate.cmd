@echo off
REM CI gate: golden corpus + red-team + audit-leak + metrics tests
"%ProgramFiles%\Go\bin\go.exe" test ./internal/scrubber/ -run "TestGoldenCorpus|TestRedTeamExfil" -v
@if errorlevel 1 exit /b 1
"%ProgramFiles%\Go\bin\go.exe" test ./internal/audit/ ./internal/metrics/ ./internal/memguard/ -v
@if errorlevel 1 exit /b 1
echo GOLDEN-GATE OK
