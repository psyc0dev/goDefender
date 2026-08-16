@Echo off
title GoDefender Build and Setup
echo Downloading dependencies...
go mod tidy
echo Building GoDefender...
go build -o GoDefender.exe ./cmd/godefender
echo Done!
pause
