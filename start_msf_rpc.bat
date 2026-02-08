@echo off
echo Starting Metasploit RPC Daemon...
echo User: msf
echo Pass: msf
echo Port: 55553
echo SSL:  Enabled
echo.
msfrpcd -P msf -U msf -p 55553 -a 127.0.0.1 -S
pause
