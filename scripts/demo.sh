#!/usr/bin/env bash
# A little activity so the Leash TUI has something to show. Runs ~6s and exits
# (Leash auto-quits when it does). Try:
#   sudo /path/to/leash run -- bash scripts/demo.sh
for i in 1 2 3 4 5; do
  cat /etc/hostname >/dev/null       # open
  cat /etc/os-release >/dev/null     # open
  ls /usr/bin >/dev/null             # exec ls + many opens
  head -c 1 /etc/passwd >/dev/null   # exec head + open
  # outbound IPv4 connections (bash /dev/tcp — no curl needed)
  timeout 2 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' 2>/dev/null
  timeout 2 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53' 2>/dev/null
  sleep 1
done
