#!/bin/sh
# Demo log generator: writes plausible auth.log traffic to $1, with an SSH
# brute-force burst and a rogue useradd every couple of minutes so the
# dashboard has something to show.
OUT="${1:?usage: loggen.sh <logfile>}"

ts() { date '+%b %e %H:%M:%S'; }

i=0
while true; do
  i=$((i + 1))
  echo "$(ts) demo-host sshd[$((1000 + i))]: Accepted publickey for arman from 198.51.100.3 port $((50000 + i)) ssh2" >> "$OUT"
  sleep 7
  if [ $((i % 3)) -eq 0 ]; then
    echo "$(ts) demo-host sudo:    arman : TTY=pts/0 ; PWD=/home/arman ; USER=root ; COMMAND=/usr/bin/systemctl status sshd" >> "$OUT"
  fi
  if [ $((i % 8)) -eq 0 ]; then
    for p in 1 2 3 4 5 6; do
      echo "$(ts) demo-host sshd[$((2000 + p))]: Failed password for root from 203.0.113.66 port $((40000 + p)) ssh2" >> "$OUT"
      sleep 1
    done
  fi
  if [ $((i % 17)) -eq 0 ]; then
    echo "$(ts) demo-host useradd[3000]: new user: name=svc$i, UID=$((1500 + i)), GID=$((1500 + i)), home=/home/svc$i, shell=/bin/false" >> "$OUT"
  fi
  sleep 7
done
