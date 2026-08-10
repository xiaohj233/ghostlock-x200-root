#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
chmod 755 /data/local/tmp/w2host
for p in $(ps -A -o PID,NAME | grep w2host | awk '{print $1}'); do
  kill -9 $p 2>/dev/null
done
sleep 2
rm -f /data/local/tmp/w2_cred.txt /data/local/tmp/w2_dbg.log /data/local/tmp/rootcmd.sock /data/local/tmp/root_proof
nohup /data/local/tmp/w2host > /data/local/tmp/w2h.log 2>&1 &
sleep 3
cat /data/local/tmp/w2h.log 2>/dev/null | head -3
ps -A | grep w2host | head -3