#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GhostLock-X200 contributors
"""rootcmd 客户端 — vivo X200 临时 root 工具箱 (需先: adb forward tcp:19000 localfilesystem:/data/local/tmp/rootcmd.sock)
用法: python rootcmd_client.py "READ /data/system/app/some.apk" > out.apk
      python rootcmd_client.py "WRITE /data/local/tmp/x.bin 6869..."
      python rootcmd_client.py "LIST /data"
      python rootcmd_client.py "CHMOD 644 /path" / "CHOWN 0 0 /path" / "MKDIR /path" / "RM /path"
"""
import socket, sys, time

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmdline = " ".join(sys.argv[1:])
    c = socket.create_connection(("127.0.0.1", 19000), timeout=15)
    c.sendall((cmdline + "\n").encode())
    time.sleep(0.3)
    try:
        c.shutdown(socket.SHUT_WR)
    except Exception:
        pass
    data = b""
    while True:
        try:
            chunk = c.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    c.close()
    sys.stdout.buffer.write(data)

if __name__ == "__main__":
    main()