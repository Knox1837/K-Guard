#!/bin/bash
# Test script to trigger various security events for K-Guard

echo "[+] Testing security event detection..."
echo ""

echo "[1] Testing file deletion (TYPE_UNLINK)..."
touch /tmp/test_kguard_delete.txt
rm /tmp/test_kguard_delete.txt
sleep 2

echo "[2] Testing file rename (TYPE_RENAME)..."
touch /tmp/test_kguard_old.txt
mv /tmp/test_kguard_old.txt /tmp/test_kguard_new.txt
rm /tmp/test_kguard_new.txt
sleep 2

echo "[3] Testing chmod (TYPE_CHMOD)..."
touch /tmp/test_kguard_chmod.txt
chmod 755 /tmp/test_kguard_chmod.txt
rm /tmp/test_kguard_chmod.txt
sleep 2

echo "[4] Testing sensitive file access (TYPE_OPEN)..."
cat /etc/passwd > /dev/null
sleep 2

echo "[+] Test complete! Check the graph for security attributes."
echo "[+] Look for nodes with security_score, has_file_deletion, unlink_count, etc."
