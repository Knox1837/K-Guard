#!/bin/bash
# generates ~100 short-lived processes with varied activity
# for exercising a process/file/network monitoring pipeline

N=100

for i in $(seq 1 $N); do
    (
# touch a temp file (file_data / file_binary node + OPENS edge)
echo "test data $i" > /tmp/kguard_test_$i.txt
cat /tmp/kguard_test_$i.txt > /dev/null

# occasionally do a network call — now fully local/inbound instead of
# an outbound curl to the internet. A short-lived listener binds a
# port and accepts one connection (this is what triggers a
# TYPE_TCP_ACCEPT / network_socket node + in-degree edge on the
# listener process). A second local process then connects to it,
# which is what makes the listener's accept() actually return.
if (( i % 5 == 0 )); then
    PORT=$((20000 + (i % 4000)))

    # listener: bind, accept exactly one connection, then exit.
    # timeout guards against it hanging forever if nothing connects.
    timeout 2 python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT))
s.listen(1)
conn, _ = s.accept()
conn.close()
s.close()
" &
    LISTENER_PID=$!

    # give the listener a moment to bind before connecting
    sleep 0.2

    # local client connects in — this is what the listener sees as
    # an inbound connection. Uses bash's built-in /dev/tcp so the
    # script has no dependency on nc/curl for this half.
    exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null && exec 3>&- 3<&-

    wait $LISTENER_PID 2>/dev/null
fi

# occasionally fork a child process (extra process node + FORKED edge)
if (( i % 3 == 0 )); then
bash -c 'sleep 0.2' &
wait
fi

sleep 0.1
rm -f /tmp/kguard_test_$i.txt
    ) &

# throttle so you don't launch all 100 in the same instant
if (( i % 10 == 0 )); then
sleep 0.3
fi
done

wait
echo "Done — spawned $N test processes"