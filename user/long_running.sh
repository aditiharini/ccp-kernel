#!/bin/bash
for i in {0..5000000}
do
./sockops_init.sh &
sleep 5
./bpf_perf_user >> log.out &
POLL_PID=$!
sleep 5
./run_client.sh
sleep 5
echo "==========ROUND $i==========" >> log.out
echo "ROUND $i " >> progress.out
date >> progress.out
kill $POLL_PID
./sockops_cleanup.sh
sleep 20
done

