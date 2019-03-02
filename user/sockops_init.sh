sudo mkdir -p /tmp/cgroupv2
sudo mount -t cgroup2 none /tmp/cgroupv2
sudo mkdir -p /tmp/cgroupv2/foo
echo $$ | sudo tee /tmp/cgroupv2/foo/cgroup.procs
iperf -s localhost
