sudo mkdir -p /tmp/cgroupv2
sudo mount -t cgroup2 none /tmp/cgroupv2
sudo mkdir -p /tmp/cgroupv2/foo
cd ..
sudo ./ccp_kernel_load ipc=0
echo $$ | sudo tee /tmp/cgroupv2/foo/cgroup.procs
iperf3 -s localhost -1
