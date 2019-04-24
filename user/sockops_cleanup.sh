zsh -c "./load_sock_ops -r /tmp/cgroupv2/foo"
umount /tmp/cgroupv2
rm -rf /tmp/cgroupv2
cd ..
sudo ./ccp_kernel_unload

