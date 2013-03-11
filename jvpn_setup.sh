#!/bin/bash

cd ~/.juniper_networks/network_connect

curl -O https://$HOST/dana-cached/nc/ncLinuxApp.jar
unzip ncLinuxApp.jar ncsvc libncui.so
gcc -m32 -O2 -s wrapper.c -o ncui -ldl -Wl,-rpath,`pwd`
sudo chown root:root ncui
sudo chmod 04755 ncui
