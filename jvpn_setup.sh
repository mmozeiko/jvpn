#!/bin/bash
set -e

NC=~/.juniper_networks/network_connect

if [ -d "$NC" ];
then
  echo "$NC already exists, please remove it"
  exit 1
fi

mkdir -p $NC

unzip -o -q ncLinuxApp.jar ncsvc libncui.so

mv ncsvc $NC/
mv libncui.so $NC/
cp wrapper.c $NC/

cd $NC

gcc -m32 -O2 -s wrapper.c -o ncui -ldl -Wl,-rpath,`pwd`
chmod +x libncui.so
sudo chown root:root ncui
sudo chmod 04755 ncui
sudo chown root:root ncsvc
sudo chmod 04755 ncsvc
