Python script for connecting to Juniper VPN
===========================================

Tested only on x86_64 Arch Linux.

Requirements
------------

* python (3.x)
* lib32-zlib
* lib32-glibc
* net-tools
* tun module (execute `modprobe tun`)
* unzip (only for installation script)
* gcc-multilib (only for installation script)

Installation
------------

1. Login to your VPN site
2. Download `https://<HOST>/dana-cached/nc/ncLinuxApp.jar` file next to `jvpn_setup.sh` script
3. Execute `./jvpn_setup.sh`

Usage
-----

    jvpn.py [-h] [-c HOST] [-u USER] [-s] [-i] [-b]
    
      -h, --help  show this help message and exit
      -c HOST     VPN site to connect
      -u USER     username for login
      -s          stops VPN connection
      -i          display info about current state
      -b          ignore broken https certificate for web request

### Connecting to VPN

    ./jvpn.py -c <HOST> -u <USERNAME>

### Disconnecting

    ./jvpn.py -c <HOST> -s

### Info

Shows if VPN is running + total bytes transmitted and received:

    ./jvpn.py -i

Links
-----
* wrapper.c from https://github.com/samm-git/jvpn
* http://makefile.com/.plan/2009/10/juniper-vpn-64-bit-linux-an-unsolved-mystery/
