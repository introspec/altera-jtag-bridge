# altera-jtag-bridge
Client Library and Server Daemon to bridge Altera USB Blaster II JTAG commands from a Linux VM to a FreeBSD system.


## Developement & Test Environment

Foo | Val
--- | ---
Host | FreeBSD 11.0-RELEASE-p1
Guest | Linux 2.6.32-642.el6.x86_64 (CentOS 6.8)
Hypervisor | bhyve
Quartus II | Version 14.1
Device | Terasic DE0-Nano


## Quick Start

### Host
On the Host machine, one to which the device is connected, execute 

.../altera-jtag-bridge/run/run-server.sh &

### Client
Set the server IP address in run/client-env.sh and execute

.../altera-jtag/bridge/run/run-jtagd.sh &

Launch this before to executing any Quartus software otherwise the original jtagd will be launched and this client will not be able to execute. The server needs to be running on the host system or the client will fail to execute.


Send Bug & Error Reports to : rohit@purpe.com


