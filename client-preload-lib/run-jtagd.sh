#!/bin/bash
gcc -fPIC flyserv_client.c -ldl -shared -o flyserv_client.so
env LD_LIBRARY_PATH=/home/rohit/local/altera/14.1/quartus/linux64 LD_PRELOAD=./flyserv_client.so /home/rohit/local/altera/14.1/quartus/linux64/jtagd -f
