#!/bin/bash

cd `dirname $0`

source client-env
PRELOAD=../client-preload-lib/flyserv_client.so

exec env LD_LIBRARY_PATH=${QUARTUS_ROOTDIR}/linux64 LD_PRELOAD=${PRELOAD} ${QUARTUS_ROOTDIR}/linux64/jtagd -f
