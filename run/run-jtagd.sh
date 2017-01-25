#!/bin/bash

source `dirname $0`/client-env
PRELOAD=`dirname $0`/../client-preload-lib/flyserv_client.so

env LD_LIBRARY_PATH=${QUARTUS_ROOTDIR}/linux64 LD_PRELOAD=${PRELOAD} ${QUARTUS_ROOTDIR}/linux64/jtagd
