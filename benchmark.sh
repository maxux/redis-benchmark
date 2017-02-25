#!/bin/bash
gcc -o  ardb-benchmark ardb-benchmark.c -W -Wall -O2 -pthread -I/usr/include/hiredis -lhiredis -lpthread -lssl -lcrypto