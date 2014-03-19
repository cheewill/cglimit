#!/bin/bash

gcc -g -I./libcgroup/include/ cglimit.c -o cglimit -L./libcgroup/lib/ -lcgroup

sudo chown root:root cglimit
sudo chmod 6775 cglimit
