#!/bin/bash

rm -rf ./sandbox
mkdir ./sandbox

echo " "
echo "========================================================="
echo "[0] Igniting malware and copying to sandbox"
echo " "

./build/ignite/polyv_ignite ./build/client/polyv_client
cp ./build/client/polyv_client ./sandbox/polyv_client

cp ./build/target/polyv_target_to_infect ./sandbox/polyv_target_to_infect_1
cp ./build/target/polyv_target_to_infect ./sandbox/polyv_target_to_infect_2
cp ./build/target/polyv_target_to_infect ./sandbox/polyv_target_to_infect_3

echo "========================================================="
echo "[1] Launching malware"
echo " "

./sandbox/polyv_client

echo " "
echo "========================================================="
echo "[2] Launching infected target"
echo " "

./sandbox/polyv_target_to_infect_1 arg_1 arg_2 arg_3