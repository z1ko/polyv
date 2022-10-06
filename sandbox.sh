#!/bin/bash

rm -rf ./sandbox
mkdir ./sandbox

# Ignite malware
echo -n "igniting malware..."
./build/ignite/polyv_ignite ./build/client/polyv_client
echo "DONE"

# Move malware and target to sandbox
cp ./build/client/polyv_client ./sandbox/polyv_client
cp ./build/target/polyv_target_to_infect ./sandbox/polyv_target_to_infect

# Launch malware
echo -n "launching malware..."
./sandbox/polyv_client
echo "DONE"

# Launch infected target
echo -n "launching infected target..."
./sandbox/polyv_target_to_infect arg_1 arg_2 arg_3
echo "DONE"