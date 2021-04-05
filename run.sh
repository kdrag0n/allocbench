#!/usr/bin/env bash

set -eufo pipefail

traces=(
    angry_birds2
    camera
    candy_crush_saga
    gmail
    maps
    photos
    pubg
    surfaceflinger
    system_server
    systemui
    youtube
)

declare -A allocators
allocators[scudo]="/usr/lib/clang/11.1.0/lib/linux/libclang_rt.scudo-x86_64.so"
allocators[jemalloc]="/usr/lib/libjemalloc.so"
allocators[mimalloc]="allocators/mimalloc/out/1.7.0/libmimalloc.so"
allocators[mimalloc-secure]="allocators/mimalloc/out/1.7.0-secure/libmimalloc-secure.so"
allocators[mimalloc2]="allocators/mimalloc/out/2.0.0/libmimalloc.so"
allocators[mimalloc2-secure]="allocators/mimalloc/out/2.0.0-secure/libmimalloc-secure.so"
#allocators[mimalloc-1.6.7]="/usr/lib/mimalloc-1.6/libmimalloc.so"
#allocators[mimalloc-1.6.7-secure]="/usr/lib/mimalloc-1.6/libmimalloc-secure.so"
allocators[glibc]=""
allocators[tcmalloc]="/usr/lib/libtcmalloc.so"
allocators[hoard]="/usr/lib/libhoard.so"
allocators[mesh]="allocators/Mesh/bazel-bin/src/libmesh.so"
allocators[rpmalloc]="allocators/rpmalloc/build/ninja/linux/release/x86-64/rpmalloc-5aa0e6/librpmallocwrap.so"
allocators[ptmalloc3]="allocators/ptmalloc3/libptmalloc3.so"
allocators[hardened_malloc]="/usr/lib/libhardened_malloc.so"
allocators[snmalloc]="$HOME/code/android/rom/aosp/external/snmalloc/build/libsnmallocshim.so"
allocators[snmalloc-1mib]="$HOME/code/android/rom/aosp/external/snmalloc/build/libsnmallocshim-1mib.so"
allocators[snmalloc-16mib]="$HOME/code/android/rom/aosp/external/snmalloc/build/libsnmallocshim-16mib.so"

cd "$(dirname "$0")"

function msg() {
    echo -e "\e[1;32m$*\e[0m"
}

for alloc_name in "${!allocators[@]}"
do
    alloc_lib="${allocators[$alloc_name]}"
    msg "\n\n\n===========================\nAllocator: $alloc_name\n====================" 
    mkdir -p "results/$alloc_name"

    echo > "results/$alloc_name/traces_perf.csv"
    echo > "results/$alloc_name/traces_rss.csv"
    for trace in "${traces[@]}"
    do
        msg "Trace: $trace"
        LD_PRELOAD="$alloc_lib" ./replay "traces/$trace.txt" | tee "results/$alloc_name/trace-$trace"
        grep 'Finished running' "results/$alloc_name/trace-$trace" | awk '{print $8}' >> "results/$alloc_name/traces_perf.csv"
        grep 'Final memory usage' "results/$alloc_name/trace-$trace" | awk '{print $5}' >> "results/$alloc_name/traces_rss.csv"
    done
done
