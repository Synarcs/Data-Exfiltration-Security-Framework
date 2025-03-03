#!/bin/sh 

kernel_memory() {
    for i in $(seq 1 24); do 
        timestamp=$i
        memory_kb=$(bpftool map show | awk '
            /lru_hash/ {found=1; next}  # Flag start of a new map entry
            found && /memlock/ {sum += $2; found=0}  # Add memlock and reset flag
            END {print sum}
        ')

        if [[ -z "$memory_kb" ]]; then
            memory_kb=0  
        fi
        memory_mb=$(echo "scale=2; $memory_kb / 1024" | bc)  

        echo "$timestamp $memory_mb" >> bpf_memory.dat
        sleep 1
    done
}

kernel_memory