#!/bin/sh 

#!/bin/bash

pid=$1

clean() {
    rm -rf memory_usage.dat 
}

run() {
    clean
    for i in $(seq 1 10); do
        timestamp=$i
        memory_kb=$(ps -o rss= -p "$pid")  
        memory_mb=$(echo "scale=2; $memory_kb / 1024" | bc)  

        echo "$timestamp $memory_mb" >> memory_usage.dat
        sleep 1
    done
}


run
