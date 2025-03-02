tool=$1

throughput=$2

if [[ $tool == "dnsperf" ]]; then
    echo "using $tool"
    for i in $(seq 1 20); do
        dnsperf -s 10.158.82.55 -d queries.txt -Q $throughput -l 1 | \
        awk -v i=$i '
        /Queries per second/ {qps=$4}
        /Queries lost/ {lost=$3}
        /Average Latency/ {split($6, min, ","); split($8, max, ")"); print i, qps, min[1], max[1], lost}' >> dns_metrics.dat
    done
else
    echo "$tool not supported"
fi

plot(){
}
