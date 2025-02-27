tool=$1

qps=$2
duration=$3

if [[ $tool == "dnsperf" ]]; then
    echo "using $tool"
    for i in $(seq 1 20); do 
        dnsperf -s 10.158.82.55 -d queries.txt -Q 1000 -l 1 | \
        awk -v i=$i '/Queries per second/ {qps=$4} /Average Latency/ {split($6, min, ","); split($8, max, ")"); print i, qps, min[1], max[1]}' >> dns_metrics.dat
    done
else     
    echo "using $tool"
fi 


plot(){
    dnsperf -s 10.158.82.55 -d queries.txt -Q $qps -l $duration -c 100
    grep "DNS queries sent" dnsperf_output.txt | awk '{print NR, $4}' > qps.dat
}
