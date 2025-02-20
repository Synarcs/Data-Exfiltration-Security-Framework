tool=$1


if [[ $tool == "dnsperf" ]]; then
    echo "using $tool"
    qps=$2
    duration=$3
    dnsperf -s 10.158.82.55 -d queries.txt -Q $qps -l $duration
else     
    echo "using $tool"
fi 
