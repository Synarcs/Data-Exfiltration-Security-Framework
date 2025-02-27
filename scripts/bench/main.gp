set terminal png size 1600,1200
set output "out/1k/dns_perf_enb_gtld.png"
set multiplot layout 2,1

# QPS Graph
set title "DNS Queries Per Second Over Time"
set xlabel "Time (seconds)"
set ylabel "QPS"
set grid
plot "dns_metrics.dat" using 1:2 with linespoints title "QPS" pt 7 ps 1.5 lw 2 lc rgb "#0060ad"

# Latency Bar Graph
set title "DNS Query Latencies Over Time"
set xlabel "Time (seconds)"
set ylabel "Latency (seconds)"
set style data histogram
set style histogram clustered gap 1
set style fill solid 0.8
set boxwidth 0.8
plot "dns_metrics.dat" using 3:xtic(1) title "Min Latency" lc rgb "#00ad00", \
     "dns_metrics.dat" using 4 title "Max Latency" lc rgb "#ad0000"

unset multiplot
