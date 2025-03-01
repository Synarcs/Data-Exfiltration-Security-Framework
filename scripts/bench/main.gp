set terminal png size 1600,1200
set output "out/1k/dns_perf_enb_gtld.png"
set multiplot layout 2,1

# QPS and Packet Loss Line Graph (First Plot)
set tmargin 4
set title "DNS Queries Per Second and Packet Loss Over Time" offset 0,-1
set xlabel "Time (seconds)"
unset ylabel
set y2label "Packets Lost"  # Label only y2 for first plot
set y2tics format "%g"
set ytics nomirror
set grid
set y2range [0:1]  # Ensures valid y2 range even if no data
plot "dns_metrics.dat" using 1:2 with linespoints title "QPS" pt 7 ps 1.5 lw 2 lc rgb "#0060ad", \
     "dns_metrics.dat" using 1:5 axes x1y2 with points title "Packets Lost" pt 7 ps 2 lc rgb "#FF0000"

# Latency Bar Graph (Second Plot) - No y2 axis needed
set title "DNS Query Latencies Over Time"
set xlabel "Time (seconds)"
set ylabel "Latency (ms)"  # Add relevant ylabel for latency
set style data histogram
set style histogram clustered gap 1
set style fill solid 0.8
set boxwidth 0.8
plot "dns_metrics.dat" using 3:xtic(1) title "Min Latency" lc rgb "#00ad00", \
     "dns_metrics.dat" using 4 title "Max Latency" lc rgb "#ad0000"

unset multiplot