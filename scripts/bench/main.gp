set terminal png size 800,600
set output "qps_packet_loss.png"

set title "DNS over TCP Queries Per Second and Packet Loss Over Time" offset 0,-1
set xlabel "Time (seconds)"
unset ylabel
set y2label "Packets Lost"
set y2tics format "%g"
set ytics nomirror
set grid
set y2range [0:1]

plot "dns_metrics.dat" using 1:2 with linespoints title "QPS" pt 7 ps 1.5 lw 2 lc rgb "#0060ad", \
     "dns_metrics.dat" using 1:5 axes x1y2 with points title "Packets Lost" pt 7 ps 2 lc rgb "#FF0000"