set terminal png size 800,600
set output "out/10k/memory_usage.png"
set title "Process Memory Usage Over Time (MB) 10,000 DNS Req / Sec"
set xlabel "Time (seconds)"
set ylabel "Memory (MB)"
set grid
plot "memory_usage.dat" using 1:2 with linespoints title "Memory Usage" pt 7 ps 1.5 lw 2 lc rgb "#5e03fc"
