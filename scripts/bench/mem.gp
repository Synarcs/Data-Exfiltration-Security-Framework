set terminal png size 1600,900
set output "out/10k/memory_usage.png"
set title "Process Memory Usage Over Time (MB)"
set xlabel "Time (seconds)"
set ylabel "Memory (MB)"
set grid
plot "memory_usage.dat" using 1:2 with linespoints title "Memory Usage" pt 7 ps 1.5 lw 2 lc rgb "#5e03fc"
