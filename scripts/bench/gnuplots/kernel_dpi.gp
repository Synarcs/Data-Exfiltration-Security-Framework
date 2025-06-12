# cleaner_plot_kernel_dpi_time.gp
set terminal pngcairo size 800,600 enhanced font 'Verdana,10'
set output 'kernel_dpi_time_plot.png'

set title "Microsecond Raw Parsing Time of DNS Kernel"
set xlabel "Seconds (Single DNS Packet per Second)"
set ylabel "DNS DPI Parsing Time (μs)"
set grid
set format y "%.1f"

datafile = '../kernel_dpi_time.dat'

# Calculate mean and divide by 1000 to convert to μs
stats datafile using 1 nooutput
mean = STATS_mean / 1000.0

# Plot the data and mean line
plot datafile using ($0+1):($1/1000.0) with linespoints title "Parsing Time (μs)" lc rgb "blue" pt 7, \
     mean with lines title sprintf("Mean = %.2f μs", mean) lc rgb "#7e1026" dt 2 lw 2