# Set the output format and file
set terminal pngcairo size 800,600 enhanced font 'Verdana,10'
set output 'dns_response_time.png'

set title "Response Time Per Each DNS Exfiltration Attempt"
set xlabel "Attempt #"
set ylabel "Response Time (µs)"
set grid

datafile = 'resp_bench.dat'

stats datafile using 2 nooutput
mean = STATS_mean

# Plot data and bold mean line
plot datafile using 1:2 with linespoints title "Response Time", \
     mean with lines title sprintf("Mean = %.3f µs", mean) lc rgb "red" dt 2 lw 2