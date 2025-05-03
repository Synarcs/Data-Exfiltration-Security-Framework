set terminal pngcairo size 800,600 enhanced font 'Arial,12'
set output 'exfil_stopped.png'

set title 'DNS Exfiltration Stopped vs Threshold Count'
set xlabel 'Exfiltration Threshold (Count Before Implant Process SIGKILL)'
set ylabel 'Data Exfiltrated (Bytes) Prevented'

set grid
set style data linespoints
set pointsize 1.5
plot 'dns_exfil_vol' using 1:2 title 'Exfiltrated Paylod size prevented' lw 2 lc rgb 'blue'