
arch=$(arch)
kernel=$(uname -r) 


release=$(cat /etc/os-release)

installExfTools() {
    echo "installing exf tools"
    
    echo "installing dnscat2"
    git clone https://github.com/iagox86/dnscat2.git /tmp/dnscat2

    echo "installing DNSExfiltrator"
    git clone https://github.com/Arno0x/DNSExfiltrator.git /tmp/DNSExfiltrator

    echo "Installing det"
    git clone https://github.com/sensepost/DET.git /tmp/DET

    echo "installing iodine"
    sudo apt-get install -y iodine 

    echo "installing dnsscapy"
}

buildExfTools() {
    cd /tmp/dnscat2/client  
    make 

    cd /tmp/DNSExfiltrator


}

clean () {
    echo "cleaning the dns exfiltration tools"

    rm -rf /tmp/dnscat2
    rm -rf /tmp/DNSExfiltrator
    rm -rf /tmp/DET

}

if [[ $arch == "x86_64" ]]; then
    echo "x86_64"
elif [[ $arch == "aarch64" ]]; then
    echo "aarch64"
    installExfTools 
fi  





