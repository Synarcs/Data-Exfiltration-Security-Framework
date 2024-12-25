#!/bin/sh 

build_controller=$1 

dir=$(pwd)

echo "[x] Building Kernel eBPF code, eBPF node agent Go Binary Cilium, and inference socket"
cd node_agent
make build 
make infer-build 
rm -rf dist 

cd ../
echo "build autoInstall Build dir"

ls package/
if [ $? -eq 0 ]; then
  rm -rf package/
  rm -rf *.deb
  rm -rf *.rpm
  rm -rf *.osx
fi

mkdir -p package/{usr/bin,lib/systemd/system,etc/sudoers.d}

loadbinaries() {
  cp node_agent/main package/usr/bin
  cp node_agent/dist/infer package/usr/bin
  cp scripts/brctl.sh package/usr/bin
  cp node_agent/config.yaml package/usr/bin 
  cp ebpf_agent.service package/lib/systemd/system/
  
  touch package/etc/sudoers.d/data-exfil
  echo "ebpf_agent ALL=(ALL) NOPASSWD: /usr/bin/brctl.sh" >> package/etc/sudoers.d/data-exfil
  echo "ebpf_agent ALL=(ALL) NOPASSWD: /usr/bin/infer" >> package/etc/sudoers.d/data-exfil
  echo "ebpf_agent ALL=(ALL) NOPASSWD: /usr/bin/main" >> package/etc/sudoers.d/data-exfil
}


buildpackage() {
 fpm -s dir -t deb -n "data-exfil-security" -v 1.0.0 --after-install post-install.sh  --deb-no-default-config-files  -C package .	
}


loadbinaries
buildpackage


if [ $build_controller ]; then 
  bash controller.sh 
fi 







