#!/bin/bash

cd $HOME
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/client
make 

cd $HOME
curl https://sliver.sh/install|sudo bash


cd $HOME
git clone https://github.com/yarrick/iodine.git
make && make install 

