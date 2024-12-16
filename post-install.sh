#!/bin/sh

chmod +x /usr/bin/brctl.sh
chmod +x /usr/bin/infer
chmod +x /usr/bin/main

chmod 700 /usr/bin/brctl.sh
chmod 700 /usr/bin/infer
chmod 700 /usr/bin/main
chown root:root /usr/bin/brctl.sh
chown root:root /usr/bin/infer
chown root:root /usr/bin/main
chmod 440 /etc/sudoers.d/data-exfil
chown root:root /etc/sudoers.d/data-exfil

systemctl daemon-reload
systemctl enable ebpf_agent



