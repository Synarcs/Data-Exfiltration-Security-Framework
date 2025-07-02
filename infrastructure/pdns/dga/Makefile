# SPDX-License-Identifier: AGPL-3.0

.PHONY: dga
dga:
	python3 dga.py -d 3 
	service pdns-recursor restart

.PHONY: dep
dep:
	pip3 install -r requirements.txt --break-system-packages 

.PHONY: clean 
clean:
	python3 dga.py -c true 
