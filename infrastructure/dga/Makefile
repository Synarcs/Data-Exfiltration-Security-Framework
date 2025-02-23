
.PHONY: dga
dga:
	python3 dga.py -d 3 
	service pdns-recursor restart
.PHONY: clean 
clean:
	python3 dga.py -c true 