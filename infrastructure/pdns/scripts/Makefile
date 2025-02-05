

.PHONY: run
run:
	lua block.lua

.PHONY: dep
dep: 
	luarocks install luaposix
	luarocks install --server=https://luarocks.org/dev ltn12
	luarocks install lua-cjson-ol 


.PHONY: build
build:
	luac -o block block.lua 

.PHONY: install-lua
install-lua:
	sudo apt-get install lua5.4 5.4.6-3build2