.PHONY: install

install:
	sudo mkdir -p /opt/bpfbench
	sudo cp -r . /opt/bpfbench
	sudo ln -vsfn /opt/bpfbench/bpfbench /usr/bin/bpfbench
