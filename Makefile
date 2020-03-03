.PHONY: install uninstall

install:
	mkdir -p /opt/bpfbench
	cp -r . /opt/bpfbench
	ln -vsfn /opt/bpfbench/bpfbench /usr/bin/bpfbench

uninstall:
	rm -rf /opt/bpfbench
	rm /usr/bin/bpfbench
