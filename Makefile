.PHONY: install uninstall

install: uninstall
	@mkdir -p /opt/bpfbench
	@cp -r . /opt/bpfbench
	@ln -vsfn /opt/bpfbench/bpfbench /usr/bin/bpfbench

uninstall:
	@rm -rf /opt/bpfbench
	@rm -f /usr/bin/bpfbench
