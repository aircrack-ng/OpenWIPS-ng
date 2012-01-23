$(shell chmod 755 evalrev)

default: all

all:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

install:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)
	$(MAKE) -C manpages $(@)

uninstall:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)
	$(MAKE) -C manpages $(@)

strip:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

clean:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

distclean: clean
