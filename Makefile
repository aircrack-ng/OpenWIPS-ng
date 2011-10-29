default: all

all:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

install:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

uninstall:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

strip:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

clean:
	$(MAKE) -C sensor $(@)
	$(MAKE) -C server $(@)

distclean: clean
