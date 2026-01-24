# SPDX-License-Identifier: GPL-2.0
# Top-level Makefile for Toasty (AF_XDP)

SUBDIRS := lib AF_XDP

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	for d in $(SUBDIRS); do \
		$(MAKE) -C $$d clean; \
	done