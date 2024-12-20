ALL_SOURCES := $(wildcard src/**/*.c) src/openblahaj.c
SOURCES_EXCLUSION := src/link/bluetooth.c src/link/dbus.c
SOURCES := $(filter-out $(SOURCES_EXCLUSION), $(ALL_SOURCES))
OBJECTS := $(patsubst src/%.c, build/objects/%.o, $(SOURCES))
SRCDIRS := $(sort $(dir $(SOURCES)))
BUILDDIRS := $(patsubst src/%, build/objects/%, $(SRCDIRS))
CFLAGS ?= -Wall -Wextra -O3 -march=native
MANDATORY_CFLAGS := -I. -Iinclude/
MANDATORY_LDFLAGS := -lpcap
CC ?= cc

all: make_build_dir build/openBLAHAJ

.PHONY: clean
clean:
	rm -rf build/

.PHONY: make_build_dir
make_build_dir:
	mkdir -p $(BUILDDIRS)

build/objects/%.o: src/%.c
	$(CC) $(MANDATORY_CFLAGS) $(CFLAGS) -o $@ -c $<

build/openBLAHAJ: $(OBJECTS)
	$(CC) $(MANDATORY_CFLAGS) $(CFLAGS) $(MANDATORY_LDFLAGS) $(LDFLAGS) -o $@ $(OBJECTS)
