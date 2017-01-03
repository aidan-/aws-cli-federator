SHELL := /bin/bash

ifeq ($(OS), Windows_NT)
	EXECUTABLE := aws-cli-federator.exe
else
	EXECUTABLE := aws-cli-federator
endif

.PHONY: all
all: build

.PHONY: clean
clean:
	rm -rf build/*

.PHONY: dist
dist: release

.PHONY: build
build:
	mkdir build
	go build -v -o build/${EXECUTABLE}

.PHONY: release
release: clean release-build

.PHONY: release-build
release:
	mkdir build
	gox -os="linux darwin windows" -arch="386 amd64" -output="build/{{.Dir}}_{{.OS}}_{{.Arch}}/aws-cli-federator"
	for dir in `ls build/`; do	\
		[ -e "build/$${dir}/$${dir}.zip" ] ||	\
		( cd -- "build/$${dir}" && zip -r $${dir}.zip .);	\
	done
