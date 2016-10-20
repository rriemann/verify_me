INSTANBUL=node_modules/.bin/istanbul
MOCHA=node_modules/.bin/mocha
_MOCHA=node_modules/.bin/_mocha

default: build
all: clean build test

build: src/main.ts
	@tsc

watch: src/main.ts
	@tsc -w

test:
	$(INSTANBUL) cover $(_MOCHA) -- dist/test/*

test-debug:
	$(MOCHA) --debug-brk -- dist/test/* --check-leaks --full-trace

clean:
	@rm -rf dist/* coverage/*

setup-dev:
	@npm install

setup-production:
	@npm install --production

.PHONY: clean setup-dev setup-production test
