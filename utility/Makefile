INSTANBUL=node_modules/.bin/istanbul
MOCHA=node_modules/.bin/mocha
_MOCHA=node_modules/.bin/_mocha
TSC=node_modules/.bin/tsc
TSLINT=node_modules/.bin/tslint

default: build
all: clean build test

build:
	${TSC}
	${TSLINT} -c tslint.json src/*

watch:
	${TSC} -w

build-test:
	${TSC} -p tsconfig.test.json
	${TSLINT} -c tslint.json src/*

test: build-test
	$(INSTANBUL) cover $(_MOCHA) -- dist/test/

test-debug: build-test
	$(MOCHA) --debug-brk -- dist/test/

clean:
	@rm -rf dist/* coverage/*

setup-dev:
	@npm install

setup-production:
	@npm install --production

.PHONY: clean setup-dev setup-production test
