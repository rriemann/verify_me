 KARMA=node_modules/.bin/karma
+INSTANBUL=node_modules/.bin/istanbul
+MOCHA=node_modules/.bin/mocha
+_MOCHA=node_modules/.bin/_mocha
+TSC=node_modules/.bin/tsc
+TSLINT=node_modules/.bin/tslint
 
 default: build
 all: clean build test
 
 

BROWSERIFY=node_modules/.bin/browserify
WATCHIFY=node_modules/.bin/watchify

KARMA=node_modules/.bin/karma
INSTANBUL=node_modules/.bin/istanbul
MOCHA=node_modules/.bin/mocha
_MOCHA=node_modules/.bin/_mocha

TSC=node_modules/.bin/tsc
TSLINT=node_modules/.bin/tslint

default: build
all: clean build test

build:
	${TSC} --skipLibCheck
	${TSLINT} -c tslint.json src/*
	$(BROWSERIFY) src/main.ts -v \
	   -o dist/verifyme_client.js \
	   -p tsify \
	   -t [ babelify --presets [ stage-3 es2015 ] ] \

watch:
	${TSC} -w --skipLibCheck
	$(WATCHIFY) src/main.ts -v \
	   -o dist/verifyme.js \
	   -p tsify \
	   -t [ babelify --presets [ stage-3 es2015 ] ] \

build-test:
	${TSC} -p tsconfig.test.json
	${TSLINT} -c tslint.json src/*
	$(BROWSERIFY) src/main.ts -v \
	   -o dist/verifyme.js \
	   -p tsify \
	   -t [ babelify --presets [ stage-3 es2015 ] ] \

karma:
	$(KARMA) start karma.conf.js

test: build-test
	$(INSTANBUL) cover $(_MOCHA) -- dist/test/ \
             --compilers js:babel-core/register  \
             --require babel-polyfill \
             --recursive

test-debug: build-test
	$(MOCHA) --debug-brk --recursive dist/test/

clean:
	@rm -rf dist/* coverage/*

setup-dev:
	@npm install

setup-production:
	@npm install --production

.PHONY: clean setup-dev setup-production test
