# Setting up project
preconfig_submodules:
	echo "\n----- Preconfig: Updating git submodules -----\n"

	git submodule init
	git submodule update

preconfig_frontend:
	echo "\n----- Preconfig: Setting up svelte frontend nodejs dependencies -----\n"

	cd ./frontend && npm i

preconfig_conformance_server:
	echo "\n----- Preconfig: Updating go dependencies -----\n"

	go get

setup: preconfig_submodules preconfig_frontend preconfig_conformance_server

build_config_onprem:
	sed -i -e 's/const TOOLS_MODE.*/const TOOLS_MODE = fdoshared.CFG_MODE_ONPREM/' running.ctx.go

build_config_online:
	sed -i -e 's/const TOOLS_MODE.*/const TOOLS_MODE = fdoshared.CFG_MODE_ONLINE/' running.ctx.go

# Compiling GO code
compile_win:
	echo "\n----- Building for Windows... -----\n"
	GOOS=windows go build -o bin/fdo-fido-conformance-server-windows.exe

compile_linux:
	echo "\n----- Building for Linux... -----\n"
	GOOS=linux go build -o bin/fdo-fido-conformance-server-linux

compile_osx:
	echo "\n----- Building for MacOS... -----\n"
	GOOS=darwin go build -o bin/fdo-fido-conformance-server-osx

compile_all: compile_win compile_linux compile_osx

# Build frontend
build_frontend:
	echo "\n----- Building frontend... -----\n"
	cd ./frontend && npm run build
	cp -Rf ./frontend/dist bin/frontend

# Build frontend
update_fdo_packages:
	echo "\n----- Updating FDO packages... -----\n"
	GOSUMDB=off go get github.com/WebauthnWorks/fdo-shared
	GOSUMDB=off go get github.com/WebauthnWorks/fdo-do
	GOSUMDB=off go get github.com/WebauthnWorks/fdo-rv
	GOSUMDB=off go get github.com/WebauthnWorks/fdo-device-implementation


build: build_frontend compile_all