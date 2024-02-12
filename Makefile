build_loc := ./bin


fdotools_bin_loc := ~/conformance-test-infrastructure-new/iot-fdo-conformance/
fdotools_infra_loc := ~/conformance-test-infrastructure-new/

ifeq ($(OS),Windows_NT)
    RM = cmd.exe /C del /S /Q
    RMDIR = cmd.exe /C rmdir /S /Q
else
    RM = rm -rf
    RMDIR = rm -rf
endif

preconfig_frontend:
	echo "\n----- Preconfig: Setting up svelte frontend nodejs dependencies -----\n"

	cd ./frontend && npm i

preconfig_conformance_server:
	echo "\n----- Preconfig: Updating go dependencies -----\n"

	go get

setup: preconfig_frontend preconfig_conformance_server

# Compiling GO code
compile_win:
	echo "\n----- Building for Windows... -----\n"
	set GOOS=windows
	go build -o $(build_loc)/iot-fdo-conformance-tools-windows.exe

compile_linux:
	echo "\n----- Building for Linux... -----\n"
	set GOOS=linux
	set GOARCH=amd64
	go build -o $(build_loc)/iot-fdo-conformance-tools-linux

compile_osx:
	echo "\n----- Building for MacOS... -----\n"
	set GOOS=darwin
	go build -o $(build_loc)/iot-fdo-conformance-tools-osx

compile_all: compile_win compile_linux compile_osx

# Build frontend
build_frontend:
	echo "\n----- Building frontend... -----\n"
	cd ./frontend && npm run build
	$(RMDIR) $(build_loc)/frontend
	cp -Rf ./frontend/dist $(build_loc)/frontend

# Build frontend
fdotools__push_new_bin:
	echo "\n----- Updating FDO tools binary... -----\n"
	scp -P ${FDO_BUILD_PUSH_PORT} bin/iot-fdo-conformance-tools-linux ${FDO_BUILD_PUSH_HOST}:$(fdotools_bin_loc)

# Build frontend
fdotools__push_new_ui:
	echo "\n----- Updating FDO tools ui... -----\n"
	scp -R bin/frontend ${FDO_BUILD_PUSH_HOST}:$(fdotools_bin_loc)

# Build frontend
fdotools__restart_docker_compose:
	echo "\n----- Restarting docker compose... -----\n"
	ssh ${FDO_BUILD_PUSH_HOST} "cd $(fdotools_infra_loc) && docker-compose up --build --force -d"

# fdotools__restart_docker_update:

build: build_frontend compile_all