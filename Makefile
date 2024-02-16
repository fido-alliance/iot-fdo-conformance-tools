ifeq ($(OS),Windows_NT)
    RM = cmd.exe /C del /S /Q
    RMDIR = cmd.exe /C rmdir /S /Q
	CURRENT_DIR = $(CURDIR)
else
    RM = rm -rfc
    RMDIR = rm -rf
	CURRENT_DIR = $(shell pwd)
endif

BUILD_LOC = $(CURRENT_DIR)/bin

preconfig_frontend:
	echo "\n----- Preconfig: Setting up svelte frontend nodejs dependencies -----\n"

	cd $(CURRENT_DIR)/frontend && npm i

preconfig_conformance_server:
	echo "\n----- Preconfig: Updating go denppendencies -----\n"

	go get

setup: preconfig_frontend preconfig_conformance_server

# Compiling GO code
compile_win:
	echo "\n----- Building for Windows... -----\n"
	set GOOS=windows
	go build -o $(BUILD_LOC)/iot-fdo-conformance-tools-windows.exe

compile_linux:
	echo "\n----- Building for Linux... -----\n"
	set GOOS=linux
	set GOARCH=amd64
	go build -o $(BUILD_LOC)/iot-fdo-conformance-tools-linux

compile_osx:
	echo "\n----- Building for MacOS... -----\n"
	set GOOS=darwin
	go build -o $(BUILD_LOC)/iot-fdo-conformance-tools-osx

compile_all: compile_win compile_linux compile_osx

# Build frontend
build_frontend:
	echo "\n----- Building frontend... -----\n"
	cd $(CURRENT_DIR)/frontend && npm run build
	
	$(RMDIR) $(BUILD_LOC)/frontend
	cp -Rf $(CURRENT_DIR)/frontend/dist $(BUILD_LOC)/frontend

build: build_frontend compile_all


FDOTOOLS_BIN_LOC = ~/conformance-test-infrastructure-new/iot-fdo-conformance/
FDOTOOLS_INFRA_LOC = ~/conformance-test-infrastructure-new/

# Build frontend
fdotools__push_new_bin:
	echo "\n----- Updating FDO tools binary... -----\n"
	scp -P ${FDO_BUILD_PUSH_PORT} $(CURRENT_DIR)/bin/iot-fdo-conformance-tools-linux ${FDO_BUILD_PUSH_HOST}:$(FDOTOOLS_BIN_LOC)

# Build frontend
fdotools__push_new_ui:
	echo "\n----- Updating FDO tools ui... -----\n"
	scp -R $(CURRENT_DIR)/bin/frontend ${FDO_BUILD_PUSH_HOST}:$(FDOTOOLS_BIN_LOC)

# Build frontend
fdotools__restart_docker_compose:
	echo "\n----- Restarting docker compose... -----\n"
	ssh ${FDO_BUILD_PUSH_HOST} "cd $(FDOTOOLS_INFRA_LOC) && docker-compose up --build --force -d"

# fdotools__restart_docker_update:
