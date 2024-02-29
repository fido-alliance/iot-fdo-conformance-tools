OS := $(if $(findstring Windows_NT,$(OS)),Windows,$(OS))

define build_build_helper
	go build ./build_helper
endef


define delete_folder
	$(call build_build_helper)
	build_helper delete $(1)
endef


define copy_folder_or_file
	$(call build_build_helper)
	build_helper copy $(1) $(2)
endef

BUILD_LOC = bin

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
	go build -o $(BUILD_LOC)/iot-fdo-conformance-tools-windows.exe
	$(call copy_folder_or_file,./build_helper/start_server.bat,./$(BUILD_LOC)/start_server.bat)

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

cleanup_frontend:
	$(call delete_folder,$(BUILD_LOC)/frontend)

# Build frontend
build_frontend:
	echo "\n----- Building frontend... -----\n"
	cd ./frontend && npm run build

	$(call copy_folder_or_file,./frontend/dist,./$(BUILD_LOC)/frontend)

build: cleanup_frontend build_frontend compile_all


FDOTOOLS_BIN_LOC = ~/conformance-test-infrastructure-new/iot-fdo-conformance/
FDOTOOLS_INFRA_LOC = ~/conformance-test-infrastructure-new/

# Build frontend
fdotools__push_new_bin:
	echo "\n----- Updating FDO tools binary... -----\n"
	scp -P ${FDO_BUILD_PUSH_PORT} ./bin/iot-fdo-conformance-tools-linux ${FDO_BUILD_PUSH_HOST}:$(FDOTOOLS_BIN_LOC)

# Build frontend
fdotools__push_new_ui:
	echo "\n----- Updating FDO tools ui... -----\n"
	scp -R ./bin/frontend ${FDO_BUILD_PUSH_HOST}:$(FDOTOOLS_BIN_LOC)

# Build frontend
fdotools__restart_docker_compose:
	echo "\n----- Restarting docker compose... -----\n"
	ssh ${FDO_BUILD_PUSH_HOST} "cd $(FDOTOOLS_INFRA_LOC) && docker-compose up --build --force -d"

# fdotools__restart_docker_update:
