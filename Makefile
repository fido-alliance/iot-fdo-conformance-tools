OS := $(if $(findstring Windows_NT,$(OS)),Windows,$(OS))

BUILD_LOC = bin
BUILD_HELPER_LOC := .build_helper
OUTPUT_FILE := $(if $(findstring Windows,$(OS)),build_helper.exe,build_helper)

define build_build_helper
	go build -o $(OUTPUT_FILE) $(BUILD_HELPER_LOC)/main.go
endef

define delete_folder
	$(call build_build_helper)
	./build_helper delete $(1)
endef

define copy_folder_or_file
	$(call build_build_helper)
	./build_helper copy $(1) $(2)
endef

preconfig_frontend:
	echo "\n----- Preconfig: Setting up svelte frontend nodejs dependencies -----\n"

	cd ./frontend && npm i

preconfig_conformance_server:
	echo "\n----- Preconfig: Updating go dependencies -----\n"

	go get

preconfig_dotenv_file:
	echo "\n----- Preconfig: Copying .env.example to .env -----\n"

	cp ./example.env ./.env

setup: preconfig_dotenv_file preconfig_frontend preconfig_conformance_server

# Compiling GO code
compile_win:
	echo "\n----- Building for Windows... -----\n"
	set GOOS=windows
	set GOARCH=amd64
	go build -o $(BUILD_LOC)/iot-fdo-conformance-tools-windows.exe
	$(call copy_folder_or_file,./$(BUILD_HELPER_LOC)/start_server.bat,./$(BUILD_LOC)/start_server.bat)

compile_linux:
	echo "\n----- Building for Linux... -----\n"
	set GOOS=linux
	set GOARCH=amd64
	go env
	go build -o $(BUILD_LOC)/iot-fdo-conformance-tools-linux

compile_osx:
	echo "\n----- Building for MacOS... -----\n"
	set GOOS=darwin
	set GOARCH=amd64
	go build -o $(BUILD_LOC)/iot-fdo-conformance-tools-osx

compile_all: compile_win compile_linux compile_osx

cleanup_frontend:
	$(call delete_folder,./$(BUILD_LOC)/frontend)

# Build frontend
build_frontend:
	echo "\n----- Building frontend... -----\n"
	cd ./frontend && npm run build

	$(call copy_folder_or_file,./frontend/dist,./$(BUILD_LOC)/frontend)

build: cleanup_frontend build_frontend compile_all
