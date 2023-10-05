FIDO Device Onboarding Conformance Server
-----

## General info

FDO conformance tools are build in Golang for the backend, and Svelte NodeJS frontend framework for the frontend. Uses on disk key-value DB, so you do not need SQL or Mongo to run it.

For interop documentation follow here: [https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop](https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop)

The backend consists of five modules:
- [Core](https://github.com/fido-alliance/fdo-fido-conformance-server/tree/main/core) - contains all core protocol submodules, such as RV, DO, Device, and Shared.
    + [FDO: Shared](https://github.com/fido-alliance/fdo-fido-conformance-server/tree/main/core/shared) - a common module for all FDO operations that has all the crypto, structs definitions, and registry for commands, codes, and algorithms.
    + [FDO: DO Service](https://github.com/fido-alliance/fdo-fido-conformance-server/tree/main/core/do) - Device Onboarding Service with full implementation of FDO DO TO0 and TO2 protocols. It also contains all related tests.
    + [FDO: RV Service](https://github.com/fido-alliance/fdo-fido-conformance-server/tree/main/core/rv) - Rendezvous Service with full implementation of FDO DO TO0 and TO1 protocols. It also contains all related tests.
    + [FDO: Device Implementation Service](https://github.com/fido-alliance/fdo-fido-conformance-server/tree/main/core/device) - Virtual Device Implementation with full implementation of FDO DO TO1 and TO2 protocols. It also contains all related tests.

- [FIDO Conformance Server](https://github.com/fido-alliance/fdo-fido-conformance-server) - A user facing conformance server. Has testing structs, conformance APIs, conformance tests ID and much much more.
- [FIDO Conformance Server - Frontend](https://github.com/fido-alliance/fdo-fido-conformance-server/tree/main/frontend) - A frontend for FIDO Conformance Server

## Pre requisites:

- Node JS 18+ https://nodejs.org/en/
- Golang 1.18+ https://go.dev/dl/
- Github access with configured SSH key https://docs.github.com/en/authentication/connecting-to-github-with-ssh
- (Windows) `make` - https://gnuwin32.sourceforge.net/packages/make.htm

## Configuration:

- `make setup` - will configure submodule, frontend nodejs deps, and goland packages
    - `make preconfig_submodules` - Will only initialize git submodules, and pull latest updates
    - `make preconfig_frontend` - Will only configure frontend nodejs deps
    - `make preconfig_conformance_server` - Will only configure golang dependencies

## Building

- `make build` - will compile builds for Windows, Linux, and MacOS

- `make compile_all` - will only generate binaries for Windows, Linux, and MacOS
    - `make compile_win` - will only generate Windows binary
    - `make compile_linux` - will only generate Linux binary
    - `make compile_osx` - will only generate MacOS binary

- `make build_frontend` - will only regenerate static frontend

## Running

For the onprem running now enviroment, except for `GODEBUG=x509sha1=1` env, is needed.
For online deployment, take `example.env`. Set required variables, and rename to `.env`

- `./fdo-fido-conformance-server-OS seed` will generate testing config, and pre-seed testing device credentials. This will take just a minute to run. Need to be run only once
- `./fdo-fido-conformance-server-OS serve` will serve testing frontend on port 8080 (http://localhost:8080/)[http://localhost:8080/]
    - If you experience issues with SHA1 checking, please run with `GODEBUG=x509sha1=1` env

## Development

- `git submodule init` - Will init git submodules. Only needed first time setup
- `git submodule update` - Will pull latest changes

- `go get` - Will pull all golang dependencies
- `npm i` - In frontend to install frontend dependencies
- `go build` - Build code
- `GOOS=linux GOARCH=amd64 go build` - Build for Linux x86 64bit architecture. More values here: https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63

To update packages without GOSUM check use env `GOSUMDB=off`

 * Example `GOSUMDB=off go get github.com/fido-alliance/fdo-fido-conformance-server/core/device`
 * To update all `make update_fdo_packages`

## Interop

You can find interop documentation here: https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop

### Structure

- `/dbs` - Contains database structs and menthods. To see db entry structs see `*.structs.db.go`
- `/externalapi` - User facing APIs
    - `common.go` - Contains common request response methods
    - `server.go` - Contains all routing
    - `do.api.go`, `rv.api.go`, `device.api.go` - Contain DO/RV/Device conformance test, user facing APIs. 
    - `user.api.go` - Contain user management APIs. 

- `/testexec` - Contains TO0 DO, TO1 Device, TO2 Device conformance testing execution.

- `/core` - Core implementations of RV, DO, Device see [General Info](#general-info)

- [FDO: Shared /testcom/](https://github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/) - Contains common test methods, dbs, etc
- [FDO: Shared /testcom/listener](https://github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/listener) - Contains all listener tests dependencies for `RV(TO0)`, `RV(TO1)`, and `DO(TO2)`
- [FDO: Shared /testcom/request](https://github.com/fido-alliance/fdo-fido-conformance-server/core/shared/testcom/request) - Contains all requestor tests dependencies for `DO(TO0)`, `Device(TO1)`, `Device(TO2)`

- `/frontend` - Contains frontend git submodule. See https://github.com/fido-alliance/fdo-fido-conformance-frontend

- `running.ctx.go` - Contain default context values

### Common issues

- If you have issues with `WebAuthnWorks` legacy repositories

> Run `go clean -modcache && go get`

 - I am getting `insecure algorithm SHA1-RSA`

> Try running with environment variable `GODEBUG=x509sha1=1`

 

### [License](LICENSE.md)

This code is licensed under the Apache License 2.0. Please see the [License](LICENSE.md) for more information.
