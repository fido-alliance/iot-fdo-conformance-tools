FIDO Device Onboarding Conformance Server
-----

## General info

FDO conformance tools are build in Golang for the backend, and Svelte NodeJS frontend framework for the frontend. Uses on disk key-value DB, so you do not need SQL or Mongo to run it.

**For interop documentation visit resources:** [https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop](https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop)

The backend consists of five modules:
- [Core](https://github.com/fido-alliance/iot-fdo-conformance-tools/tree/main/core) - contains all core protocol submodules, such as RV, DO, Device, and Shared.
    + [FDO: Shared](https://github.com/fido-alliance/iot-fdo-conformance-tools/tree/main/core/shared) - a common module for all FDO operations that has all the crypto, structs definitions, and registry for commands, codes, and algorithms.
    + [FDO: DO Service](https://github.com/fido-alliance/iot-fdo-conformance-tools/tree/main/core/do) - Device Onboarding Service with full implementation of FDO DO TO0 and TO2 protocols. It also contains all related tests.
    + [FDO: RV Service](https://github.com/fido-alliance/iot-fdo-conformance-tools/tree/main/core/rv) - Rendezvous Service with full implementation of FDO DO TO0 and TO1 protocols. It also contains all related tests.
    + [FDO: Device Implementation Service](https://github.com/fido-alliance/iot-fdo-conformance-tools/tree/main/core/device) - Virtual Device Implementation with full implementation of FDO DO TO1 and TO2 protocols. It also contains all related tests.

- [FIDO Conformance Server](https://github.com/fido-alliance/iot-fdo-conformance-tools) - A user facing conformance server. Has testing structs, conformance APIs, conformance tests ID and much much more.
- [FIDO Conformance Server - Frontend](https://github.com/fido-alliance/iot-fdo-conformance-tools/tree/main/frontend) - A frontend for FIDO Conformance Server

## Pre requisites:

- Node JS 18+ https://nodejs.org/en/
- Golang 1.18+ https://go.dev/dl/
- Github access with configured SSH key https://docs.github.com/en/authentication/connecting-to-github-with-ssh
- (Windows) `make` - https://community.chocolatey.org/packages/make

## Configuration:

- `make setup` - will configure submodule, frontend nodejs deps, and goland packages
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

- `./iot-fdo-conformance-tools-{OS} seed` will generate testing config, and pre-seed testing device credentials. This will take just a minute to run. Need to be run only once
- `./iot-fdo-conformance-tools-{OS} serve` will serve testing frontend on port 8080 (http://localhost:8080/)[http://localhost:8080/]
    - If you experience issues with SHA1 checking, please run with `GODEBUG=x509sha1=1` env

## Development

- `git submodule init` - Will init git submodules. Only needed first time setup
- `git submodule update` - Will pull latest changes

- `go get` - Will pull all golang dependencies
- `npm i` - In frontend to install frontend dependencies
- `go build` - Build code
- `GOOS=linux GOARCH=amd64 go build` - Build for Linux x86 64bit architecture. More values here: https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63

To update packages without GOSUM check use env `GOSUMDB=off`

 * Example `GOSUMDB=off go get github.com/fido-alliance/iot-fdo-conformance-tools/core/device`
 * To update all `make update_fdo_packages`

## Interop

You can find interop documentation here: https://github.com/fido-alliance/conformance-test-tools-resources/tree/master/docs/FDO/Pre-Interop

## Virtual Device Usage

- `./fdo-fido-conformance-server iop generate` - Will generate test credentials for virtual device credentail `./_dis` and voucher `./_vouchers` files. 

Example output:
```bash
$./fdo-fido-conformance-server iop generate
2024/02/26 22:10:17 Successfully generate voucher and di files.
2024/02/26 22:10:17 ./_vouchers/2024-02-26_22.10.57f1d0fd00184e4eab8c71d465f934f2c7.voucher.pem
2024/02/26 22:10:17 ./_dis/2024-02-26_22.10.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
```

- `./fdo-fido-conformance-server iop to1 http://localhost:8080/ _dis/2024-02-26_22.10.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem` - Will start TO1 protocol testing to the server with the specified virtual device credential.

```bash
➜  iot-fdo-conformance-tools git:(main) ✗ ./iot-fdo-conformance-tools iop to1 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem  
2024/02/26 22:41:52 Error running ProveToRV32. RVRedirect33: Received FDO Error: FDO Error: 101, 32, Error to verify signature ProveToRV32 , 1708940512, 4664021194176952107
➜  iot-fdo-conformance-tools git:(main) ✗ ./iot-fdo-conformance-tools iop to1 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:41:53 Error running ProveToRV32. RVRedirect33: Received FDO Error: FDO Error: 101, 32, Error to verify signature ProveToRV32 , 1708940513, 8805323990583729210
➜  iot-fdo-conformance-tools git:(main) ✗ ./iot-fdo-conformance-tools iop to1 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:41:54 Error running ProveToRV32. RVRedirect33: Received FDO Error: FDO Error: 101, 32, Error to verify signature ProveToRV32 , 1708940514, 1372373267534261332
➜  iot-fdo-conformance-tools git:(main) ✗ ./iot-fdo-conformance-tools iop to1 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:43:07 Success  DNS: localhost Port: 8080
➜  iot-fdo-conformance-tools git:(main) ✗ ./iot-fdo-conformance-tools iop to1 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:43:09 Success  DNS: localhost Port: 8080
```

- `./fdo-fido-conformance-server iop to2 http://localhost:8080/ _dis/2024-02-26_22.10.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem` - Will start TO2 calls against the server with the specified virtual device credential.

```bash
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:50 Starting HelloDevice60
2024/02/26 22:45:50 Error running HelloDevice60. HelloDevice60: Unknown Header HMac. failed to verify HMAC. HMACs do not match
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:52 Starting HelloDevice60
2024/02/26 22:45:52 Error running HelloDevice60. HelloDevice60: DO returned wrong NonceTO2ProveOV
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:53 Starting HelloDevice60
2024/02/26 22:45:53 Error running HelloDevice60. HelloDevice60: Failed SigInfo check. sgTypes don't match
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:55 Starting HelloDevice60
2024/02/26 22:45:55 Error running HelloDevice60. HelloDevice60: Failed to verify hello device Hash
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:56 Starting HelloDevice60
2024/02/26 22:45:56 Error running HelloDevice60. failed to verify signature
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:57 Starting HelloDevice60
2024/02/26 22:45:57 Error running HelloDevice60. error decoding FdoError cbor: 499 bytes of extraneous data starting at index 1
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:57 Starting HelloDevice60
2024/02/26 22:45:57 Error running HelloDevice60. HelloDevice60: Failed to unmarshal ProveOVHdr61. cbor: 694 bytes of extraneous data starting at index 1
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:58 Starting HelloDevice60
2024/02/26 22:45:58 Requesting GetOVNextEntry62 for entry 0 
2024/02/26 22:45:58 GetOVNextEntry62: Unauthorized! Missing authorization header!
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:45:59 Starting HelloDevice60
2024/02/26 22:45:59 Requesting GetOVNextEntry62 for entry 0 
2024/02/26 22:45:59 Requesting GetOVNextEntry62 for entry 1 
2024/02/26 22:45:59 GetOVNextEntry64: Failed to unmarshal OVNextEntry63. error decoding FdoError cbor: 243 bytes of extraneous data starting at index 4
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:46:00 Starting HelloDevice60
2024/02/26 22:46:00 Requesting GetOVNextEntry62 for entry 0 
2024/02/26 22:46:00 Server retured wrong entry. Expected 0. Got 247
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:46:00 Starting HelloDevice60
2024/02/26 22:46:00 Requesting GetOVNextEntry62 for entry 0 
2024/02/26 22:46:00 Requesting GetOVNextEntry62 for entry 1 
2024/02/26 22:46:00 Requesting GetOVNextEntry62 for entry 2 
2024/02/26 22:46:00 Requesting GetOVNextEntry62 for entry 3 
2024/02/26 22:46:00 Requesting GetOVNextEntry62 for entry 4 
2024/02/26 22:46:00 Starting ProveDevice64
2024/02/26 22:46:00 ProveDevice64: NonceTO2SetupDv64 nonces don't match...
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:46:01 Starting HelloDevice60
2024/02/26 22:46:01 Requesting GetOVNextEntry62 for entry 0 
2024/02/26 22:46:01 Requesting GetOVNextEntry62 for entry 1 
2024/02/26 22:46:01 Requesting GetOVNextEntry62 for entry 2 
2024/02/26 22:46:01 Requesting GetOVNextEntry62 for entry 3 
2024/02/26 22:46:01 Requesting GetOVNextEntry62 for entry 4 
2024/02/26 22:46:01 Starting ProveDevice64
2024/02/26 22:46:01 ProveDevice64: Error decoding SetupDevice65 Payload... error decoding FdoError unexpected EOF
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:46:14 Starting HelloDevice60
2024/02/26 22:46:14 Requesting GetOVNextEntry62 for entry 0 
2024/02/26 22:46:14 Requesting GetOVNextEntry62 for entry 1 
2024/02/26 22:46:14 Requesting GetOVNextEntry62 for entry 2 
2024/02/26 22:46:14 Requesting GetOVNextEntry62 for entry 3 
2024/02/26 22:46:14 Requesting GetOVNextEntry62 for entry 4 
2024/02/26 22:46:14 Starting ProveDevice64
2024/02/26 22:46:14 Starting DeviceServiceInfoReady66
2024/02/26 22:46:14 DeviceServiceInfoReady66: Error decrypting... Error decrypting EMB GCM. cipher: message authentication failed
➜  fdo-fido-conformance-server git:(main) ✗ ./iot-fdo-conformance-tools iop to2 http://localhost:8080 ./_dis/2024-02-26_22.39.57f1d0fd00184e4eab8c71d465f934f2c7.dis.pem
2024/02/26 22:46:15 Starting HelloDevice60
2024/02/26 22:46:15 Requesting GetOVNextEntry62 for entry 0 
2024/02/26 22:46:15 Requesting GetOVNextEntry62 for entry 1 
2024/02/26 22:46:15 Requesting GetOVNextEntry62 for entry 2 
2024/02/26 22:46:15 Requesting GetOVNextEntry62 for entry 3 
2024/02/26 22:46:15 Requesting GetOVNextEntry62 for entry 4 
2024/02/26 22:46:15 Starting ProveDevice64
2024/02/26 22:46:15 Starting DeviceServiceInfoReady66
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:active
2024/02/26 22:46:15 f5
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:os
2024/02/26 22:46:15 6664617277696e
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:arch
2024/02/26 22:46:15 6561726d3634
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:version
2024/02/26 22:46:15 68676f312e32312e33
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:device
2024/02/26 22:46:15 78224649444f20446576696365204f6e626f617264205669727475616c20446576696365
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:sep
2024/02/26 22:46:15 613b
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:bin
2024/02/26 22:46:15 6561726d3634
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:nummodules
2024/02/26 22:46:15 01
2024/02/26 22:46:15 Sending DeviceServiceInfo68 for sim devmod:modules
2024/02/26 22:46:15 8301016d6669646f5f616c6c69616e6365
2024/02/26 22:46:15 Starting Done70
2024/02/26 22:46:15 Success To2
2024/02/26 22:46:15 IOP logger not found in owner sims
```


### Structure

- `/dbs` - Contains database structs and menthods. To see db entry structs see `*.structs.db.go`
- `/externalapi` - User facing APIs
    - `common.go` - Contains common request response methods
    - `server.go` - Contains all routing
    - `do.api.go`, `rv.api.go`, `device.api.go` - Contain DO/RV/Device conformance test, user facing APIs. 
    - `user.api.go` - Contain user management APIs. 

- `/testexec` - Contains TO0 DO, TO1 Device, TO2 Device conformance testing execution.

- `/core` - Core implementations of RV, DO, Device see [General Info](#general-info)

- [FDO: Shared /testcom/](https://github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/) - Contains common test methods, dbs, etc
- [FDO: Shared /testcom/listener](https://github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/listener) - Contains all listener tests dependencies for `RV(TO0)`, `RV(TO1)`, and `DO(TO2)`
- [FDO: Shared /testcom/request](https://github.com/fido-alliance/iot-fdo-conformance-tools/core/shared/testcom/request) - Contains all requestor tests dependencies for `DO(TO0)`, `Device(TO1)`, `Device(TO2)`

- `/frontend` - Contains frontend git submodule. See https://github.com/fido-alliance/fdo-fido-conformance-frontend

- `running.ctx.go` - Contain default context values

### Common issues

- If you have issues with `WebAuthnWorks` legacy repositories

> Run `go clean -modcache && go get`

 - I am getting `insecure algorithm SHA1-RSA`

> Try running with environment variable `GODEBUG=x509sha1=1`

 

### [License](LICENSE.md)

This code is licensed under the Apache License 2.0. Please see the [License](LICENSE.md) for more information.
