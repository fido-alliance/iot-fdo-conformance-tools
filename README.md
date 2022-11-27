# fdoshared
fdo-shared Golang

A shared common module that hold all crypto, shared structs, and 

## Other modules that use it
- [FDO: DO Service](https://github.com/WebauthnWorks/fdo-do) - Device Onboarding Service with full implementation of FDO DO TO0 and TO2 protocols. It also contains all related tests.
- [FDO: RV Service](https://github.com/WebauthnWorks/fdo-rv) - Rendezvous Service with full implementation of FDO DO TO0 and TO1 protocols. It also contains all related tests.
- [FDO: Device Implementation Service](https://github.com/WebauthnWorks/fdo-device-implementation) - Virtual Device Implementation with full implementation of FDO DO TO1 and TO2 protocols. It also contains all related tests.


## Structure


- `*.crypto.go` - Contains all the crypto and blockchain. DOGE contains as well
    - `hasing.crypto.go` - All the hashing deps
    - `kex.crypto.go` - All the key exchange deps
    - `signing.crypto.go` - All the signing methods 
    - `signing.misc.go` - All the signing structs 
    - `enc.crypto.go` - All the encryption deps
    - `other.crypto.go` - Other little useful methods


- `cmds.go` and `error.go` - All commands and errors registries
- `to0.go`, `to1.go`, and `to2.go` - All commands structs
- `voucher.go` - All voucher related methods and structs

- `conformance.go` - All conformance tests related methods and structs, mostly fuzzers.

- `/testcom` - Common test methods and registries
- `/testcom/request` - Common request dependencies
- `/testcom/listener` - Common listener dependencies
- `/testcom/dbs` - Common test databases
