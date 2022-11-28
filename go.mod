module github.com/WebauthnWorks/fdo-fido-conformance-server

go 1.18

require (
	github.com/dgraph-io/badger/v3 v3.2103.4
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/urfave/cli/v2 v2.11.1
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
)

require (
	github.com/WebauthnWorks/fdo-device-implementation v0.3.0
	github.com/WebauthnWorks/fdo-do v0.3.0
	github.com/WebauthnWorks/fdo-rv v0.3.0
)

require (
	github.com/WebauthnWorks/dhkx v0.3.3 // indirect
	github.com/WebauthnWorks/fdo-shared v0.9.6 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/drhodes/golorem v0.0.0-20220328165741-da82e5b29246 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/groupcache v0.0.0-20190702054246-869f871628b6 // indirect
	github.com/golang/protobuf v1.3.1 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/flatbuffers v1.12.1 // indirect
	github.com/klauspost/compress v1.12.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/stretchr/testify v1.5.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.opencensus.io v0.22.5 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/sys v0.0.0-20221010170243-090e33056c14 // indirect
)

// For when you are doing local dev
// replace github.com/WebauthnWorks/fdo-do v0.0.0 => /Users/yuriy/go/src/github.com/WebauthnWorks/fdo-do
// replace github.com/WebauthnWorks/fdo-rv v0.0.0 => /Users/yuriy/go/src/github.com/WebauthnWorks/fdo-rv
// replace github.com/WebauthnWorks/fdo-device-implementation v0.0.0 => /Users/yuriy/go/src/github.com/WebauthnWorks/fdo-device-implementation
// replace github.com/WebauthnWorks/fdo-shared v0.0.0 => /Users/yuriy/go/src/github.com/WebauthnWorks/fdo-shared
