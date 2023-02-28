module github.com/fido-alliance/fdo-fido-conformance-server

go 1.18

require (
	github.com/dgraph-io/badger/v3 v3.2103.5
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/urfave/cli/v2 v2.23.7
	golang.org/x/crypto v0.4.0
)

require (
	github.com/fido-alliance/fdo-device-implementation v0.3.1
	github.com/fido-alliance/fdo-do v0.3.1
	github.com/fido-alliance/fdo-rv v0.3.1
	github.com/fido-alliance/fdo-shared v0.9.85
	golang.org/x/oauth2 v0.3.0
)

require (
	github.com/fido-alliance/dhkx v0.3.3 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/drhodes/golorem v0.0.0-20220328165741-da82e5b29246 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/flatbuffers v22.11.23+incompatible // indirect
	github.com/klauspost/compress v1.15.13 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	go.opencensus.io v0.24.0 // indirect
	golang.org/x/net v0.4.0 // indirect
	golang.org/x/sys v0.3.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)

// For when you are doing local dev
// replace github.com/fido-alliance/fdo-do v0.0.0 => /Users/yuriy/go/src/github.com/fido-alliance/fdo-do
// replace github.com/fido-alliance/fdo-rv v0.0.0 => /Users/yuriy/go/src/github.com/fido-alliance/fdo-rv
// replace github.com/fido-alliance/fdo-device-implementation v0.0.0 => /Users/yuriy/go/src/github.com/fido-alliance/fdo-device-implementation
// replace github.com/fido-alliance/fdo-shared v0.0.0 => /Users/yuriy/go/src/github.com/fido-alliance/fdo-shared
