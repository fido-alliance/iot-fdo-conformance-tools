package fdoshared

import (
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

type CoseTagged uint64

const COSE_SIGNATURE_TAGGED CoseTagged = 18
const COSE_ENCRYPT_TAGGED CoseTagged = 16
const COSE_MAC_TAGGED CoseTagged = 17

type CBOR_CUSTOM_TAGS struct {
}

func (h CBOR_CUSTOM_TAGS) getTags() cbor.TagSet {
	var customTags cbor.TagSet = cbor.NewTagSet()
	customTags.Add(
		cbor.TagOptions{
			EncTag: cbor.EncTagRequired,
			DecTag: cbor.DecTagRequired,
		},
		reflect.TypeOf(CoseSignature{}),
		uint64(COSE_SIGNATURE_TAGGED),
	)

	customTags.Add(
		cbor.TagOptions{
			EncTag: cbor.EncTagRequired,
			DecTag: cbor.DecTagRequired,
		},
		reflect.TypeOf(COSEMacStructure{}),
		uint64(COSE_MAC_TAGGED),
	)

	customTags.Add(
		cbor.TagOptions{
			EncTag: cbor.EncTagRequired,
			DecTag: cbor.DecTagRequired,
		},
		reflect.TypeOf(ETMInnerBlock{}),
		uint64(COSE_ENCRYPT_TAGGED),
	)

	return customTags
}

func (h *CBOR_CUSTOM_TAGS) Unmarshal(data []byte, v interface{}) error {
	dm, _ := cbor.DecOptions{}.DecModeWithTags(h.getTags())
	return dm.Unmarshal(data, v)
}

func (h *CBOR_CUSTOM_TAGS) Marshal(v interface{}) ([]byte, error) {
	em, _ := cbor.EncOptions{}.EncModeWithTags(h.getTags())
	return em.Marshal(v)
}

var CborCust CBOR_CUSTOM_TAGS = CBOR_CUSTOM_TAGS{}
