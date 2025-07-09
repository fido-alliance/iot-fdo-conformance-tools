package fdoshared

type SIM_ID string

const (
	// REQ | BOOL | Indicates the module is active. Devmod is required on all devices
	SIM_DEVMOD_ACTIVE SIM_ID = "devmod:active"

	// REQ | TSTR | OS name (e.g., Linux)
	SIM_DEVMOD_OS SIM_ID = "devmod:os"

	// REQ | TSTR | Architecture name / instruction set (e.g., X86_64)
	SIM_DEVMOD_ARCH SIM_ID = "devmod:arch"

	// REQ | TSTR | Version of OS (e.g., “Ubuntu* 16.0.4LTS”)
	SIM_DEVMOD_VERSION SIM_ID = "devmod:version"

	// REQ | TSTR | Model specifier for this FIDO Device Onboard Device, manufacturer specific
	SIM_DEVMOD_DEVICE SIM_ID = "devmod:device"

	// OPT | TSTR/BSTR | Serial number for this FIDO Device Onboard Device, manufacturer specific
	SIM_DEVMOD_SN SIM_ID = "devmod:sn"

	// OPT | TSTR | Filename path separator, between the directory and sub-directory (e.g., ‘/’ or ‘\’)
	SIM_DEVMOD_PATHSEP SIM_ID = "devmod:pathsep"

	// REQ | TSTR | Filename separator, that works to make lists of file names (e.g., ‘:’ or ‘;’)
	SIM_DEVMOD_SEP SIM_ID = "devmod:sep"

	// OPT | TSTR | Newline sequence (e.g., a tstr of length 1 containing U+000A; a tstr of length 2 containing U+000D followed by U+000A)
	SIM_DEVMOD_NL SIM_ID = "devmod:nl"

	// OPT | TSTR | Location of temporary directory, including terminating file separator (e.g., “/tmp”)
	SIM_DEVMOD_TMP SIM_ID = "devmod:tmp"

	// OPT | TSTR | Location of suggested installation directory, including terminating file separator (e.g., “.” or “/home/fdo” or “c:\Program Files\fdo”)
	SIM_DEVMOD_DIR SIM_ID = "devmod:dir"

	// OPT | TSTR | Programming environment. See Table 3‑22 (e.g., “bin:java:py3:py2”)
	SIM_DEVMOD_PROGENV SIM_ID = "devmod:progenv"

	// REQ | TSTR | Either the same value as “arch”, or a list of machine formats that can be interpreted by this device, in preference order, separated by the “sep” value (e.g., “x86:X86_64”)
	SIM_DEVMOD_BIN SIM_ID = "devmod:bin"

	// OPT | UINT | URL for the Manufacturer Usage Description file that relates to this device
	SIM_DEVMOD_MUDURL SIM_ID = "devmod:mudurl"

	// REQ | UINT | Number of modules supported by this FIDO Device Onboard Device
	SIM_DEVMOD_NUMMODULES SIM_ID = "devmod:nummodules"

	// REQ | TSTR | Enumerates the modules supported by this FIDO Device Onboard Device. The first element is an integer from zero to devmod:nummodules. The second element is the number of module names to return The subsequent elements are module names. During the initial Device ServiceInfo, the device sends the complete list of modules to the Owner. If the list is long, it might require more than one ServiceInfo message.
	SIM_DEVMOD_MODULES SIM_ID = "devmod:modules"
)

type SIM_IDS []SIM_ID

func (h *SIM_IDS) Contains(id SIM_ID) bool {
	for _, sim := range *h {
		if sim == id {
			return true
		}
	}

	return false
}

func (h *SIM_IDS) FindDelta(other SIM_IDS) SIM_IDS {
	var delta SIM_IDS

	for _, sim := range *h {
		if !other.Contains(sim) {
			delta = append(delta, sim)
		}
	}

	return delta
}

func (h *SIM_IDS) ToString() string {
	var str string = ""

	for _, sim := range *h {
		str += string(sim) + ","
	}

	return str
}

var MANDATORY_SIMS = SIM_IDS{
	SIM_DEVMOD_ACTIVE,
	SIM_DEVMOD_OS,
	SIM_DEVMOD_ARCH,
	SIM_DEVMOD_VERSION,
	SIM_DEVMOD_DEVICE,
	SIM_DEVMOD_SEP,
	SIM_DEVMOD_BIN,
	SIM_DEVMOD_NUMMODULES,
	SIM_DEVMOD_MODULES,
}

// SIM helpers
var (
	CBOR_TRUE  = []byte{0xF5}
	CBOR_FALSE = []byte{0xF4}
)
