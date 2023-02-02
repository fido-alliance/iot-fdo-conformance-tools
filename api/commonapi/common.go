package commonapi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const CONTENT_TYPE_JSON string = "application/json"

func GenerateCookie(token []byte) *http.Cookie {
	expires := time.Now().Add(14 * 24 * time.Hour)
	cookie := http.Cookie{Name: "session", Value: string(token), Expires: expires, HttpOnly: true, Path: "/api/"}

	return &cookie
}

type FdoConfApiStatus string

const (
	FdoApiStatus_OK     FdoConfApiStatus = "ok"
	FdoApiStatus_Failed FdoConfApiStatus = "failed"
)

type FdoConformanceApiError struct {
	Status       FdoConfApiStatus `json:"status"`
	ErrorMessage string           `json:"errorMessage"`
}

func RespondError(w http.ResponseWriter, errorMessage string, httpErrorCode int) {
	log.Printf("Responding error: %s. HTTP code %d", errorMessage, httpErrorCode)
	errorResponse := FdoConformanceApiError{
		Status:       FdoApiStatus_Failed,
		ErrorMessage: errorMessage,
	}

	errorResponseBytes, _ := json.Marshal(errorResponse)

	w.Header().Set("Content-Type", CONTENT_TYPE_JSON)
	w.WriteHeader(httpErrorCode)
	w.Write(errorResponseBytes)
}

func RespondSuccess(w http.ResponseWriter) {
	errorResponse := FdoConformanceApiError{
		Status:       FdoApiStatus_OK,
		ErrorMessage: "",
	}

	errorResponseBytes, _ := json.Marshal(errorResponse)

	w.Header().Set("Content-Type", CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	w.Write(errorResponseBytes)
}

func RespondSuccessStruct(w http.ResponseWriter, successStruct interface{}) {
	successStructBytes, _ := json.Marshal(successStruct)

	w.Header().Set("Content-Type", CONTENT_TYPE_JSON)
	w.WriteHeader(http.StatusOK)
	w.Write(successStructBytes)
}

func CheckHeaders(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" {
		RespondError(w, "Method not allowed!", http.StatusMethodNotAllowed)
		return false
	}

	receivedContentType := r.Header.Get("Content-Type")
	if receivedContentType != CONTENT_TYPE_JSON {
		RespondError(w, "Unsupported media types!", http.StatusUnsupportedMediaType)
		return false
	}

	return true
}

var countriesMap map[string]string = map[string]string{
	"AW": "Aruba", "AF": "Afghanistan", "AO": "Angola", "AI": "Anguilla", "AX": "\u00c5land Islands", "AL": "Albania", "AD": "Andorra", "AE": "United Arab Emirates", "AR": "Argentina", "AM": "Armenia", "AS": "American Samoa", "AQ": "Antarctica", "TF": "French Southern and Antarctic Lands", "AG": "Antigua and Barbuda", "AU": "Australia", "AT": "Austria", "AZ": "Azerbaijan", "BI": "Burundi", "BE": "Belgium", "BJ": "Benin", "BF": "Burkina Faso", "BD": "Bangladesh", "BG": "Bulgaria", "BH": "Bahrain", "BS": "Bahamas", "BA": "Bosnia and Herzegovina", "BL": "Saint Barth\u00e9lemy", "SH": "Saint Helena, Ascension and Tristan da Cunha", "BY": "Belarus", "BZ": "Belize", "BM": "Bermuda", "BO": "Bolivia", "BQ": "Caribbean Netherlands", "BR": "Brazil", "BB": "Barbados", "BN": "Brunei", "BT": "Bhutan", "BV": "Bouvet Island", "BW": "Botswana", "CF": "Central African Republic", "CA": "Canada", "CC": "Cocos (Keeling) Islands", "CH": "Switzerland", "CL": "Chile", "CN": "China", "CI": "Ivory Coast", "CM": "Cameroon", "CD": "DR Congo", "CG": "Republic of the Congo", "CK": "Cook Islands", "CO": "Colombia", "KM": "Comoros", "CV": "Cape Verde", "CR": "Costa Rica", "CU": "Cuba", "CW": "Cura\u00e7ao", "CX": "Christmas Island", "KY": "Cayman Islands", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DJ": "Djibouti", "DM": "Dominica", "DK": "Denmark", "DO": "Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "EG": "Egypt", "ER": "Eritrea", "EH": "Western Sahara", "ES": "Spain", "EE": "Estonia", "ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji", "FK": "Falkland Islands", "FR": "France", "FO": "Faroe Islands", "FM": "Micronesia", "GA": "Gabon", "GB": "United Kingdom", "GE": "Georgia", "GG": "Guernsey", "GH": "Ghana", "GI": "Gibraltar", "GN": "Guinea", "GP": "Guadeloupe", "GM": "Gambia", "GW": "Guinea-Bissau", "GQ": "Equatorial Guinea", "GR": "Greece", "GD": "Grenada", "GL": "Greenland", "GT": "Guatemala", "GF": "French Guiana", "GU": "Guam", "GY": "Guyana", "HK": "Hong Kong", "HM": "Heard Island and McDonald Islands", "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia", "IM": "Isle of Man", "IN": "India", "IO": "British Indian Ocean Territory", "IE": "Ireland", "IR": "Iran", "IQ": "Iraq", "IS": "Iceland", "IL": "Israel", "IT": "Italy", "JM": "Jamaica", "JE": "Jersey", "JO": "Jordan", "JP": "Japan", "KZ": "Kazakhstan", "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KI": "Kiribati", "KN": "Saint Kitts and Nevis", "KR": "South Korea", "XK": "Kosovo", "KW": "Kuwait", "LA": "Laos", "LB": "Lebanon", "LR": "Liberia", "LY": "Libya", "LC": "Saint Lucia", "LI": "Liechtenstein", "LK": "Sri Lanka", "LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "MO": "Macau", "MF": "Saint Martin", "MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "MG": "Madagascar", "MV": "Maldives", "MX": "Mexico", "MH": "Marshall Islands", "MK": "North Macedonia", "ML": "Mali", "MT": "Malta", "MM": "Myanmar", "ME": "Montenegro", "MN": "Mongolia", "MP": "Northern Mariana Islands", "MZ": "Mozambique", "MR": "Mauritania", "MS": "Montserrat", "MQ": "Martinique", "MU": "Mauritius", "MW": "Malawi", "MY": "Malaysia", "YT": "Mayotte", "NA": "Namibia", "NC": "New Caledonia", "NE": "Niger", "NF": "Norfolk Island", "NG": "Nigeria", "NI": "Nicaragua", "NU": "Niue", "NL": "Netherlands", "NO": "Norway", "NP": "Nepal", "NR": "Nauru", "NZ": "New Zealand", "OM": "Oman", "PK": "Pakistan", "PA": "Panama", "PN": "Pitcairn Islands", "PE": "Peru", "PH": "Philippines", "PW": "Palau", "PG": "Papua New Guinea", "PL": "Poland", "PR": "Puerto Rico", "KP": "North Korea", "PT": "Portugal", "PY": "Paraguay", "PS": "Palestine", "PF": "French Polynesia", "QA": "Qatar", "RE": "R\u00e9union", "RO": "Romania", "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia", "SD": "Sudan", "SN": "Senegal", "SG": "Singapore", "GS": "South Georgia", "SJ": "Svalbard and Jan Mayen", "SB": "Solomon Islands", "SL": "Sierra Leone", "SV": "El Salvador", "SM": "San Marino", "SO": "Somalia", "PM": "Saint Pierre and Miquelon", "RS": "Serbia", "SS": "South Sudan", "ST": "S\u00e3o Tom\u00e9 and Pr\u00edncipe", "SR": "Suriname", "SK": "Slovakia", "SI": "Slovenia", "SE": "Sweden", "SZ": "Eswatini", "SX": "Sint Maarten", "SC": "Seychelles", "SY": "Syria", "TC": "Turks and Caicos Islands", "TD": "Chad", "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan", "TK": "Tokelau", "TM": "Turkmenistan", "TL": "Timor-Leste", "TO": "Tonga", "TT": "Trinidad and Tobago", "TN": "Tunisia", "TR": "Turkey", "TV": "Tuvalu", "TW": "Taiwan", "TZ": "Tanzania", "UG": "Uganda", "UA": "Ukraine", "UM": "United States Minor Outlying Islands", "UY": "Uruguay", "US": "United States", "UZ": "Uzbekistan", "VA": "Vatican City", "VC": "Saint Vincent and the Grenadines", "VE": "Venezuela", "VG": "British Virgin Islands", "VI": "United States Virgin Islands", "VN": "Vietnam", "VU": "Vanuatu", "WF": "Wallis and Futuna", "WS": "Samoa", "YE": "Yemen", "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}

func ExtractCloudflareLocation(r *http.Request) string {
	cfCountryCode := r.Header.Get("CF-IPCountry")

	countryCode := "CLOUDFLARE_TEST"
	if cfCountryCode != "" {
		countryCode = strings.ToUpper(cfCountryCode)
	}

	countryName, ok := countriesMap[countryCode]

	if countryCode == "" {
		countryCode = "UNKNOWN"
	} else if countryCode == "CLOUDFLARE_TEST" {
		countryName = "CLOUDFLARE"
	} else if !ok {
		countryCode = "UNKNOWN"
	}

	return fmt.Sprintf(`%s (%s)`, countryName, countryCode)
}
