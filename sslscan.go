// Package sslscan provides methods and structs for working with SSLLabs public API
package sslscan

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2016 Essential Kaos                         //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"fmt"

	"pkg.re/essentialkaos/ek.v5/req"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const (
	_API_URL_INFO     = "https://api.ssllabs.com/api/v2/info"
	_API_URL_ANALYZE  = "https://api.ssllabs.com/api/v2/analyze"
	_API_URL_DETAILED = "https://api.ssllabs.com/api/v2/getEndpointData"
)

const (
	STATUS_IN_PROGRESS = "IN_PROGRESS"
	STATUS_DNS         = "DNS"
	STATUS_READY       = "READY"
	STATUS_ERROR       = "ERROR"
)

const (
	SSLCSC_STATUS_FAILED              = -1
	SSLCSC_STATUS_UNKNOWN             = 0
	SSLCSC_STATUS_NOT_VULNERABLE      = 1
	SSLCSC_STATUS_POSSIBLE_VULNERABLE = 2
	SSLCSC_STATUS_VULNERABLE          = 3
)

const (
	LUCKY_MINUS_STATUS_FAILED         = -1
	LUCKY_MINUS_STATUS_UNKNOWN        = 0
	LUCKY_MINUS_STATUS_NOT_VULNERABLE = 1
	LUCKY_MINUS_STATUS_VULNERABLE     = 2
)

const (
	POODLE_STATUS_TIMEOUT           = -3
	POODLE_STATUS_TLS_NOT_SUPPORTED = -2
	POODLE_STATUS_FAILED            = -1
	POODLE_STATUS_UNKNOWN           = 0
	POODLE_STATUS_NOT_VULNERABLE    = 1
	POODLE_STATUS_VULNERABLE        = 2
)

const (
	REVOCATION_STATUS_NOT_CHECKED            = 0
	REVOCATION_STATUS_REVOKED                = 1
	REVOCATION_STATUS_NOT_REVOKED            = 2
	REVOCATION_STATUS_REVOCATION_CHECK_ERROR = 3
	REVOCATION_STATUS_NO_REVOCATION_INFO     = 4
	REVOCATION_STATUS_INTERNAL_INFO          = 5
)

const (
	HSTS_STATUS_UNKNOWN  = "unknown"
	HSTS_STATUS_ABSENT   = "absent"
	HSTS_STATUS_PRESENT  = "present"
	HSTS_STATUS_INVALID  = "invalid"
	HSTS_STATUS_DISABLED = "disabled"
	HSTS_STATUS_ERROR    = "error"
)

const (
	HPKP_STATUS_UNKNOWN    = "unknown"
	HPKP_STATUS_ABSENT     = "absent"
	HPKP_STATUS_INVALID    = "invalid"
	HPKP_STATUS_DISABLED   = "disabled"
	HPKP_STATUS_INCOMPLETE = "incomplete"
	HPKP_STATUS_VALID      = "valid"
	HPKP_STATUS_ERROR      = "error"
)

const (
	DROWN_STATUS_ERROR                 = "error"
	DROWN_STATUS_UNKNOWN               = "unknown"
	DROWN_STATUS_NOT_CHECKED           = "not_checked"
	DROWN_STATUS_NOT_CHECKED_SAME_HOST = "not_checked_same_host"
	DROWN_STATUS_HANDSHAKE_FAILURE     = "handshake_failure"
	DROWN_STATUS_SSLV2                 = "sslv2"
	DROWN_STATUS_KEY_MATCH             = "key_match"
	DROWN_STATUS_HOSTNAME_MATCH        = "hostname_match"
)

// Package version
const VERSION = 4

// ////////////////////////////////////////////////////////////////////////////////// //

type API struct {
	Info *Info

	engine *req.Engine // Pointer to req.Engine used for all request
}

type AnalyzeParams struct {
	Public         bool
	StartNew       bool
	FromCache      bool
	MaxAge         int
	All            bool
	IgnoreMismatch bool
}

type AnalyzeProgress struct {
	host       string
	prevStatus string

	engine *req.Engine // Pointer to req.Engine used for all request
}

// DOCS: https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md

type Info struct {
	EngineVersion        string   `json:"engineVersion"`        // SSL Labs software version as a string (e.g., "1.11.14")
	CriteriaVersion      string   `json:"criteriaVersion"`      // rating criteria version as a string (e.g., "2009f")
	ClientMaxAssessments int      `json:"clientMaxAssessments"` // -
	MaxAssessments       int      `json:"maxAssessments"`       // the maximum number of concurrent assessments the client is allowed to initiate
	CurrentAssessments   int      `json:"currentAssessments"`   // the number of ongoing assessments submitted by this client
	NewAssessmentCoolOff int      `json:"newAssessmentCoolOff"` // he cool-off period after each new assessment; you're not allowed to submit a new assessment before the cool-off expires, otherwise you'll get a 429
	Messages             []string `json:"messages"`             // a list of messages (strings). Messages can be public (sent to everyone) and private (sent only to the invoking client). Private messages are prefixed with "[Private]".
}

type AnalyzeInfo struct {
	Host            string          `json:"host"`            // assessment host, which can be a hostname or an IP address
	Port            int             `json:"port"`            // assessment port (e.g., 443)
	Protocol        string          `json:"protocol"`        // protocol (e.g., HTTP)
	IsPublic        bool            `json:"isPublic"`        // true if this assessment publicly available (listed on the SSL Labs assessment boards)
	Status          string          `json:"status"`          // assessment status; possible values: DNS, ERROR, IN_PROGRESS, and READY
	StatusMessage   string          `json:"statusMessage"`   // status message in English. When status is ERROR, this field will contain an error message
	StartTime       int64           `json:"startTime"`       // assessment starting time, in milliseconds since 1970
	TestTime        int64           `json:"testTime"`        // assessment completion time, in milliseconds since 1970
	EngineVersion   string          `json:"engineVersion"`   // assessment engine version (e.g., "1.0.120")
	CriteriaVersion string          `json:"criteriaVersion"` // grading criteria version (e.g., "2009")
	Endpoints       []*EndpointInfo `json:"endpoints"`       // list of Endpoint objects
}

type EndpointInfo struct {
	IPAdress             string           `json:"ipAddress"`            // endpoint IP address, in IPv4 or IPv6 format
	ServerName           string           `json:"serverName"`           // server name retrieved via reverse DNS
	Grade                string           `json:"grade"`                // possible values: A+, A-, A-F, T (no trust) and M (certificate name mismatch)
	GradeTrustIgnored    string           `json:"gradeTrustIgnored"`    // grade (as above), if trust issues are ignored
	HasWarnings          bool             `json:"hasWarnings"`          // if this endpoint has warnings that might affect the score (e.g., get A- instead of A).
	IsExceptional        bool             `json:"isExceptional"`        // this flag will be raised when an exceptional configuration is encountered. The SSL Labs test will give such sites an A+
	StatusMessage        string           `json:"statusMessage"`        // assessment status message
	StatusDetails        string           `json:"statusDetails"`        // code of the operation currently in progress
	StatusDetailsMessage string           `json:"statusDetailsMessage"` // description of the operation currently in progress
	Progress             int              `json:"progress"`             // assessment progress, which is a value from 0 to 100, and -1 if the assessment has not yet started
	Duration             int              `json:"duration"`             // assessment duration, in milliseconds
	ETA                  int              `json:"eta"`                  // estimated time, in seconds, until the completion of the assessment
	Delegation           int              `json:"delegation"`           // indicates domain name delegation with and without the www prefix
	Details              *EndpointDetails `json:"details"`              // this field contains an EndpointDetails object. It's not present by default, but can be enabled by using the "all" paramerer to the analyze API call
}

type EndpointDetails struct {
	HostStartTime                  int64          `json:"hostStartTime"`                  // endpoint assessment starting time, in milliseconds since 1970. This field is useful when test results are retrieved in several HTTP invocations. Then, you should check that the hostStartTime value matches the startTime value of the host
	Key                            *Key           `json:"key"`                            // key information
	Cert                           *Cert          `json:"cert"`                           // certificate information
	Chain                          *Chain         `json:"chain"`                          // chain information
	Protocols                      []*Protocol    `json:"protocols"`                      // supported protocols
	Suites                         *Suites        `json:"suites"`                         // supported cipher suites
	ServerSignature                string         `json:"serverSignature"`                // contents of the HTTP Server response header when known
	PrefixDelegation               bool           `json:"prefixDelegation"`               // true if this endpoint is reachable via a hostname with the www prefix
	NonPrefixDelegation            bool           `json:"nonPrefixDelegation"`            // true if this endpoint is reachable via a hostname without the www prefix
	VulnBeast                      bool           `json:"vulnBeast"`                      // true if the endpoint is vulnerable to the BEAST attack
	RenegSupport                   int            `json:"renegSupport"`                   // this is an integer value that describes the endpoint support for renegotiation
	SessionResumption              int            `json:"sessionResumption"`              // this is an integer value that describes endpoint support for session resumption
	CompressionMethods             int            `json:"compressionMethods"`             // integer value that describes supported compression methods
	SupportsNPN                    bool           `json:"supportsNpn"`                    // true if the server supports NPN
	NPNProtocols                   string         `json:"npnProtocols"`                   // space separated list of supported protocols
	SessionTickets                 int            `json:"sessionTickets"`                 // indicates support for Session Tickets
	OCSPStapling                   bool           `json:"ocspStapling"`                   // true if OCSP stapling is deployed on the server
	StaplingRevocationStatus       int            `json:"staplingRevocationStatus"`       // same as Cert.revocationStatus, but for the stapled OCSP response
	StaplingRevocationErrorMessage string         `json:"staplingRevocationErrorMessage"` // description of the problem with the stapled OCSP response, if any
	SNIRequired                    bool           `json:"sniRequired"`                    // if SNI support is required to access the web site
	HTTPStatusCode                 int            `json:"httpStatusCode"`                 // status code of the final HTTP response seen
	HTTPForwarding                 string         `json:"httpForwarding"`                 // available on a server that responded with a redirection to some other hostname
	SupportsRC4                    bool           `json:"supportsRc4"`                    // supportsRc4
	RC4WithModern                  bool           `json:"rc4WithModern"`                  // true if RC4 is used with modern clients
	RC4Only                        bool           `json:"rc4Only"`                        // true if only RC4 suites are supported
	ForwardSecrecy                 int            `json:"forwardSecrecy"`                 // indicates support for Forward Secrecy
	ProtocolIntolerance            int            `json:"protocolIntolerance"`            // indicates protocol version intolerance issues
	MiscIntolerance                int            `json:"miscIntolerance"`                // indicates protocol version intolerance issues
	SIMS                           *SIMS          `json:"sims"`                           // sims
	Heartbleed                     bool           `json:"heartbleed"`                     // true if the server is vulnerable to the Heartbleed attack
	Heartbeat                      bool           `json:"heartbeat"`                      // true if the server supports the Heartbeat extension
	OpenSslCCS                     int            `json:"openSslCcs"`                     // results of the CVE-2014-0224 test
	OpenSSLLuckyMinus20            int            `json:"openSSLLuckyMinus20"`            // results of the CVE-2016-2107 test
	Poodle                         bool           `json:"poodle"`                         // true if the endpoint is vulnerable to POODLE
	PoodleTLS                      int            `json:"poodleTls"`                      // results of the POODLE TLS test
	FallbackSCSV                   bool           `json:"fallbackScsv"`                   // true if the server supports TLS_FALLBACK_SCSV, false if it doesn't
	Freak                          bool           `json:"freak"`                          // true of the server is vulnerable to the FREAK attack
	HasSCT                         int            `json:"hasSct"`                         // information about the availability of certificate transparency information (embedded SCTs)
	DHPrimes                       []string       `json:"dhPrimes"`                       // list of hex-encoded DH primes used by the server
	DHUsesKnownPrimes              int            `json:"dhUsesKnownPrimes"`              // whether the server uses known DH primes
	DHYsReuse                      bool           `json:"dhYsReuse"`                      // true if the DH ephemeral server value is reused
	Logjam                         bool           `json:"logjam"`                         // true if the server uses DH parameters weaker than 1024 bits
	HSTSPolicy                     *HSTSPolicy    `json:"hstsPolicy"`                     // server's HSTS policy
	HSTSPreloads                   []*HSTSPreload `json:"hstsPreloads"`                   // information about preloaded HSTS policies
	HPKPPolicy                     *HPKPPolicy    `json:"hpkpPolicy"`                     // server's HPKP policy
	HPKPRoPolicy                   *HPKPPolicy    `json:"hpkpRoPolicy"`                   // server's HPKP RO (Report Only) policy
	DrownHosts                     []*DrownHost   `json:"drownHosts"`                     // list of drown hosts
	DrownErrors                    bool           `json:"drownErrors"`                    // true if error occurred in drown test
	DrownVulnerable                bool           `json:"drownVulnerable"`                // true if server vulnerable to drown attack
}

type Key struct {
	Size       int    `json:"size"`       // key size, e.g., 1024 or 2048 for RSA and DSA, or 256 bits for EC
	Alg        string `json:"alg"`        // key algorithm; possible values: RSA, DSA, and EC
	DebianFlaw bool   `json:"debianFlaw"` // true if we suspect that the key was generated using a weak random number generator (detected via a blacklist database)
	Strength   int    `json:"strength"`   // key size expressed in RSA bits
	Q          *int   `json:"q"`          // 0 if key is insecure, null otherwise
}

type Chain struct {
	Certs  []*ChainCert `json:"certs"`
	Issues int          `json:"issues"`
}

type Cert struct {
	Subject              string   `json:"subject"`              // certificate subject
	CommonNames          []string `json:"commonNames"`          // common names extracted from the subject
	AltNames             []string `json:"altNames"`             // alternative names
	NotBefore            int64    `json:"notBefore"`            // timestamp before which the certificate is not valid
	NotAfter             int64    `json:"notAfter"`             // timestamp after which the certificate is not valid
	IssuerSubject        string   `json:"issuerSubject"`        // issuer subject
	IssuerLabel          string   `json:"issuerLabel"`          // issuer name
	SigAlg               string   `json:"sigAlg"`               // certificate signature algorithm
	RevocationInfo       int      `json:"revocationInfo"`       // a number that represents revocation information present in the certificate
	CRLURIs              []string `json:"crlURIs"`              // CRL URIs extracted from the certificate
	OCSPURIs             []string `json:"ocspURIs"`             // OCSP URIs extracted from the certificate
	RevocationStatus     int      `json:"revocationStatus"`     // a number that describes the revocation status of the certificate
	CRLRevocationStatus  int      `json:"crlRevocationStatus"`  // same as revocationStatus, but only for the CRL information (if any)
	OCSPRevocationStatus int      `json:"ocspRevocationStatus"` // same as revocationStatus, but only for the OCSP information (if any)
	SGC                  int      `json:"sgc"`                  // Server Gated Cryptography support
	ValidationType       string   `json:"validationType"`       // E for Extended Validation certificates; may be nil if unable to determine
	Issues               int      `json:"issues"`               // list of certificate issues, one bit per issue
	SCT                  bool     `json:"sct"`                  // true if the certificate contains an embedded SCT
	MustStaple           int      `json:"mustStaple"`           // a number that describes the must staple feature extension status
	SHA1Hash             string   `json:"sha1Hash"`             // -
	PINSHA256            string   `json:"pinSha256"`            // -
}

type ChainCert struct {
	Subject              string `json:"subject"`              // certificate subject
	Label                string `json:"label"`                // certificate label (user-friendly name)
	NotBefore            int64  `json:"notBefore"`            // timestamp before which the certificate is not valid
	NotAfter             int64  `json:"notAfter"`             // timestamp after which the certificate is not valid
	IssuerSubject        string `json:"issuerSubject"`        // issuer subject
	IssuerLabel          string `json:"issuerLabel"`          // issuer name
	SigAlg               string `json:"sigAlg"`               // certificate signature algorithm
	Issues               int    `json:"issues"`               // list of certificate issues, one bit per issue
	KeyAlg               string `json:"keyAlg"`               // key algorithm
	KeySize              int    `json:"keySize"`              // key size, in bits appropriate for the key algorithm
	KeyStrength          int    `json:"keyStrength"`          // key strength, in equivalent RSA bits
	RevocationStatus     int    `json:"revocationStatus"`     // a number that describes the revocation status of the certificate
	CRLRevocationStatus  int    `json:"crlRevocationStatus"`  // same as revocationStatus, but only for the CRL information (if any)
	OCSPRevocationStatus int    `json:"ocspRevocationStatus"` // same as revocationStatus, but only for the OCSP information (if any)
	Raw                  string `json:"raw"`                  // Raw certificate data
	SHA1Hash             string `json:"sha1Hash"`             // -
	PINSHA256            string `json:"pinSha256"`            // -
}

type Protocol struct {
	ID               int    `json:"id"`               // protocol version number, e.g. 0x0303 for TLS 1.2
	Name             string `json:"name"`             // protocol name, i.e. SSL or TLS
	Version          string `json:"version"`          // protocol version, e.g. 1.2 (for TLS)
	V2SuitesDisabled bool   `json:"v2SuitesDisabled"` // some servers have SSLv2 protocol enabled, but with all SSLv2 cipher suites disabled
	Q                *int   `json:"q"`                // 0 if the protocol is insecure, null otherwise
}

type Suites struct {
	List       []*Suite `json:"list"`
	Preference bool     `json:"preference"`
}

type Suite struct {
	ID             int    `json:"id"`             // suite RFC ID (e.g., 5)
	Name           string `json:"name"`           // suite name (e.g., TLS_RSA_WITH_RC4_128_SHA)
	CipherStrength int    `json:"cipherStrength"` // suite strength (e.g., 128)
	DHStrength     int    `json:"dhStrength"`     // strength of DH params (e.g., 1024)
	DHP            int    `json:"dhP"`            // DH params, p component
	DHG            int    `json:"dhG"`            // DH params, g component
	DHYs           int    `json:"dhYs"`           // DH params, Ys component
	ECDHBits       int    `json:"ecdhBits"`       // ECDH bits
	ECDHStrength   int    `json:"ecdhStrength"`   // ECDH RSA-equivalent strength
	Q              *int   `json:"q"`              // 0 if the suite is insecure, null otherwise
}

type SIMS struct {
	Results []*SIM `json:"results"`
}

type SIM struct {
	Client     *SimClient `json:"client"`     // instance of SimClient
	ErrorCode  int        `json:"errorCode"`  // zero if handshake was successful, 1 if it was not
	Attempts   int        `json:"attempts"`   // always 1 with the current implementation
	ProtocolID int        `json:"protocolId"` // Negotiated protocol ID
	SuiteID    int        `json:"suiteId"`    // Negotiated suite ID
	KXInfo     string     `json:"kxInfo"`     // key exchange info
}

type SimClient struct {
	ID          int    `json:"id"`          // unique client ID
	Name        string `json:"name"`        // some text
	Platform    string `json:"platform"`    // some text
	Version     string `json:"version"`     // some text
	IsReference bool   `json:"isReference"` // true if the browser is considered representative of modern browsers, false otherwise
}

type HSTSPolicy struct {
	LongMaxAge        int               `json:"LONG_MAX_AGE"`      // this constant contains what SSL Labs considers to be sufficiently large max-age value
	Header            string            `json:"header"`            // the contents of the HSTS response header, if present
	Status            string            `json:"status"`            // HSTS status
	Error             string            `json:"error"`             // error message when error is encountered, null otherwise
	MaxAge            int64             `json:"maxAge"`            // the max-age value specified in the policy; null if policy is missing or invalid or on parsing error
	IncludeSubDomains bool              `json:"includeSubDomains"` // true if the includeSubDomains directive is set; null otherwise
	Preload           bool              `json:"preload"`           // true if the preload directive is set; null otherwise
	Directives        map[string]string `json:"directives"`        // list of raw policy directives
}

type HSTSPreload struct {
	Source     string `json:"source"`     // source name
	Hostname   string `json:"hostname"`   // host name
	Status     string `json:"status"`     // preload status
	SourceTime int64  `json:"sourceTime"` // time, as a Unix timestamp, when the preload database was retrieved
}

type HPKPPolicy struct {
	Header            string       `json:"header"`            // the contents of the HPKP response header, if present
	Status            string       `json:"status"`            // HPKP status
	MaxAge            int64        `json:"maxAge"`            // the max-age value from the policy
	IncludeSubDomains bool         `json:"includeSubDomains"` // true if the includeSubDomains directive is set; null otherwise
	ReportURI         string       `json:"reportUri"`         // the report-uri value from the policy
	Pins              []*Pin       `json:"pins"`              // list of all pins used by the policy
	MatchedPins       []*Pin       `json:"matchedPins"`       // list of pins that match the current configuration
	Directives        []*Directive `json:"directives"`        // list of raw policy directives
}

type Pin struct {
	HashFunction string `json:"hashFunction"`
	Value        string `json:"value"`
}

type Directive struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DrownHost struct {
	IP      string `json:"ip"`      // Ip address of server that shares same RSA-Key/hostname in its certificate
	Export  bool   `json:"export"`  // true if export cipher suites detected
	Port    int    `json:"port"`    // port number of the server
	Special bool   `json:"special"` // true if vulnerable OpenSSL version detected
	SSLv2   bool   `json:"sslv2"`   // true if SSL v2 is supported
	Status  string `json:"status"`  // drown host status
}

// ////////////////////////////////////////////////////////////////////////////////// //

// NewAPI create new api struct
func NewAPI(app, version string) (*API, error) {
	if app == "" {
		return nil, fmt.Errorf("App name can't be empty")
	}

	engine := &req.Engine{}

	engine.SetUserAgent(app, version, fmt.Sprintf("SSLScan/%d", VERSION))

	resp, err := engine.Get(req.Request{URL: _API_URL_INFO})

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API return HTTP code %d", resp.StatusCode)
	}

	info := &Info{}
	err = resp.JSON(info)

	if err != nil {
		return nil, err
	}

	return &API{Info: info, engine: engine}, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Analyze start check for host
func (api *API) Analyze(host string, params ...AnalyzeParams) (*AnalyzeProgress, error) {
	progress := &AnalyzeProgress{host: host, engine: api.engine}
	query := req.Query{"host": host}

	if len(params) != 0 {
		appendParamsToQuery(query, params[0])
	}

	resp, err := api.engine.Get(req.Request{
		URL:   _API_URL_ANALYZE,
		Query: query,
	})

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API return HTTP code %d", resp.StatusCode)
	}

	return progress, nil
}

// Info return short info
func (ap *AnalyzeProgress) Info() (*AnalyzeInfo, error) {
	resp, err := ap.engine.Get(req.Request{
		URL:   _API_URL_ANALYZE,
		Query: req.Query{"host": ap.host},
	})

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API return HTTP code %d", resp.StatusCode)
	}

	info := &AnalyzeInfo{}
	err = resp.JSON(info)

	if err != nil {
		return nil, err
	}

	ap.prevStatus = info.Status

	return info, nil
}

// DetailedInfo return detailed endpoint info
func (ap *AnalyzeProgress) DetailedInfo(ip string) (*EndpointInfo, error) {
	if ap.prevStatus != STATUS_READY {
		ap.Info()

		if ap.prevStatus != STATUS_READY {
			return nil, fmt.Errorf("Retrieving detailed information possible only with status READY")
		}
	}

	resp, err := ap.engine.Get(req.Request{
		URL:   _API_URL_DETAILED,
		Query: req.Query{"host": ap.host, "s": ip},
	})

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API return HTTP code %d", resp.StatusCode)
	}

	info := &EndpointInfo{}
	err = resp.JSON(info)

	if err != nil {
		return nil, err
	}

	return info, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

func appendParamsToQuery(query req.Query, params AnalyzeParams) {
	if params.Public {
		query["publish"] = "on"
	}

	if params.StartNew {
		query["startNew"] = "on"
	}

	if params.FromCache {
		query["fromCache"] = "on"
	}

	if params.MaxAge != 0 {
		query["maxAge"] = fmt.Sprintf("%d", params.MaxAge)
	}

	if params.All {
		query["all"] = "on"
	}

	if params.IgnoreMismatch {
		query["ignoreMismatch"] = "on"
	}
}
