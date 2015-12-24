// Package ssllabs provides methods and structs for working with SSLLabs public API
package ssllabs

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2015 Essential Kaos                         //
//      Essential Kaos Open Source License <http://essentialkaos.com/ekol?en>         //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"errors"
	"strconv"

	"pkg.re/essentialkaos/ek.v1/req"
)

// ////////////////////////////////////////////////////////////////////////////////// //

// API_PRODUCTION Production api
// API_DEVELOPMENT Development api
const (
	API_PRODUCTION  = "https://api.ssllabs.com/api/v2"
	API_DEVELOPMENT = "https://api.dev.ssllabs.com/api/v2"
)

// Base statuses
const (
	STATUS_IN_PROGRESS = "IN_PROGRESS"
	STATUS_DNS         = "DNS"
	STATUS_READY       = "READY"
	STATUS_ERROR       = "ERROR"
)

// ////////////////////////////////////////////////////////////////////////////////// //

type API struct {
	Info       *APIInfo
	entryPoint string
}

type AnalyzeParams struct {
	Private        bool
	StartNew       bool
	FromCache      bool
	MaxAge         int
	All            bool
	IgnoreMismatch bool
}

type AnalyzeProgress struct {
	entryPoint string
	host       string
	prevStatus string
}

// DOCS: https://github.com/ssllabs/ssllabs-scan/blob/stable/ssllabs-api-docs.md

type APIInfo struct {
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
	HostStartTime                  int64               `json:"hostStartTime"`                  // endpoint assessment starting time, in milliseconds since 1970. This field is useful when test results are retrieved in several HTTP invocations. Then, you should check that the hostStartTime value matches the startTime value of the host
	Key                            *KeyInfo            `json:"key"`                            // key information
	Cert                           *CertInfo           `json:"cert"`                           // certificate information
	Chain                          *ChainInfo          `json:"chain"`                          // chain information
	Protocols                      []*ProtocolInfo     `json:"protocols"`                      // supported protocols
	Suites                         *SuitesInfo         `json:"suites"`                         // supported cipher suites
	ServerSignature                string              `json:"serverSignature"`                // contents of the HTTP Server response header when known
	PrefixDelegation               bool                `json:"prefixDelegation"`               // true if this endpoint is reachable via a hostname with the www prefix
	NonPrefixDelegation            bool                `json:"nonPrefixDelegation"`            // true if this endpoint is reachable via a hostname without the www prefix
	VulnBeast                      bool                `json:"vulnBeast"`                      // true if the endpoint is vulnerable to the BEAST attack
	RenegSupport                   int                 `json:"renegSupport"`                   // this is an integer value that describes the endpoint support for renegotiation
	STSStatus                      string              `json:"stsStatus"`                      // -
	STSResponseHeader              string              `json:"stsResponseHeader"`              // the contents of the Strict-Transport-Security (STS) response header, if seen
	STSMaxAge                      int64               `json:"stsMaxAge"`                      // the maxAge parameter extracted from the STS parameters
	STSSubdomains                  bool                `json:"stsSubdomains"`                  // true if the includeSubDomains STS parameter is set
	STSPreload                     bool                `json:"stsPreload"`                     // -
	PKPResponseHeader              string              `json:"pkpResponseHeader"`              // the contents of the Public-Key-Pinning response header
	SessionResumption              int                 `json:"sessionResumption"`              // this is an integer value that describes endpoint support for session resumption
	CompressionMethods             int                 `json:"compressionMethods"`             // integer value that describes supported compression methods
	SupportsNPN                    bool                `json:"supportsNpn"`                    // true if the server supports NPN
	NPNProtocols                   string              `json:"npnProtocols"`                   // space separated list of supported protocols
	SessionTickets                 int                 `json:"sessionTickets"`                 // indicates support for Session Tickets
	OCSPStapling                   bool                `json:"ocspStapling"`                   // true if OCSP stapling is deployed on the server
	StaplingRevocationStatus       int                 `json:"staplingRevocationStatus"`       // same as Cert.revocationStatus, but for the stapled OCSP response
	StaplingRevocationErrorMessage string              `json:"staplingRevocationErrorMessage"` // description of the problem with the stapled OCSP response, if any
	SNIRequired                    bool                `json:"sniRequired"`                    // if SNI support is required to access the web site
	HTTPStatusCode                 int                 `json:"httpStatusCode"`                 // status code of the final HTTP response seen
	HTTPForwarding                 string              `json:"httpForwarding"`                 // available on a server that responded with a redirection to some other hostname
	SupportsRC4                    bool                `json:"supportsRc4"`                    // supportsRc4
	RC4WithModern                  bool                `json:"rc4WithModern"`                  // true if RC4 is used with modern clients
	RC4Only                        bool                `json:"rc4Only"`                        // -
	ForwardSecrecy                 int                 `json:"forwardSecrecy"`                 // indicates support for Forward Secrecy
	SIMS                           *SIMSInfo           `json:"sims"`                           // sims
	Heartbleed                     bool                `json:"heartbleed"`                     // true if the server is vulnerable to the Heartbleed attack
	Heartbeat                      bool                `json:"heartbeat"`                      // true if the server supports the Heartbeat extension
	OpenSslCCS                     int                 `json:"openSslCcs"`                     // results of the CVE-2014-0224 test
	Poodle                         bool                `json:"poodle"`                         // true if the endpoint is vulnerable to POODLE
	PoodleTLS                      int                 `json:"poodleTls"`                      // results of the POODLE TLS test
	FallbackSCSV                   bool                `json:"fallbackScsv"`                   // true if the server supports TLS_FALLBACK_SCSV, false if it doesn't
	Freak                          bool                `json:"freak"`                          // true of the server is vulnerable to the FREAK attack
	HasSCT                         int                 `json:"hasSct"`                         // information about the availability of certificate transparency information (embedded SCTs)
	DHPrimes                       []string            `json:"dhPrimes"`                       // list of hex-encoded DH primes used by the server
	DHUsesKnownPrimes              int                 `json:"dhUsesKnownPrimes"`              // whether the server uses known DH primes
	DHYsReuse                      bool                `json:"dhYsReuse"`                      // true if the DH ephemeral server value is reused
	Logjam                         bool                `json:"logjam"`                         // true if the server uses DH parameters weaker than 1024 bits
	PreloadChecks                  []*PreloadCheckInfo `json:"preloadChecks"`                  // -
}

type KeyInfo struct {
	Size       int    `json:"size"`       // key size, e.g., 1024 or 2048 for RSA and DSA, or 256 bits for EC
	Alg        string `json:"alg"`        // key algorithm; possible values: RSA, DSA, and EC
	DebianFlaw bool   `json:"debianFlaw"` // true if we suspect that the key was generated using a weak random number generator (detected via a blacklist database)
	Strength   int    `json:"strength"`   // key size expressed in RSA bits
	Q          *int   `json:"q"`          // 0 if key is insecure, null otherwise
}

type ChainInfo struct {
	Certs  []*CertInfo `json:"certs"`
	Issues int         `json:"issues"`
}

type CertInfo struct {
	Subject              string   `json:"subject"`              // certificate subject
	Label                string   `json:"label"`                // -
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
	SHA1Hash             string   `json:"sha1Hash"`             // -
	PINSHA256            string   `json:"pinSha256"`            // -
	KeyAlg               string   `json:"keyAlg"`               // -
	KeySize              int      `json:"keySize"`              // -
	KeyStrength          int      `json:"keyStrength"`          // -
	Raw                  string   `json:"raw"`                  // Raw certificate data
}

type ProtocolInfo struct {
	ID               int    `json:"id"`               // protocol version number, e.g. 0x0303 for TLS 1.2
	Name             string `json:"name"`             // protocol name, i.e. SSL or TLS
	Version          string `json:"version"`          // protocol version, e.g. 1.2 (for TLS)
	V2SuitesDisabled bool   `json:"v2SuitesDisabled"` // some servers have SSLv2 protocol enabled, but with all SSLv2 cipher suites disabled
	Q                *int   `json:"q"`                // 0 if the protocol is insecure, null otherwise
}

type SuitesInfo struct {
	List       []*SuiteInfo `json:"list"`
	Preference bool         `json:"preference"`
}

type SuiteInfo struct {
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

type SIMSInfo struct {
	Results []*SIMInfo `json:"results"`
}

type SIMInfo struct {
	Client     *ClientInfo `json:"client"`     // instance of SimClient
	ErrorCode  int         `json:"errorCode"`  // zero if handshake was successful, 1 if it was not
	Attempts   int         `json:"attempts"`   // always 1 with the current implementation
	ProtocolID int         `json:"protocolId"` // Negotiated protocol ID
	SuiteID    int         `json:"suiteId"`    // Negotiated suite ID
}

type ClientInfo struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Platform    string `json:"platform"`
	Version     string `json:"version"`
	IsReference bool   `json:"isReference"` // true if the browser is considered representative of modern browsers, false otherwise
}

type PreloadCheckInfo struct {
	SourceName string `json:"sourceName"`
	Hostname   string `json:"hostname"`
	Status     string `json:"status"`
	SourceTime int64  `json:"sourceTime"`
}

// ////////////////////////////////////////////////////////////////////////////////// //

// NewAPI create new api struct
func NewAPI(entryPoint string) (*API, error) {
	if entryPoint == "" {
		entryPoint = API_PRODUCTION
	}

	api := &API{entryPoint: entryPoint}
	resp, err := req.Request{URL: api.entryPoint + "/info"}.Do()

	if err != nil {
		return nil, err
	}

	info := &APIInfo{}
	err = resp.JSON(info)

	if err != nil {
		return nil, err
	}

	api.Info = info

	return api, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

// Analyze start check for host
func (api *API) Analyze(host string, params ...*AnalyzeParams) (*AnalyzeProgress, error) {
	progress := &AnalyzeProgress{
		entryPoint: api.entryPoint,
		host:       host,
	}

	var query = map[string]string{"host": host}

	if len(params) != 0 {
		appendParamsToQuery(query, params[0])
	}

	resp, err := req.Request{
		URL:   api.entryPoint + "/analyze",
		Query: query,
	}.Do()

	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("API return HTTP code " + strconv.Itoa(resp.StatusCode))
	}

	return progress, nil
}

// Info return short info
func (ap *AnalyzeProgress) Info() (*AnalyzeInfo, error) {
	resp, err := req.Request{
		URL:   ap.entryPoint + "/analyze",
		Query: map[string]string{"host": ap.host},
	}.Do()

	if err != nil {
		return nil, err
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
			return nil, errors.New("Retrieving detailed information possible only with status READY")
		}
	}

	resp, err := req.Request{
		URL: ap.entryPoint + "/getEndpointData",
		Query: map[string]string{
			"host": ap.host,
			"s":    ip,
		},
	}.Do()

	info := &EndpointInfo{}
	err = resp.JSON(info)

	if err != nil {
		return nil, err
	}

	return info, nil
}

// ////////////////////////////////////////////////////////////////////////////////// //

func appendParamsToQuery(query map[string]string, params *AnalyzeParams) {
	if params.Private {
		query["publish"] = "off"
	}

	if params.StartNew {
		query["startNew"] = "on"
	}

	if params.FromCache {
		query["fromCache"] = "on"
	}

	if params.MaxAge != 0 {
		query["maxAge"] = strconv.Itoa(params.MaxAge)
	}

	if params.All {
		query["all"] = "on"
	}

	if params.IgnoreMismatch {
		query["ignoreMismatch"] = "on"
	}
}
