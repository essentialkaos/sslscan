package sslscan

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                         Copyright (c) 2024 ESSENTIAL KAOS                          //
//      Apache License, Version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>     //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"fmt"
	"os"
	"testing"
	"time"

	check "github.com/essentialkaos/check"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const (
	_TESTER_VERSION = "11.0.0"
	_TESTER_EMAIL   = "jdoe@someoraganizationemail.com"
)

// ////////////////////////////////////////////////////////////////////////////////// //

func Test(t *testing.T) { check.TestingT(t) }

type SSLLabsSuite struct{}

// ////////////////////////////////////////////////////////////////////////////////// //

var _ = check.Suite(&SSLLabsSuite{})

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *SSLLabsSuite) TestErrors(c *check.C) {
	_, err := NewAPI("", _TESTER_VERSION, _TESTER_EMAIL)
	c.Assert(err, check.Equals, ErrEmptyClientName)
	_, err = NewAPI("SSLScanTester", "", _TESTER_EMAIL)
	c.Assert(err, check.Equals, ErrEmptyClientVersion)

	var api *API
	_, err = api.Analyze("test.com", AnalyzeParams{})
	c.Assert(err, check.Equals, ErrInvalid)

	var ap *AnalyzeProgress
	_, err = ap.Info(false, false)
	c.Assert(err, check.Equals, ErrInvalid)
	_, err = ap.GetEndpointInfo("0.0.0.0", false)
	c.Assert(err, check.Equals, ErrInvalid)

	ap = &AnalyzeProgress{}
	_, err = ap.Info(false, false)
	c.Assert(err, check.Equals, ErrInvalid)
	_, err = ap.GetEndpointInfo("0.0.0.0", false)
	c.Assert(err, check.Equals, ErrInvalid)

	ap.api = &API{}
	_, err = ap.Info(false, false)
	c.Assert(err, check.Equals, ErrInvalid)
	_, err = ap.GetEndpointInfo("0.0.0.0", false)
	c.Assert(err, check.Equals, ErrInvalid)
}

func (s *SSLLabsSuite) TestInfo(c *check.C) {
	api, err := NewAPI("SSLScanTester", _TESTER_VERSION, _TESTER_EMAIL)

	if err != nil {
		c.Fatal(err.Error())
	}

	c.Assert(api, check.NotNil)

	c.Assert(api.Info.EngineVersion, check.Equals, "2.3.1")
	c.Assert(api.Info.CriteriaVersion, check.Equals, "2009q")
}

func (s *SSLLabsSuite) TestAnalyze(c *check.C) {
	var progress *AnalyzeProgress

	api, err := NewAPI("SSLScanTester", _TESTER_VERSION, _TESTER_EMAIL)

	if err != nil {
		c.Fatal(err.Error())
	}

	c.Assert(api, check.NotNil)

	lastSuccess := time.Now()

	for {
		if os.Getenv("NO_CACHE") != "" {
			progress, err = api.Analyze("github.com", AnalyzeParams{StartNew: true})
		} else {
			progress, err = api.Analyze("github.com", AnalyzeParams{})
		}

		if err != nil {
			fmt.Printf("Error: %v (%.0f sec since test start)\n", err, time.Since(lastSuccess).Seconds())
			if time.Since(lastSuccess) > 3*time.Minute {
				c.Fatal("Can't start test for 3 minutes, exiting…")
			}
			time.Sleep(30 * time.Second)
		} else {
			c.Assert(progress, check.NotNil)
			break
		}
	}

	var info *AnalyzeInfo

	fmt.Printf("Progress: ∙")

	lastSuccess = time.Now()

	for range time.NewTicker(5 * time.Second).C {
		info, err = progress.Info(false, false)

		if info != nil && err == nil {
			lastSuccess = time.Now()
		}

		if info.Status == STATUS_ERROR {
			c.Fatal(info.StatusMessage)
		}

		if info.Status == STATUS_READY {
			break
		}

		if time.Since(lastSuccess) > 30*time.Second {
			c.Fatal("Can't get result from API more than 30 sec")
		}

		fmt.Printf("∙")
	}

	fmt.Println(" DONE")

	c.Assert(info.Host, check.Equals, "github.com")
	c.Assert(info.Port, check.Equals, 443)
	c.Assert(info.Protocol, check.Equals, "http")
	c.Assert(info.IsPublic, check.Equals, false)
	c.Assert(info.Status, check.Equals, "READY")
	c.Assert(info.Endpoints, check.Not(check.HasLen), 0)

	c.Assert(info.Endpoints[0].Grade, check.Equals, "A+")
	c.Assert(info.Endpoints[0].GradeTrustIgnored, check.Equals, "A+")
	c.Assert(info.Endpoints[0].HasWarnings, check.Equals, false)
	c.Assert(info.Endpoints[0].IsExceptional, check.Equals, true)
	c.Assert(info.Endpoints[0].Progress, check.Equals, 100)
	c.Assert(info.Endpoints[0].Delegation, check.Equals, 1)
	c.Assert(info.Endpoints[0].Details, check.IsNil)

	fullInfo, err := progress.Info(true, true)

	c.Assert(err, check.IsNil)
	c.Assert(fullInfo, check.NotNil)
	c.Assert(fullInfo.Endpoints, check.HasLen, 1)

	details := fullInfo.Endpoints[0].Details

	c.Assert(details.HostStartTime, check.Not(check.Equals), 0)

	c.Assert(details.CertChains, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].ID, check.Equals, "da6f6e74c248cd1ff4f1b2b388bf07cb8c01c1253888119e1e984b2c8d204f3f")
	c.Assert(details.CertChains[0].CertIDs, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].CertIDs[0], check.Equals, "6157d9d5f6066c0085aa9e487f3ae7c94a6778b8f76ddca9c8539e730386f45f")
	c.Assert(details.CertChains[0].TrustPaths, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].TrustPaths[0].CertIDs[0], check.Equals, "6157d9d5f6066c0085aa9e487f3ae7c94a6778b8f76ddca9c8539e730386f45f")
	c.Assert(details.CertChains[0].TrustPaths[0].Trust[0].RootStore, check.Equals, "Mozilla")
	c.Assert(details.CertChains[0].TrustPaths[0].Trust[0].IsTrusted, check.Equals, true)
	c.Assert(details.CertChains[0].Issues, check.Equals, 0)
	c.Assert(details.CertChains[0].NoSNI, check.Equals, false)

	c.Assert(details.Protocols[0].ID, check.Equals, 771)
	c.Assert(details.Protocols[0].Name, check.Equals, "TLS")
	c.Assert(details.Protocols[0].Version, check.Equals, "1.2")
	c.Assert(details.Protocols[0].V2SuitesDisabled, check.Equals, false)
	c.Assert(details.Protocols[0].Q, check.IsNil)

	c.Assert(details.Suites, check.HasLen, 2)
	c.Assert(details.Suites[0].Protocol, check.Equals, 771)
	c.Assert(details.Suites[0].Preference, check.Equals, true)
	c.Assert(details.Suites[0].List[0].ID, check.Equals, 49195)
	c.Assert(details.Suites[0].List[0].Name, check.Equals, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
	c.Assert(details.Suites[0].List[0].CipherStrength, check.Equals, 128)
	c.Assert(details.Suites[0].List[0].KxType, check.Equals, "ECDH")
	c.Assert(details.Suites[0].List[0].KxStrength, check.Equals, 3072)
	c.Assert(details.Suites[0].List[0].DHBits, check.Equals, 0)
	c.Assert(details.Suites[0].List[0].DHG, check.Equals, 0)
	c.Assert(details.Suites[0].List[0].DHP, check.Equals, 0)
	c.Assert(details.Suites[0].List[0].DHYs, check.Equals, 0)
	c.Assert(details.Suites[0].List[0].NamedGroupBits, check.Equals, 256)
	c.Assert(details.Suites[0].List[0].NamedGroupID, check.Equals, 29)
	c.Assert(details.Suites[0].List[0].NamedGroupName, check.Equals, "x25519")
	c.Assert(details.Suites[0].List[0].Q, check.IsNil)

	c.Assert(details.NamedGroups, check.NotNil)
	c.Assert(details.NamedGroups.List, check.HasLen, 2)
	c.Assert(details.NamedGroups.Preference, check.Equals, true)
	c.Assert(details.NamedGroups.List[0].ID, check.Equals, 29)
	c.Assert(details.NamedGroups.List[0].Name, check.Equals, "x25519")
	c.Assert(details.NamedGroups.List[0].Bits, check.Equals, 256)
	c.Assert(details.NamedGroups.List[0].NamedGroupType, check.Equals, "EC")

	c.Assert(details.SIMS, check.NotNil)
	c.Assert(details.SIMS.Results, check.NotNil)
	c.Assert(details.SIMS.Results[5].Client, check.NotNil)
	c.Assert(details.SIMS.Results[5].Client.ID, check.Equals, 62)
	c.Assert(details.SIMS.Results[5].Client.Name, check.Equals, "Android")
	c.Assert(details.SIMS.Results[5].Client.Platform, check.Equals, "")
	c.Assert(details.SIMS.Results[5].Client.Version, check.Equals, "4.4.2")
	c.Assert(details.SIMS.Results[5].Client.IsReference, check.Equals, false)
	c.Assert(details.SIMS.Results[5].ErrorCode, check.Equals, 0)
	c.Assert(details.SIMS.Results[5].ErrorMessage, check.Equals, "")
	c.Assert(details.SIMS.Results[5].Attempts, check.Equals, 1)
	c.Assert(details.SIMS.Results[5].CertChainID, check.Not(check.Equals), "")
	c.Assert(details.SIMS.Results[5].ProtocolID, check.Equals, 771)
	c.Assert(details.SIMS.Results[5].SuiteID, check.Equals, 49195)
	c.Assert(details.SIMS.Results[5].SuiteName, check.Equals, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
	c.Assert(details.SIMS.Results[5].KxType, check.Equals, "ECDH")
	c.Assert(details.SIMS.Results[5].KxStrength, check.Equals, 3072)
	c.Assert(details.SIMS.Results[5].NamedGroupBits, check.Equals, 256)
	c.Assert(details.SIMS.Results[5].NamedGroupID, check.Equals, 23)
	c.Assert(details.SIMS.Results[5].NamedGroupName, check.Equals, "secp256r1")
	c.Assert(details.SIMS.Results[5].KeyAlg, check.Equals, "EC")
	c.Assert(details.SIMS.Results[5].KeySize, check.Equals, 256)
	c.Assert(details.SIMS.Results[5].SigAlg, check.Equals, "SHA256withECDSA")
	c.Assert(details.SIMS.Results[16].Client, check.NotNil)
	c.Assert(details.SIMS.Results[16].Client.ID, check.Equals, 153)
	c.Assert(details.SIMS.Results[16].Client.Name, check.Equals, "Chrome")
	c.Assert(details.SIMS.Results[16].Client.Platform, check.Equals, "Win 10")
	c.Assert(details.SIMS.Results[16].Client.Version, check.Equals, "70")
	c.Assert(details.SIMS.Results[16].Client.IsReference, check.Equals, false)
	c.Assert(details.SIMS.Results[16].ErrorCode, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].ErrorMessage, check.Equals, "")
	c.Assert(details.SIMS.Results[16].Attempts, check.Equals, 1)
	c.Assert(details.SIMS.Results[16].ProtocolID, check.Equals, 772)
	c.Assert(details.SIMS.Results[16].SuiteID, check.Equals, 4865)
	c.Assert(details.SIMS.Results[16].SuiteName, check.Equals, "TLS_AES_128_GCM_SHA256")
	c.Assert(details.SIMS.Results[16].KxType, check.Equals, "ECDH")
	c.Assert(details.SIMS.Results[16].KxStrength, check.Equals, 3072)
	c.Assert(details.SIMS.Results[16].DHBits, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].DHG, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].DHP, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].DHYs, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].NamedGroupBits, check.Equals, 256)
	c.Assert(details.SIMS.Results[16].NamedGroupID, check.Equals, 29)
	c.Assert(details.SIMS.Results[16].NamedGroupName, check.Equals, "x25519")

	c.Assert(details.ServerSignature, check.Equals, "github.com")
	c.Assert(details.PrefixDelegation, check.Equals, false)
	c.Assert(details.NonPrefixDelegation, check.Equals, true)
	c.Assert(details.VulnBeast, check.Equals, false)
	c.Assert(details.RenegSupport, check.Equals, 2)
	c.Assert(details.SessionResumption, check.Equals, 0)
	c.Assert(details.CompressionMethods, check.Equals, 0)
	c.Assert(details.SupportsNPN, check.Equals, false)
	c.Assert(details.NPNProtocols, check.Equals, "")
	c.Assert(details.SupportsALPN, check.Equals, true)
	c.Assert(details.ALPNProtocols, check.Equals, "h2 http/1.1")
	c.Assert(details.SessionTickets, check.Equals, 0)
	c.Assert(details.OCSPStapling, check.Equals, false)
	c.Assert(details.StaplingRevocationStatus, check.Equals, 0)
	c.Assert(details.StaplingRevocationErrorMessage, check.Equals, "")
	c.Assert(details.SNIRequired, check.Equals, false)
	c.Assert(details.HTTPStatusCode, check.Equals, 200)
	c.Assert(details.SupportsRC4, check.Equals, false)
	c.Assert(details.RC4WithModern, check.Equals, false)
	c.Assert(details.RC4Only, check.Equals, false)
	c.Assert(details.ForwardSecrecy, check.Equals, 4)
	c.Assert(details.SupportAEAD, check.Equals, true)
	c.Assert(details.SupportsCBC, check.Equals, true)
	c.Assert(details.ProtocolIntolerance, check.Equals, 0)
	c.Assert(details.MiscIntolerance, check.Equals, 0)
	c.Assert(details.Heartbleed, check.Equals, false)
	c.Assert(details.Heartbeat, check.Equals, false)
	c.Assert(details.OpenSSLCCS, check.Equals, SSLCSC_STATUS_NOT_VULNERABLE)
	c.Assert(details.OpenSSLLuckyMinus20, check.Equals, LUCKY_MINUS_STATUS_NOT_VULNERABLE)
	c.Assert(details.Ticketbleed, check.Equals, TICKETBLEED_STATUS_NOT_VULNERABLE)
	c.Assert(details.Bleichenbacher, check.Equals, BLEICHENBACHER_STATUS_NOT_VULNERABLE)
	c.Assert(details.ZombiePoodle, check.Equals, POODLE_STATUS_NOT_VULNERABLE)
	c.Assert(details.GoldenDoodle, check.Equals, POODLE_STATUS_NOT_VULNERABLE)
	c.Assert(details.ZeroLengthPaddingOracle, check.Equals, 1)
	c.Assert(details.SleepingPoodle, check.Equals, POODLE_STATUS_NOT_VULNERABLE)
	c.Assert(details.Poodle, check.Equals, false)
	c.Assert(details.PoodleTLS, check.Equals, POODLE_STATUS_NOT_VULNERABLE)
	c.Assert(details.FallbackSCSV, check.Equals, true)
	c.Assert(details.Freak, check.Equals, false)
	c.Assert(details.HasSCT, check.Equals, 1)
	c.Assert(details.DHPrimes, check.HasLen, 0)
	c.Assert(details.DHUsesKnownPrimes, check.Equals, 0)
	c.Assert(details.DHYsReuse, check.Equals, false)
	c.Assert(details.ECDHParameterReuse, check.Equals, false)
	c.Assert(details.Logjam, check.Equals, false)
	c.Assert(details.ChaCha20Preference, check.Equals, true)
	c.Assert(details.HSTSPolicy, check.NotNil)
	c.Assert(details.HSTSPolicy.Status, check.Equals, HSTS_STATUS_PRESENT)
	c.Assert(details.HSTSPreloads, check.HasLen, 4)
	c.Assert(details.HSTSPreloads[2].Source, check.Equals, "Firefox")
	c.Assert(details.HSTSPreloads[2].Hostname, check.Equals, "github.com")
	c.Assert(details.HSTSPreloads[2].Status, check.Equals, HSTS_STATUS_PRESENT)
	c.Assert(details.HSTSPreloads[2].Error, check.Equals, "")
	c.Assert(details.HSTSPreloads[2].SourceTime, check.Not(check.Equals), 0)
	c.Assert(details.HPKPPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.HPKPRoPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.StaticPKPPolicy.Status, check.Equals, SPKP_STATUS_ABSENT)
	c.Assert(details.HTTPTransactions, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].RequestURL, check.Equals, "https://github.com/")
	c.Assert(details.HTTPTransactions[0].StatusCode, check.Equals, 200)
	c.Assert(details.HTTPTransactions[0].RequestLine, check.Equals, "GET / HTTP/1.1")
	c.Assert(details.HTTPTransactions[0].RequestHeaders, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].ResponseLine, check.Equals, "HTTP/1.1 200 OK")
	c.Assert(details.HTTPTransactions[0].ResponseHeadersRaw, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].ResponseHeaders, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].FragileServer, check.Equals, false)
	c.Assert(details.ImplementsTLS13MandatoryCS, check.Equals, true)
	c.Assert(details.ZeroRTTEnabled, check.Equals, 0)

	certs := fullInfo.Certs

	c.Assert(certs, check.HasLen, 9)
	c.Assert(certs[0].ID, check.Equals, "6157d9d5f6066c0085aa9e487f3ae7c94a6778b8f76ddca9c8539e730386f45f")
	c.Assert(certs[0].Subject, check.Not(check.Equals), "")
	c.Assert(certs[0].SerialNumber, check.Equals, "145d04b46500c429ccf3fb43a33fafd2")
	c.Assert(certs[0].CommonNames, check.DeepEquals, []string{"github.com"})
	c.Assert(certs[0].AltNames, check.DeepEquals, []string{"github.com", "www.github.com"})
	c.Assert(certs[0].NotBefore, check.Equals, int64(1741564800000))
	c.Assert(certs[0].NotAfter, check.Equals, int64(1773187199000))
	c.Assert(certs[0].IssuerSubject, check.Equals, "CN=Sectigo RSA Domain Validation Secure Server CA, O=Sectigo Limited, L=Salford, ST=Greater Manchester, C=GB")
	c.Assert(certs[0].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(certs[0].RevocationInfo, check.Equals, 2)
	c.Assert(certs[0].OCSPURIs, check.DeepEquals, []string{"http://ocsp.sectigo.com"})
	c.Assert(certs[0].RevocationStatus, check.Equals, 2)
	c.Assert(certs[0].CRLRevocationStatus, check.Equals, 4)
	c.Assert(certs[0].OCSPRevocationStatus, check.Equals, 2)
	c.Assert(certs[0].DNSCAA, check.Equals, true)
	c.Assert(certs[0].MustStaple, check.Equals, false)
	c.Assert(certs[0].SGC, check.Equals, 0)
	c.Assert(certs[0].ValidationType, check.Equals, "")
	c.Assert(certs[0].Issues, check.Equals, 0)
	c.Assert(certs[0].SCT, check.Equals, true)
	c.Assert(certs[0].SHA1Hash, check.Equals, "2fa036d645d7be5369a33b7c667d0b336d882f1c")
	c.Assert(certs[0].SHA256Hash, check.Equals, "6157d9d5f6066c0085aa9e487f3ae7c94a6778b8f76ddca9c8539e730386f45f")
	c.Assert(certs[0].PINSHA256, check.Equals, "1jXwPJjk3SAhvkPxGFQ0VP8KMMN1FEFUNBOz2uaHHGk=")
	c.Assert(certs[0].KeyAlg, check.Equals, "RSA")
	c.Assert(certs[0].KeySize, check.Equals, 4096)
	c.Assert(certs[0].KeyStrength, check.Equals, 4096)
	c.Assert(certs[0].KeyKnownDebianInsecure, check.Equals, false)
	c.Assert(certs[0].Raw, check.Not(check.Equals), "")
}

// ////////////////////////////////////////////////////////////////////////////////// //
