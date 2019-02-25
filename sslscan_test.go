package sslscan

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2019 ESSENTIAL KAOS                         //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"fmt"
	"testing"
	"time"

	check "pkg.re/check.v1"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const _TESTER_VERSION = "8.0.0"

// ////////////////////////////////////////////////////////////////////////////////// //

func Test(t *testing.T) { check.TestingT(t) }

type SSLLabsSuite struct{}

// ////////////////////////////////////////////////////////////////////////////////// //

var _ = check.Suite(&SSLLabsSuite{})

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *SSLLabsSuite) TestInfo(c *check.C) {
	api, err := NewAPI("SSLScanTester", _TESTER_VERSION)

	RequestTimeout = 3.0

	c.Assert(err, check.IsNil)
	c.Assert(api, check.NotNil)

	c.Assert(api.Info.EngineVersion, check.Equals, "1.32.16")
	c.Assert(api.Info.CriteriaVersion, check.Equals, "2009p")
}

func (s *SSLLabsSuite) TestAnalyze(c *check.C) {
	api, err := NewAPI("SSLScanTester", _TESTER_VERSION)

	RequestTimeout = 3.0

	c.Assert(err, check.IsNil)
	c.Assert(api, check.NotNil)

	progress, err := api.Analyze("api.ssllabs.com", AnalyzeParams{})

	c.Assert(progress, check.NotNil)
	c.Assert(err, check.IsNil)

	var info *AnalyzeInfo

	fmt.Printf("Progress: ")

	for {
		info, err = progress.Info(false)

		c.Assert(info, check.NotNil)
		c.Assert(err, check.IsNil)

		if info.Status == STATUS_ERROR {
			c.Fatal(info.StatusMessage)
		}

		if info.Status == STATUS_READY {
			break
		}

		fmt.Printf("∙")

		time.Sleep(5 * time.Second)
	}

	fmt.Println(" DONE")

	c.Assert(info.Host, check.Equals, "api.ssllabs.com")
	c.Assert(info.Port, check.Equals, 443)
	c.Assert(info.Protocol, check.Equals, "http")
	c.Assert(info.IsPublic, check.Equals, false)
	c.Assert(info.Status, check.Equals, "READY")
	c.Assert(info.Endpoints, check.Not(check.HasLen), 0)

	c.Assert(info.Endpoints[0].IPAdress, check.Equals, "64.41.200.100")
	c.Assert(info.Endpoints[0].ServerName, check.Equals, "www.ssllabs.com")
	c.Assert(info.Endpoints[0].Grade, check.Equals, "A")
	c.Assert(info.Endpoints[0].GradeTrustIgnored, check.Equals, "A")
	c.Assert(info.Endpoints[0].HasWarnings, check.Equals, false)
	c.Assert(info.Endpoints[0].IsExceptional, check.Equals, false)
	c.Assert(info.Endpoints[0].Progress, check.Equals, 100)
	c.Assert(info.Endpoints[0].Delegation, check.Equals, 1)
	c.Assert(info.Endpoints[0].Details, check.IsNil)

	fullInfo, err := progress.Info(true)

	c.Assert(err, check.IsNil)
	c.Assert(fullInfo, check.NotNil)
	c.Assert(fullInfo.Endpoints, check.HasLen, 1)

	details := fullInfo.Endpoints[0].Details

	c.Assert(details.HostStartTime, check.Not(check.Equals), 0)

	c.Assert(details.CertChains, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].ID, check.Equals, "3ee8e569b42ce723b20643dd67ea0e8a1c0bfe231af977ee7b43eabcb7f8f157")
	c.Assert(details.CertChains[0].CertIDs, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].CertIDs[0], check.Equals, "3385baec319fc7c0dcf242480f01b617c024675aed7734a1abb6dc3ec45af022")
	c.Assert(details.CertChains[0].TrustPaths, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].TrustPaths[0].CertIDs[0], check.Equals, "3385baec319fc7c0dcf242480f01b617c024675aed7734a1abb6dc3ec45af022")
	c.Assert(details.CertChains[0].TrustPaths[0].Trust[0].RootStore, check.Equals, "Mozilla")
	c.Assert(details.CertChains[0].TrustPaths[0].Trust[0].IsTrusted, check.Equals, true)
	c.Assert(details.CertChains[0].Issues, check.Equals, 0)
	c.Assert(details.CertChains[0].NoSNI, check.Equals, false)

	c.Assert(details.Protocols, check.Not(check.HasLen), 0)
	c.Assert(details.Protocols[0].ID, check.Equals, 769)
	c.Assert(details.Protocols[0].Name, check.Equals, "TLS")
	c.Assert(details.Protocols[0].Version, check.Equals, "1.0")
	c.Assert(details.Protocols[0].V2SuitesDisabled, check.Equals, false)
	c.Assert(details.Protocols[0].Q, check.IsNil)

	c.Assert(details.Protocols[1].ID, check.Equals, 770)
	c.Assert(details.Protocols[1].Name, check.Equals, "TLS")
	c.Assert(details.Protocols[1].Version, check.Equals, "1.1")
	c.Assert(details.Protocols[1].V2SuitesDisabled, check.Equals, false)
	c.Assert(details.Protocols[1].Q, check.IsNil)

	c.Assert(details.Protocols[2].ID, check.Equals, 771)
	c.Assert(details.Protocols[2].Name, check.Equals, "TLS")
	c.Assert(details.Protocols[2].Version, check.Equals, "1.2")
	c.Assert(details.Protocols[2].V2SuitesDisabled, check.Equals, false)
	c.Assert(details.Protocols[2].Q, check.IsNil)

	c.Assert(details.Suites, check.HasLen, 3)
	c.Assert(details.Suites[2].Protocol, check.Equals, 771)
	c.Assert(details.Suites[2].Preference, check.Equals, true)
	c.Assert(details.Suites[2].List[0].ID, check.Equals, 49199)
	c.Assert(details.Suites[2].List[0].Name, check.Equals, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	c.Assert(details.Suites[2].List[0].CipherStrength, check.Equals, 128)
	c.Assert(details.Suites[2].List[0].KxType, check.Equals, "ECDH")
	c.Assert(details.Suites[2].List[0].KxStrength, check.Equals, 3072)
	c.Assert(details.Suites[2].List[0].DHBits, check.Equals, 0)
	c.Assert(details.Suites[2].List[0].DHG, check.Equals, 0)
	c.Assert(details.Suites[2].List[0].DHP, check.Equals, 0)
	c.Assert(details.Suites[2].List[0].DHYs, check.Equals, 0)
	c.Assert(details.Suites[2].List[0].NamedGroupBits, check.Equals, 256)
	c.Assert(details.Suites[2].List[0].NamedGroupID, check.Equals, 23)
	c.Assert(details.Suites[2].List[0].NamedGroupName, check.Equals, "secp256r1")
	c.Assert(details.Suites[2].List[0].Q, check.IsNil)
	c.Assert(details.Suites[2].List[11].ID, check.Equals, 107)
	c.Assert(details.Suites[2].List[11].Name, check.Equals, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256")
	c.Assert(details.Suites[2].List[11].CipherStrength, check.Equals, 256)
	c.Assert(details.Suites[2].List[11].KxType, check.Equals, "DH")
	c.Assert(details.Suites[2].List[11].KxStrength, check.Equals, 2048)
	c.Assert(details.Suites[2].List[11].DHBits, check.Equals, 256)
	c.Assert(details.Suites[2].List[11].DHG, check.Equals, 1)
	c.Assert(details.Suites[2].List[11].DHP, check.Equals, 256)
	c.Assert(details.Suites[2].List[11].DHYs, check.Equals, 256)
	c.Assert(details.Suites[2].List[11].NamedGroupBits, check.Equals, 0)
	c.Assert(details.Suites[2].List[11].NamedGroupID, check.Equals, 0)
	c.Assert(details.Suites[2].List[11].NamedGroupName, check.Equals, "")
	c.Assert(details.Suites[2].List[11].Q, check.IsNil)

	c.Assert(details.NamedGroups, check.NotNil)
	c.Assert(details.NamedGroups.List, check.HasLen, 1)
	c.Assert(details.NamedGroups.Preference, check.Equals, false)
	c.Assert(details.NamedGroups.List[0].ID, check.Equals, 23)
	c.Assert(details.NamedGroups.List[0].Name, check.Equals, "secp256r1")
	c.Assert(details.NamedGroups.List[0].Bits, check.Equals, 256)
	c.Assert(details.NamedGroups.List[0].NamedGroupType, check.Equals, "EC")

	c.Assert(details.SIMS, check.NotNil)
	c.Assert(details.SIMS.Results, check.NotNil)
	c.Assert(details.SIMS.Results[0].Client, check.NotNil)
	c.Assert(details.SIMS.Results[0].Client.ID, check.Equals, 56)
	c.Assert(details.SIMS.Results[0].Client.Name, check.Equals, "Android")
	c.Assert(details.SIMS.Results[0].Client.Platform, check.Equals, "")
	c.Assert(details.SIMS.Results[0].Client.Version, check.Equals, "2.3.7")
	c.Assert(details.SIMS.Results[0].Client.IsReference, check.Equals, false)
	c.Assert(details.SIMS.Results[0].ErrorCode, check.Equals, 0)
	c.Assert(details.SIMS.Results[0].ErrorMessage, check.Equals, "")
	c.Assert(details.SIMS.Results[0].Attempts, check.Equals, 1)
	c.Assert(details.SIMS.Results[0].CertChainID, check.Not(check.Equals), "")
	c.Assert(details.SIMS.Results[0].ProtocolID, check.Equals, 769)
	c.Assert(details.SIMS.Results[0].SuiteID, check.Equals, 51)
	c.Assert(details.SIMS.Results[0].SuiteName, check.Equals, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA")
	c.Assert(details.SIMS.Results[0].KxType, check.Equals, "DH")
	c.Assert(details.SIMS.Results[0].KxStrength, check.Equals, 16384)
	c.Assert(details.SIMS.Results[0].DHBits, check.Equals, 2048)
	c.Assert(details.SIMS.Results[0].DHG, check.Equals, 1)
	c.Assert(details.SIMS.Results[0].DHP, check.Equals, 256)
	c.Assert(details.SIMS.Results[0].DHYs, check.Equals, 256)
	c.Assert(details.SIMS.Results[0].NamedGroupBits, check.Equals, 0)
	c.Assert(details.SIMS.Results[0].NamedGroupID, check.Equals, 0)
	c.Assert(details.SIMS.Results[0].NamedGroupName, check.Equals, "")
	c.Assert(details.SIMS.Results[0].KeyAlg, check.Equals, "RSA")
	c.Assert(details.SIMS.Results[0].KeySize, check.Equals, 2048)
	c.Assert(details.SIMS.Results[0].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(details.SIMS.Results[13].Client, check.NotNil)
	c.Assert(details.SIMS.Results[13].Client.ID, check.Equals, 153)
	c.Assert(details.SIMS.Results[13].Client.Name, check.Equals, "Chrome")
	c.Assert(details.SIMS.Results[13].Client.Platform, check.Equals, "Win 10")
	c.Assert(details.SIMS.Results[13].Client.Version, check.Equals, "70")
	c.Assert(details.SIMS.Results[13].Client.IsReference, check.Equals, false)
	c.Assert(details.SIMS.Results[13].ErrorCode, check.Equals, 0)
	c.Assert(details.SIMS.Results[13].ErrorMessage, check.Equals, "")
	c.Assert(details.SIMS.Results[13].Attempts, check.Equals, 1)
	c.Assert(details.SIMS.Results[13].CertChainID, check.Not(check.Equals), "")
	c.Assert(details.SIMS.Results[13].ProtocolID, check.Equals, 771)
	c.Assert(details.SIMS.Results[13].SuiteID, check.Equals, 49199)
	c.Assert(details.SIMS.Results[13].SuiteName, check.Equals, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	c.Assert(details.SIMS.Results[13].KxType, check.Equals, "ECDH")
	c.Assert(details.SIMS.Results[13].KxStrength, check.Equals, 3072)
	c.Assert(details.SIMS.Results[13].DHBits, check.Equals, 0)
	c.Assert(details.SIMS.Results[13].DHG, check.Equals, 0)
	c.Assert(details.SIMS.Results[13].DHP, check.Equals, 0)
	c.Assert(details.SIMS.Results[13].DHYs, check.Equals, 0)
	c.Assert(details.SIMS.Results[13].NamedGroupBits, check.Equals, 256)
	c.Assert(details.SIMS.Results[13].NamedGroupID, check.Equals, 23)
	c.Assert(details.SIMS.Results[13].NamedGroupName, check.Equals, "secp256r1")
	c.Assert(details.SIMS.Results[13].KeyAlg, check.Equals, "RSA")
	c.Assert(details.SIMS.Results[13].KeySize, check.Equals, 2048)
	c.Assert(details.SIMS.Results[13].SigAlg, check.Equals, "SHA256withRSA")

	c.Assert(details.ServerSignature, check.Equals, "Apache")
	c.Assert(details.PrefixDelegation, check.Equals, false)
	c.Assert(details.NonPrefixDelegation, check.Equals, true)
	c.Assert(details.VulnBeast, check.Equals, true)
	c.Assert(details.RenegSupport, check.Equals, 0)
	c.Assert(details.SessionResumption, check.Equals, 2)
	c.Assert(details.CompressionMethods, check.Equals, 0)
	c.Assert(details.SupportsNPN, check.Equals, false)
	c.Assert(details.NPNProtocols, check.Equals, "")
	c.Assert(details.SupportsALPN, check.Equals, false)
	c.Assert(details.ALPNProtocols, check.Equals, "")
	c.Assert(details.SessionTickets, check.Equals, 0)
	c.Assert(details.OCSPStapling, check.Equals, false)
	c.Assert(details.StaplingRevocationStatus, check.Equals, 0)
	c.Assert(details.StaplingRevocationErrorMessage, check.Equals, "")
	c.Assert(details.SNIRequired, check.Equals, false)
	c.Assert(details.HTTPStatusCode, check.Equals, 302)
	c.Assert(details.HTTPForwarding, check.Equals, "https://www.ssllabs.com")
	c.Assert(details.SupportsRC4, check.Equals, false)
	c.Assert(details.RC4WithModern, check.Equals, false)
	c.Assert(details.RC4Only, check.Equals, false)
	c.Assert(details.ForwardSecrecy, check.Equals, 4)
	c.Assert(details.ProtocolIntolerance, check.Equals, 0)
	c.Assert(details.MiscIntolerance, check.Equals, 0)
	c.Assert(details.Heartbleed, check.Equals, false)
	c.Assert(details.Heartbeat, check.Equals, false)
	c.Assert(details.OpenSSLCCS, check.Equals, SSLCSC_STATUS_NOT_VULNERABLE)
	c.Assert(details.OpenSSLLuckyMinus20, check.Equals, LUCKY_MINUS_STATUS_NOT_VULNERABLE)
	c.Assert(details.Ticketbleed, check.Equals, TICKETBLEED_STATUS_NOT_VULNERABLE)
	c.Assert(details.Bleichenbacher, check.Equals, BLEICHENBACHER_STATUS_NOT_VULNERABLE)
	c.Assert(details.Poodle, check.Equals, false)
	c.Assert(details.PoodleTLS, check.Equals, POODLE_STATUS_NOT_VULNERABLE)
	c.Assert(details.FallbackSCSV, check.Equals, true)
	c.Assert(details.Freak, check.Equals, false)
	c.Assert(details.HasSCT, check.Equals, 1)
	c.Assert(details.DHPrimes, check.HasLen, 1)
	c.Assert(details.DHUsesKnownPrimes, check.Equals, 0)
	c.Assert(details.DHYsReuse, check.Equals, false)
	c.Assert(details.ECDHParameterReuse, check.Equals, false)
	c.Assert(details.Logjam, check.Equals, false)
	c.Assert(details.ChaCha20Preference, check.Equals, false)
	c.Assert(details.HSTSPolicy, check.NotNil)
	c.Assert(details.HSTSPolicy.Status, check.Equals, HSTS_STATUS_ABSENT)
	c.Assert(details.HSTSPreloads, check.HasLen, 4)
	c.Assert(details.HSTSPreloads[0].Source, check.Equals, "Chrome")
	c.Assert(details.HSTSPreloads[0].Hostname, check.Equals, "api.ssllabs.com")
	c.Assert(details.HSTSPreloads[0].Status, check.Equals, HSTS_STATUS_ABSENT)
	c.Assert(details.HSTSPreloads[0].Error, check.Equals, "")
	c.Assert(details.HSTSPreloads[0].SourceTime, check.Not(check.Equals), 0)
	c.Assert(details.HPKPPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.HPKPRoPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.StaticPKPPolicy.Status, check.Equals, SPKP_STATUS_ABSENT)
	c.Assert(details.HTTPTransactions, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].RequestURL, check.Equals, "https://api.ssllabs.com/")
	c.Assert(details.HTTPTransactions[0].StatusCode, check.Equals, 302)
	c.Assert(details.HTTPTransactions[0].RequestLine, check.Equals, "GET / HTTP/1.1")
	c.Assert(details.HTTPTransactions[0].RequestHeaders, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].ResponseLine, check.Equals, "HTTP/1.1 302 Found")
	c.Assert(details.HTTPTransactions[0].ResponseHeadersRaw, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].ResponseHeaders, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].FragileServer, check.Equals, false)
	c.Assert(details.DrownErrors, check.Equals, false)
	c.Assert(details.DrownVulnerable, check.Equals, false)
	c.Assert(details.ImplementsTLS13MandatoryCS, check.Equals, false)

	certs := fullInfo.Certs

	c.Assert(certs, check.HasLen, 3)
	c.Assert(certs[0].ID, check.Equals, "3385baec319fc7c0dcf242480f01b617c024675aed7734a1abb6dc3ec45af022")
	c.Assert(certs[0].Subject, check.Not(check.Equals), "")
	c.Assert(certs[0].SerialNumber, check.Equals, "09d8eba6cc1729e8a3b86e98f960b30b")
	c.Assert(certs[0].CommonNames, check.DeepEquals, []string{"ssllabs.com"})
	c.Assert(certs[0].AltNames, check.DeepEquals, []string{"ssllabs.com", "*.ssllabs.com"})
	c.Assert(certs[0].NotBefore, check.Equals, int64(1525219200000))
	c.Assert(certs[0].NotAfter, check.Equals, int64(1556884800000))
	c.Assert(certs[0].IssuerSubject, check.Equals, "CN=DigiCert Global CA G2, O=DigiCert Inc, C=US")
	c.Assert(certs[0].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(certs[0].RevocationInfo, check.Equals, 3)
	c.Assert(certs[0].CRLURIs, check.DeepEquals, []string{"http://crl3.digicert.com/DigiCertGlobalCAG2.crl"})
	c.Assert(certs[0].OCSPURIs, check.DeepEquals, []string{"http://ocsp.digicert.com"})
	c.Assert(certs[0].RevocationStatus, check.Equals, 2)
	c.Assert(certs[0].CRLRevocationStatus, check.Equals, 2)
	c.Assert(certs[0].OCSPRevocationStatus, check.Equals, 2)
	c.Assert(certs[0].DNSCAA, check.Equals, true)
	c.Assert(certs[0].CAAPolicy, check.NotNil)
	c.Assert(certs[0].CAAPolicy.PolicyHostname, check.Equals, "api.ssllabs.com")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Tag, check.Equals, "issue")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Value, check.Equals, "Digicert.com")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Flags, check.Equals, 0)
	c.Assert(certs[0].MustStaple, check.Equals, false)
	c.Assert(certs[0].SGC, check.Equals, 0)
	c.Assert(certs[0].ValidationType, check.Equals, "")
	c.Assert(certs[0].Issues, check.Equals, 0)
	c.Assert(certs[0].SCT, check.Equals, true)
	c.Assert(certs[0].SHA1Hash, check.Equals, "835fa74e3cecad06e82cb3469b7af8287edc59b2")
	c.Assert(certs[0].SHA256Hash, check.Equals, "3385baec319fc7c0dcf242480f01b617c024675aed7734a1abb6dc3ec45af022")
	c.Assert(certs[0].PINSHA256, check.Equals, "Apy5nr74bAFaH6LW5jamLzig16emadx9yHSDqDIVGM4=")
	c.Assert(certs[0].KeyAlg, check.Equals, "RSA")
	c.Assert(certs[0].KeySize, check.Equals, 2048)
	c.Assert(certs[0].KeyStrength, check.Equals, 2048)
	c.Assert(certs[0].KeyKnownDebianInsecure, check.Equals, false)
	c.Assert(certs[0].Raw, check.Not(check.Equals), "")
}
