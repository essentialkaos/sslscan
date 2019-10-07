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

const _TESTER_VERSION = "8.2.0"

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

	c.Assert(api.Info.EngineVersion, check.Equals, "1.36.1")
	c.Assert(api.Info.CriteriaVersion, check.Equals, "2009q")
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

	fmt.Printf("Progress: ∙")

	for {
		info, err = progress.Info(false, true)

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

	fullInfo, err := progress.Info(true, true)

	c.Assert(err, check.IsNil)
	c.Assert(fullInfo, check.NotNil)
	c.Assert(fullInfo.Endpoints, check.HasLen, 1)

	details := fullInfo.Endpoints[0].Details

	c.Assert(details.HostStartTime, check.Not(check.Equals), 0)

	c.Assert(details.CertChains, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].ID, check.Equals, "ec9e72359c6bae51e0a44a666ebe843064a974b1a6f969073f145df7948c3278")
	c.Assert(details.CertChains[0].CertIDs, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].CertIDs[0], check.Equals, "4bda9e40d19260d636042a0e6ad5222a024f05f7001d61220f17e6632428f1d6")
	c.Assert(details.CertChains[0].TrustPaths, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].TrustPaths[0].CertIDs[0], check.Equals, "4bda9e40d19260d636042a0e6ad5222a024f05f7001d61220f17e6632428f1d6")
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
	c.Assert(details.Suites[2].List[11].Q, check.NotNil)

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
	c.Assert(details.SIMS.Results[16].Client, check.NotNil)
	c.Assert(details.SIMS.Results[16].Client.ID, check.Equals, 153)
	c.Assert(details.SIMS.Results[16].Client.Name, check.Equals, "Chrome")
	c.Assert(details.SIMS.Results[16].Client.Platform, check.Equals, "Win 10")
	c.Assert(details.SIMS.Results[16].Client.Version, check.Equals, "70")
	c.Assert(details.SIMS.Results[16].Client.IsReference, check.Equals, false)
	c.Assert(details.SIMS.Results[16].ErrorCode, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].ErrorMessage, check.Equals, "")
	c.Assert(details.SIMS.Results[16].Attempts, check.Equals, 1)
	c.Assert(details.SIMS.Results[16].CertChainID, check.Not(check.Equals), "")
	c.Assert(details.SIMS.Results[16].ProtocolID, check.Equals, 771)
	c.Assert(details.SIMS.Results[16].SuiteID, check.Equals, 49199)
	c.Assert(details.SIMS.Results[16].SuiteName, check.Equals, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
	c.Assert(details.SIMS.Results[16].KxType, check.Equals, "ECDH")
	c.Assert(details.SIMS.Results[16].KxStrength, check.Equals, 3072)
	c.Assert(details.SIMS.Results[16].DHBits, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].DHG, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].DHP, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].DHYs, check.Equals, 0)
	c.Assert(details.SIMS.Results[16].NamedGroupBits, check.Equals, 256)
	c.Assert(details.SIMS.Results[16].NamedGroupID, check.Equals, 23)
	c.Assert(details.SIMS.Results[16].NamedGroupName, check.Equals, "secp256r1")
	c.Assert(details.SIMS.Results[16].KeyAlg, check.Equals, "RSA")
	c.Assert(details.SIMS.Results[16].KeySize, check.Equals, 2048)
	c.Assert(details.SIMS.Results[16].SigAlg, check.Equals, "SHA256withRSA")

	c.Assert(details.ServerSignature, check.Equals, "Apache")
	c.Assert(details.PrefixDelegation, check.Equals, false)
	c.Assert(details.NonPrefixDelegation, check.Equals, true)
	c.Assert(details.VulnBeast, check.Equals, true)
	c.Assert(details.RenegSupport, check.Equals, 2)
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
	c.Assert(details.ZeroRTTEnabled, check.Equals, -1)

	certs := fullInfo.Certs

	c.Assert(certs, check.HasLen, 3)
	c.Assert(certs[0].ID, check.Equals, "4bda9e40d19260d636042a0e6ad5222a024f05f7001d61220f17e6632428f1d6")
	c.Assert(certs[0].Subject, check.Not(check.Equals), "")
	c.Assert(certs[0].SerialNumber, check.Equals, "0bea3e0fa14ddb70348a7193f6ba4d66")
	c.Assert(certs[0].CommonNames, check.DeepEquals, []string{"ssllabs.com"})
	c.Assert(certs[0].AltNames, check.DeepEquals, []string{"ssllabs.com", "*.ssllabs.com"})
	c.Assert(certs[0].NotBefore, check.Equals, int64(1556582400000))
	c.Assert(certs[0].NotAfter, check.Equals, int64(1588248000000))
	c.Assert(certs[0].IssuerSubject, check.Equals, "CN=DigiCert SHA2 Secure Server CA, O=DigiCert Inc, C=US")
	c.Assert(certs[0].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(certs[0].RevocationInfo, check.Equals, 3)
	c.Assert(certs[0].CRLURIs, check.DeepEquals, []string{"http://crl3.digicert.com/ssca-sha2-g6.crl"})
	c.Assert(certs[0].OCSPURIs, check.DeepEquals, []string{"http://ocsp.digicert.com"})
	c.Assert(certs[0].RevocationStatus, check.Equals, 2)
	c.Assert(certs[0].CRLRevocationStatus, check.Equals, 2)
	c.Assert(certs[0].OCSPRevocationStatus, check.Equals, 2)
	c.Assert(certs[0].DNSCAA, check.Equals, true)
	c.Assert(certs[0].CAAPolicy, check.NotNil)
	c.Assert(certs[0].CAAPolicy.PolicyHostname, check.Equals, "api.ssllabs.com")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Tag, check.Equals, "issue")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Value, check.Equals, "comodoca.com")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Flags, check.Equals, 0)
	c.Assert(certs[0].MustStaple, check.Equals, false)
	c.Assert(certs[0].SGC, check.Equals, 0)
	c.Assert(certs[0].ValidationType, check.Equals, "")
	c.Assert(certs[0].Issues, check.Equals, 0)
	c.Assert(certs[0].SCT, check.Equals, true)
	c.Assert(certs[0].SHA1Hash, check.Equals, "759b17ba443900b25537c8df2d7b175c2e22cd08")
	c.Assert(certs[0].SHA256Hash, check.Equals, "4bda9e40d19260d636042a0e6ad5222a024f05f7001d61220f17e6632428f1d6")
	c.Assert(certs[0].PINSHA256, check.Equals, "Han7gVNy0CJ/BhWix6RTtjN8hvQMhyKFZtavNjiMzH8=")
	c.Assert(certs[0].KeyAlg, check.Equals, "RSA")
	c.Assert(certs[0].KeySize, check.Equals, 2048)
	c.Assert(certs[0].KeyStrength, check.Equals, 2048)
	c.Assert(certs[0].KeyKnownDebianInsecure, check.Equals, false)
	c.Assert(certs[0].Raw, check.Not(check.Equals), "")
}
