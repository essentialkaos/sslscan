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

const _TESTER_VERSION = "9.0.0"

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

	c.Assert(api.Info.EngineVersion, check.Equals, "2.0.7")
	c.Assert(api.Info.CriteriaVersion, check.Equals, "2009q")
}

func (s *SSLLabsSuite) TestAnalyze(c *check.C) {
	api, err := NewAPI("SSLScanTester", _TESTER_VERSION)

	RequestTimeout = 3.0

	c.Assert(err, check.IsNil)
	c.Assert(api, check.NotNil)

	progress, err := api.Analyze("essentialkaos.com", AnalyzeParams{})

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

	c.Assert(info.Host, check.Equals, "essentialkaos.com")
	c.Assert(info.Port, check.Equals, 443)
	c.Assert(info.Protocol, check.Equals, "http")
	c.Assert(info.IsPublic, check.Equals, false)
	c.Assert(info.Status, check.Equals, "READY")
	c.Assert(info.Endpoints, check.Not(check.HasLen), 0)

	c.Assert(info.Endpoints[0].IPAdress, check.Equals, "5.79.108.150")
	c.Assert(info.Endpoints[0].ServerName, check.Equals, "curie.kaos.cc")
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
	c.Assert(details.CertChains[0].ID, check.Equals, "ff8a173ccfbf4b02c2aa1db43a5ed08081129e11b30397b5bd584c96065529a6")
	c.Assert(details.CertChains[0].CertIDs, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].CertIDs[0], check.Equals, "679abbd8062273b062a95d41aca26438936789f58fd6c797832fee41cc9d09bc")
	c.Assert(details.CertChains[0].TrustPaths, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].TrustPaths[0].CertIDs[0], check.Equals, "679abbd8062273b062a95d41aca26438936789f58fd6c797832fee41cc9d09bc")
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
	c.Assert(details.Suites[0].List[0].ID, check.Equals, 49200)
	c.Assert(details.Suites[0].List[0].Name, check.Equals, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	c.Assert(details.Suites[0].List[0].CipherStrength, check.Equals, 256)
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
	c.Assert(details.Suites[0].List[4].ID, check.Equals, 49171)
	c.Assert(details.Suites[0].List[4].Name, check.Equals, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
	c.Assert(details.Suites[0].List[4].CipherStrength, check.Equals, 128)
	c.Assert(details.Suites[0].List[4].KxType, check.Equals, "ECDH")
	c.Assert(details.Suites[0].List[4].KxStrength, check.Equals, 3072)
	c.Assert(details.Suites[0].List[4].NamedGroupBits, check.Equals, 256)
	c.Assert(details.Suites[0].List[4].NamedGroupID, check.Equals, 29)
	c.Assert(details.Suites[0].List[4].NamedGroupName, check.Equals, "x25519")
	c.Assert(details.Suites[0].List[4].Q, check.NotNil)

	c.Assert(details.NamedGroups, check.NotNil)
	c.Assert(details.NamedGroups.List, check.HasLen, 3)
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
	c.Assert(details.SIMS.Results[5].SuiteID, check.Equals, 49200)
	c.Assert(details.SIMS.Results[5].SuiteName, check.Equals, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	c.Assert(details.SIMS.Results[5].KxType, check.Equals, "ECDH")
	c.Assert(details.SIMS.Results[5].KxStrength, check.Equals, 15360)
	c.Assert(details.SIMS.Results[5].NamedGroupBits, check.Equals, 521)
	c.Assert(details.SIMS.Results[5].NamedGroupID, check.Equals, 25)
	c.Assert(details.SIMS.Results[5].NamedGroupName, check.Equals, "secp521r1")
	c.Assert(details.SIMS.Results[5].KeyAlg, check.Equals, "RSA")
	c.Assert(details.SIMS.Results[5].KeySize, check.Equals, 4096)
	c.Assert(details.SIMS.Results[5].SigAlg, check.Equals, "SHA256withRSA")
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

	c.Assert(details.ServerSignature, check.Equals, "PEW-PEW-SERVER")
	c.Assert(details.PrefixDelegation, check.Equals, false)
	c.Assert(details.NonPrefixDelegation, check.Equals, true)
	c.Assert(details.VulnBeast, check.Equals, false)
	c.Assert(details.RenegSupport, check.Equals, 2)
	c.Assert(details.SessionResumption, check.Equals, 2)
	c.Assert(details.CompressionMethods, check.Equals, 0)
	c.Assert(details.SupportsNPN, check.Equals, true)
	c.Assert(details.NPNProtocols, check.Equals, "h2 http/1.1")
	c.Assert(details.SupportsALPN, check.Equals, true)
	c.Assert(details.ALPNProtocols, check.Equals, "h2 http/1.1")
	c.Assert(details.SessionTickets, check.Equals, 1)
	c.Assert(details.OCSPStapling, check.Equals, false)
	c.Assert(details.StaplingRevocationStatus, check.Equals, 0)
	c.Assert(details.StaplingRevocationErrorMessage, check.Equals, "")
	c.Assert(details.SNIRequired, check.Equals, true)
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
	c.Assert(details.HSTSPreloads[0].Source, check.Equals, "Chrome")
	c.Assert(details.HSTSPreloads[0].Hostname, check.Equals, "essentialkaos.com")
	c.Assert(details.HSTSPreloads[0].Status, check.Equals, HSTS_STATUS_ABSENT)
	c.Assert(details.HSTSPreloads[0].Error, check.Equals, "")
	c.Assert(details.HSTSPreloads[0].SourceTime, check.Not(check.Equals), 0)
	c.Assert(details.HPKPPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.HPKPRoPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.StaticPKPPolicy.Status, check.Equals, SPKP_STATUS_ABSENT)
	c.Assert(details.HTTPTransactions, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].RequestURL, check.Equals, "https://essentialkaos.com/")
	c.Assert(details.HTTPTransactions[0].StatusCode, check.Equals, 200)
	c.Assert(details.HTTPTransactions[0].RequestLine, check.Equals, "GET / HTTP/1.1")
	c.Assert(details.HTTPTransactions[0].RequestHeaders, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].ResponseLine, check.Equals, "HTTP/1.1 200 OK")
	c.Assert(details.HTTPTransactions[0].ResponseHeadersRaw, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].ResponseHeaders, check.Not(check.HasLen), 0)
	c.Assert(details.HTTPTransactions[0].FragileServer, check.Equals, false)
	c.Assert(details.DrownErrors, check.Equals, false)
	c.Assert(details.DrownVulnerable, check.Equals, false)
	c.Assert(details.ImplementsTLS13MandatoryCS, check.Equals, true)
	c.Assert(details.ZeroRTTEnabled, check.Equals, 0)

	certs := fullInfo.Certs

	c.Assert(certs, check.HasLen, 6)
	c.Assert(certs[0].ID, check.Equals, "679abbd8062273b062a95d41aca26438936789f58fd6c797832fee41cc9d09bc")
	c.Assert(certs[0].Subject, check.Not(check.Equals), "")
	c.Assert(certs[0].SerialNumber, check.Equals, "05ec48f4bc2a47d3f673ba74fd6abb92")
	c.Assert(certs[0].CommonNames, check.DeepEquals, []string{"essentialkaos.com"})
	c.Assert(certs[0].AltNames, check.DeepEquals, []string{"essentialkaos.com", "www.essentialkaos.com"})
	c.Assert(certs[0].NotBefore, check.Equals, int64(1519948800000))
	c.Assert(certs[0].NotAfter, check.Equals, int64(1591228800000))
	c.Assert(certs[0].IssuerSubject, check.Equals, "CN=RapidSSL TLS RSA CA G1, OU=www.digicert.com, O=DigiCert Inc, C=US")
	c.Assert(certs[0].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(certs[0].RevocationInfo, check.Equals, 3)
	c.Assert(certs[0].CRLURIs, check.DeepEquals, []string{"http://cdp.rapidssl.com/RapidSSLTLSRSACAG1.crl"})
	c.Assert(certs[0].OCSPURIs, check.DeepEquals, []string{"http://status.rapidssl.com"})
	c.Assert(certs[0].RevocationStatus, check.Equals, 2)
	c.Assert(certs[0].CRLRevocationStatus, check.Equals, 2)
	c.Assert(certs[0].OCSPRevocationStatus, check.Equals, 2)
	c.Assert(certs[0].DNSCAA, check.Equals, true)
	c.Assert(certs[0].CAAPolicy, check.NotNil)
	c.Assert(certs[0].CAAPolicy.PolicyHostname, check.Equals, "essentialkaos.com")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Tag, check.Equals, "iodef")
	c.Assert(certs[0].CAAPolicy.CAARecords[0].Flags, check.Equals, 0)
	c.Assert(certs[0].MustStaple, check.Equals, false)
	c.Assert(certs[0].SGC, check.Equals, 0)
	c.Assert(certs[0].ValidationType, check.Equals, "")
	c.Assert(certs[0].Issues, check.Equals, 0)
	c.Assert(certs[0].SCT, check.Equals, true)
	c.Assert(certs[0].SHA1Hash, check.Equals, "be8b1260444044dfb1c3c176f1b7a06f5f6f158e")
	c.Assert(certs[0].SHA256Hash, check.Equals, "679abbd8062273b062a95d41aca26438936789f58fd6c797832fee41cc9d09bc")
	c.Assert(certs[0].PINSHA256, check.Equals, "iV/V+ArFf61vm/fqfOmfPozziuR7Wn6ULW9S3WigEhQ=")
	c.Assert(certs[0].KeyAlg, check.Equals, "RSA")
	c.Assert(certs[0].KeySize, check.Equals, 4096)
	c.Assert(certs[0].KeyStrength, check.Equals, 4096)
	c.Assert(certs[0].KeyKnownDebianInsecure, check.Equals, false)
	c.Assert(certs[0].Raw, check.Not(check.Equals), "")
}
