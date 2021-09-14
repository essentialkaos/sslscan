package sslscan

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2021 ESSENTIAL KAOS                         //
//      Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0>      //
//                                                                                    //
// ////////////////////////////////////////////////////////////////////////////////// //

import (
	"fmt"
	"testing"
	"time"

	check "pkg.re/essentialkaos/check.v1"
)

// ////////////////////////////////////////////////////////////////////////////////// //

const _TESTER_VERSION = "10.0.1"

// ////////////////////////////////////////////////////////////////////////////////// //

func Test(t *testing.T) { check.TestingT(t) }

type SSLLabsSuite struct{}

// ////////////////////////////////////////////////////////////////////////////////// //

var _ = check.Suite(&SSLLabsSuite{})

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *SSLLabsSuite) TestInfo(c *check.C) {
	api, err := NewAPI("SSLScanTester", _TESTER_VERSION)

	api.RequestTimeout = 5 * time.Second

	c.Assert(err, check.IsNil)
	c.Assert(api, check.NotNil)

	c.Assert(api.Info.EngineVersion, check.Equals, "2.1.8")
	c.Assert(api.Info.CriteriaVersion, check.Equals, "2009q")
}

func (s *SSLLabsSuite) TestAnalyze(c *check.C) {
	var progress *AnalyzeProgress

	api, err := NewAPI("SSLScanTester", _TESTER_VERSION)

	api.RequestTimeout = 5 * time.Second

	c.Assert(err, check.IsNil)
	c.Assert(api, check.NotNil)

	lastSuccess := time.Now()

	for {
		progress, err = api.Analyze("essentialkaos.com", AnalyzeParams{})

		if err != nil {
			fmt.Printf("Error: %v (%.0f sec since test start)\n", err, time.Since(lastSuccess).Seconds())
			if time.Since(lastSuccess) > 3*time.Minute {
				c.Fatal("Can't ")
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
	c.Assert(details.CertChains[0].ID, check.Equals, "18f1361483cdff25f6ab36116303201f5d74a35284721fee3ec7d5a1db731726")
	c.Assert(details.CertChains[0].CertIDs, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].CertIDs[0], check.Equals, "d3daa0d8c29117d68ec1b55a5afeffe12e0b71e13239c4d70d15b713b97ecc22")
	c.Assert(details.CertChains[0].TrustPaths, check.Not(check.HasLen), 0)
	c.Assert(details.CertChains[0].TrustPaths[0].CertIDs[0], check.Equals, "d3daa0d8c29117d68ec1b55a5afeffe12e0b71e13239c4d70d15b713b97ecc22")
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
	c.Assert(details.Suites[0].List[0].ID, check.Equals, 52393)
	c.Assert(details.Suites[0].List[0].Name, check.Equals, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256")
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
	c.Assert(details.SIMS.Results[5].SuiteID, check.Equals, 49196)
	c.Assert(details.SIMS.Results[5].SuiteName, check.Equals, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
	c.Assert(details.SIMS.Results[5].KxType, check.Equals, "ECDH")
	c.Assert(details.SIMS.Results[5].KxStrength, check.Equals, 15360)
	c.Assert(details.SIMS.Results[5].NamedGroupBits, check.Equals, 521)
	c.Assert(details.SIMS.Results[5].NamedGroupID, check.Equals, 25)
	c.Assert(details.SIMS.Results[5].NamedGroupName, check.Equals, "secp521r1")
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
	c.Assert(details.SupportsCBC, check.Equals, false)
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
	c.Assert(details.ChaCha20Preference, check.Equals, false)
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

	c.Assert(certs, check.HasLen, 4)
	c.Assert(certs[0].ID, check.Equals, "d3daa0d8c29117d68ec1b55a5afeffe12e0b71e13239c4d70d15b713b97ecc22")
	c.Assert(certs[0].Subject, check.Not(check.Equals), "")
	c.Assert(certs[0].SerialNumber, check.Equals, "056f9c1dd2b89a95528f3ab2470ff762")
	c.Assert(certs[0].CommonNames, check.DeepEquals, []string{"essentialkaos.com"})
	c.Assert(certs[0].AltNames, check.DeepEquals, []string{"essentialkaos.com", "www.essentialkaos.com"})
	c.Assert(certs[0].NotBefore, check.Equals, int64(1590796800000))
	c.Assert(certs[0].NotAfter, check.Equals, int64(1653998400000))
	c.Assert(certs[0].IssuerSubject, check.Equals, "CN=GeoTrust ECC CA 2018, OU=www.digicert.com, O=DigiCert Inc, C=US")
	c.Assert(certs[0].SigAlg, check.Equals, "SHA256withECDSA")
	c.Assert(certs[0].RevocationInfo, check.Equals, 3)
	c.Assert(certs[0].CRLURIs, check.DeepEquals, []string{"http://cdp.geotrust.com/GeoTrustECCCA2018.crl"})
	c.Assert(certs[0].OCSPURIs, check.DeepEquals, []string{"http://status.geotrust.com"})
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
	c.Assert(certs[0].SHA1Hash, check.Equals, "460702670fcafcad7159391da3d1816a9638b9e3")
	c.Assert(certs[0].SHA256Hash, check.Equals, "d3daa0d8c29117d68ec1b55a5afeffe12e0b71e13239c4d70d15b713b97ecc22")
	c.Assert(certs[0].PINSHA256, check.Equals, "TVlnEdo67QeUh73GC4b2Ef9HuUNKrpATAoUrZw3m3P4=")
	c.Assert(certs[0].KeyAlg, check.Equals, "EC")
	c.Assert(certs[0].KeySize, check.Equals, 256)
	c.Assert(certs[0].KeyStrength, check.Equals, 3072)
	c.Assert(certs[0].KeyKnownDebianInsecure, check.Equals, false)
	c.Assert(certs[0].Raw, check.Not(check.Equals), "")
}
