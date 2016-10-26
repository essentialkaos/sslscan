package sslscan

// ////////////////////////////////////////////////////////////////////////////////// //
//                                                                                    //
//                     Copyright (c) 2009-2016 Essential Kaos                         //
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

func Test(t *testing.T) { check.TestingT(t) }

type SSLLabsSuite struct{}

// ////////////////////////////////////////////////////////////////////////////////// //

var _ = check.Suite(&SSLLabsSuite{})

// ////////////////////////////////////////////////////////////////////////////////// //

func (s *SSLLabsSuite) TestInfo(c *check.C) {
	api, err := NewAPI("SSLScanTester", "4.0.0")

	c.Assert(api, check.NotNil)
	c.Assert(err, check.IsNil)

	c.Assert(api.Info.EngineVersion, check.Equals, "1.24.4")
	c.Assert(api.Info.CriteriaVersion, check.Equals, "2009l")
}

func (s *SSLLabsSuite) TestAnalyze(c *check.C) {
	api, err := NewAPI("SSLScanTester", "4.0.0")

	c.Assert(api, check.NotNil)
	c.Assert(err, check.IsNil)

	progress, err := api.Analyze("https://api.ssllabs.com")

	c.Assert(progress, check.NotNil)
	c.Assert(err, check.IsNil)

	var info *AnalyzeInfo

	fmt.Printf("Progress: ")

	for {
		info, err = progress.Info()

		c.Assert(info, check.NotNil)
		c.Assert(err, check.IsNil)

		if info.Status == STATUS_ERROR {
			c.Fatal(info.StatusMessage)
		}

		if info.Status == STATUS_READY {
			break
		}

		fmt.Printf(".")

		time.Sleep(5 * time.Second)
	}

	fmt.Println(" DONE")

	c.Assert(info.Host, check.Equals, "https://api.ssllabs.com")
	c.Assert(info.Port, check.Equals, 443)
	c.Assert(info.Protocol, check.Equals, "HTTP")
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

	detailedInfo, err := progress.DetailedInfo(info.Endpoints[0].IPAdress)

	c.Assert(err, check.IsNil)
	c.Assert(detailedInfo, check.NotNil)
	c.Assert(detailedInfo.Details, check.NotNil)

	details := detailedInfo.Details

	c.Assert(details.Key, check.NotNil)
	c.Assert(details.Key.Size, check.Equals, 2048)
	c.Assert(details.Key.Alg, check.Equals, "RSA")
	c.Assert(details.Key.DebianFlaw, check.Equals, false)
	c.Assert(details.Key.Strength, check.Equals, 2048)

	c.Assert(details.Cert, check.NotNil)
	c.Assert(details.Cert.Subject, check.Equals, "CN=ssllabs.com,O=Qualys, Inc.,L=Redwood City,ST=California,C=US")
	c.Assert(details.Cert.CommonNames, check.DeepEquals, []string{"ssllabs.com"})
	c.Assert(details.Cert.AltNames, check.DeepEquals, []string{"ssllabs.com", "*.ssllabs.com"})
	c.Assert(details.Cert.IssuerSubject, check.Equals, "CN=Entrust Certification Authority - L1K,OU=(c) 2012 Entrust, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust, Inc.,C=US")
	c.Assert(details.Cert.IssuerLabel, check.Equals, "Entrust Certification Authority - L1K")
	c.Assert(details.Cert.SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(details.Cert.RevocationInfo, check.Equals, 3)
	c.Assert(details.Cert.CRLURIs, check.DeepEquals, []string{"http://crl.entrust.net/level1k.crl"})
	c.Assert(details.Cert.OCSPURIs, check.DeepEquals, []string{"http://ocsp.entrust.net"})
	c.Assert(details.Cert.RevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Cert.CRLRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Cert.OCSPRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Cert.SGC, check.Equals, 0)
	c.Assert(details.Cert.ValidationType, check.Equals, "")
	c.Assert(details.Cert.Issues, check.Equals, 0)
	c.Assert(details.Cert.SCT, check.Equals, false)
	c.Assert(details.Cert.MustStaple, check.Equals, 0)
	c.Assert(details.Cert.SHA1Hash, check.Equals, "4c91b922af1d09702f9b6240da931b795445f70d")
	c.Assert(details.Cert.PINSHA256, check.Equals, "xkWf9Qfs1uZi2NcMV3Gdnrz1UF4FNAslzApMTwynaMU=")

	c.Assert(details.Chain, check.NotNil)
	c.Assert(details.Chain.Certs, check.Not(check.HasLen), 0)
	c.Assert(details.Chain.Issues, check.Equals, 0)

	c.Assert(details.Chain.Certs[0], check.NotNil)
	c.Assert(details.Chain.Certs[0].Subject, check.Equals, "CN=ssllabs.com,O=Qualys, Inc.,L=Redwood City,ST=California,C=US")
	c.Assert(details.Chain.Certs[0].Label, check.Equals, "ssllabs.com")
	c.Assert(details.Chain.Certs[0].NotBefore, check.Not(check.Equals), int64(0))
	c.Assert(details.Chain.Certs[0].NotAfter, check.Not(check.Equals), int64(0))
	c.Assert(details.Chain.Certs[0].IssuerSubject, check.Equals, "CN=Entrust Certification Authority - L1K,OU=(c) 2012 Entrust, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust, Inc.,C=US")
	c.Assert(details.Chain.Certs[0].IssuerLabel, check.Equals, "Entrust Certification Authority - L1K")
	c.Assert(details.Chain.Certs[0].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(details.Chain.Certs[0].Issues, check.Equals, 0)
	c.Assert(details.Chain.Certs[0].KeyAlg, check.Equals, "RSA")
	c.Assert(details.Chain.Certs[0].KeySize, check.Equals, 2048)
	c.Assert(details.Chain.Certs[0].KeyStrength, check.Equals, 2048)
	c.Assert(details.Chain.Certs[0].RevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[0].CRLRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[0].OCSPRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[0].Raw, check.Not(check.Equals), "")

	c.Assert(details.Chain.Certs[1], check.NotNil)
	c.Assert(details.Chain.Certs[1].Subject, check.Equals, "CN=Entrust Certification Authority - L1K,OU=(c) 2012 Entrust, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust, Inc.,C=US")
	c.Assert(details.Chain.Certs[1].Label, check.Equals, "Entrust Certification Authority - L1K")
	c.Assert(details.Chain.Certs[1].NotBefore, check.Not(check.Equals), int64(0))
	c.Assert(details.Chain.Certs[1].NotAfter, check.Not(check.Equals), int64(0))
	c.Assert(details.Chain.Certs[1].IssuerSubject, check.Equals, "CN=Entrust Root Certification Authority - G2,OU=(c) 2009 Entrust, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust, Inc.,C=US")
	c.Assert(details.Chain.Certs[1].IssuerLabel, check.Equals, "Entrust Root Certification Authority - G2")
	c.Assert(details.Chain.Certs[1].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(details.Chain.Certs[1].Issues, check.Equals, 0)
	c.Assert(details.Chain.Certs[1].KeyAlg, check.Equals, "RSA")
	c.Assert(details.Chain.Certs[1].KeySize, check.Equals, 2048)
	c.Assert(details.Chain.Certs[1].KeyStrength, check.Equals, 2048)
	c.Assert(details.Chain.Certs[1].RevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[1].CRLRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[1].OCSPRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[1].Raw, check.Not(check.Equals), "")

	c.Assert(details.Chain.Certs[2], check.NotNil)
	c.Assert(details.Chain.Certs[2].Subject, check.Equals, "CN=Entrust Root Certification Authority - G2,OU=(c) 2009 Entrust, Inc. - for authorized use only,OU=See www.entrust.net/legal-terms,O=Entrust, Inc.,C=US")
	c.Assert(details.Chain.Certs[2].Label, check.Equals, "Entrust Root Certification Authority - G2")
	c.Assert(details.Chain.Certs[2].NotBefore, check.Not(check.Equals), int64(0))
	c.Assert(details.Chain.Certs[2].NotAfter, check.Not(check.Equals), int64(0))
	c.Assert(details.Chain.Certs[2].IssuerSubject, check.Equals, "CN=Entrust Root Certification Authority,OU=(c) 2006 Entrust, Inc.,OU=www.entrust.net/CPS is incorporated by reference,O=Entrust, Inc.,C=US")
	c.Assert(details.Chain.Certs[2].IssuerLabel, check.Equals, "Entrust Root Certification Authority")
	c.Assert(details.Chain.Certs[2].SigAlg, check.Equals, "SHA256withRSA")
	c.Assert(details.Chain.Certs[2].Issues, check.Equals, 0)
	c.Assert(details.Chain.Certs[2].KeyAlg, check.Equals, "RSA")
	c.Assert(details.Chain.Certs[2].KeySize, check.Equals, 2048)
	c.Assert(details.Chain.Certs[2].KeyStrength, check.Equals, 2048)
	c.Assert(details.Chain.Certs[2].RevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[2].CRLRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[2].OCSPRevocationStatus, check.Equals, REVOCATION_STATUS_NOT_REVOKED)
	c.Assert(details.Chain.Certs[2].Raw, check.Not(check.Equals), "")

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

	c.Assert(details.Suites, check.NotNil)
	c.Assert(details.Suites.List, check.Not(check.HasLen), 0)
	c.Assert(details.Suites.Preference, check.Equals, true)

	for _, suite := range details.Suites.List {
		switch suite.ID {
		case 22:
			c.Assert(suite.Name, check.Equals, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA")
			c.Assert(suite.CipherStrength, check.Equals, 112)
			c.Assert(suite.DHStrength, check.Equals, 2048)
			c.Assert(suite.DHP, check.Equals, 256)
			c.Assert(suite.DHG, check.Equals, 1)
			c.Assert(suite.DHYs, check.Equals, 256)
			c.Assert(suite.ECDHBits, check.Equals, 0)
			c.Assert(suite.ECDHStrength, check.Equals, 0)
			c.Assert(suite.Q, check.IsNil)

		case 49199:
			c.Assert(suite.Name, check.Equals, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
			c.Assert(suite.CipherStrength, check.Equals, 128)
			c.Assert(suite.DHStrength, check.Equals, 0)
			c.Assert(suite.DHP, check.Equals, 0)
			c.Assert(suite.DHG, check.Equals, 0)
			c.Assert(suite.DHYs, check.Equals, 0)
			c.Assert(suite.ECDHBits, check.Equals, 256)
			c.Assert(suite.ECDHStrength, check.Equals, 3072)
			c.Assert(suite.Q, check.IsNil)
		}
	}

	c.Assert(details.ServerSignature, check.Equals, "Apache")
	c.Assert(details.PrefixDelegation, check.Equals, false)
	c.Assert(details.NonPrefixDelegation, check.Equals, true)
	c.Assert(details.VulnBeast, check.Equals, true)
	c.Assert(details.RenegSupport, check.Equals, 2)
	c.Assert(details.SessionResumption, check.Equals, 2)
	c.Assert(details.CompressionMethods, check.Equals, 0)
	c.Assert(details.SupportsNPN, check.Equals, false)
	c.Assert(details.NPNProtocols, check.Equals, "")
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
	c.Assert(details.OpenSslCCS, check.Equals, 1)
	c.Assert(details.OpenSSLLuckyMinus20, check.Equals, 1)
	c.Assert(details.Poodle, check.Equals, false)
	c.Assert(details.PoodleTLS, check.Equals, 1)
	c.Assert(details.FallbackSCSV, check.Equals, true)
	c.Assert(details.Freak, check.Equals, false)
	c.Assert(details.HasSCT, check.Equals, 0)
	c.Assert(details.DHUsesKnownPrimes, check.Equals, 0)
	c.Assert(details.DHYsReuse, check.Equals, false)
	c.Assert(details.Logjam, check.Equals, false)
	c.Assert(details.DrownErrors, check.Equals, true)
	c.Assert(details.DrownVulnerable, check.Equals, false)

	c.Assert(details.SIMS, check.NotNil)
	c.Assert(details.SIMS.Results, check.Not(check.HasLen), 0)

	for _, suite := range details.SIMS.Results {
		c.Assert(suite.Client.ID, check.NotNil)

		switch suite.Client.ID {
		case 25:
			c.Assert(suite.Client, check.NotNil)
			c.Assert(suite.ProtocolID, check.Equals, 0)
			c.Assert(suite.Attempts, check.Equals, 1)
			c.Assert(suite.ErrorCode, check.Equals, 1)
			c.Assert(suite.SuiteID, check.Equals, 0)
			c.Assert(suite.Client.ID, check.Equals, 25)
			c.Assert(suite.Client.Name, check.Equals, "Java")
			c.Assert(suite.Client.Platform, check.Equals, "")
			c.Assert(suite.Client.Version, check.Equals, "6u45")
			c.Assert(suite.Client.IsReference, check.Equals, false)

		case 114:
			c.Assert(suite.Client, check.NotNil)
			c.Assert(suite.ProtocolID, check.Equals, 771)
			c.Assert(suite.Attempts, check.Equals, 1)
			c.Assert(suite.ErrorCode, check.Equals, 0)
			c.Assert(suite.SuiteID, check.Equals, 49199)
			c.Assert(suite.Client.Name, check.Equals, "Safari")
			c.Assert(suite.Client.Platform, check.Equals, "iOS 9")
			c.Assert(suite.Client.Version, check.Equals, "9")
			c.Assert(suite.Client.IsReference, check.Equals, true)
		}
	}

	c.Assert(details.HSTSPolicy.LongMaxAge, check.Equals, 15552000)
	c.Assert(details.HSTSPolicy.Header, check.Equals, "")
	c.Assert(details.HSTSPolicy.Status, check.Equals, HSTS_STATUS_ABSENT)
	c.Assert(details.HSTSPolicy.Error, check.Equals, "")
	c.Assert(details.HSTSPolicy.MaxAge, check.Equals, int64(0))
	c.Assert(details.HSTSPolicy.IncludeSubDomains, check.Equals, false)
	c.Assert(details.HSTSPolicy.Preload, check.Equals, false)

	c.Assert(details.HSTSPreloads, check.HasLen, 4)

	c.Assert(details.HSTSPreloads[0].Hostname, check.Equals, "api.ssllabs.com")
	c.Assert(details.HSTSPreloads[1].Hostname, check.Equals, "api.ssllabs.com")
	c.Assert(details.HSTSPreloads[2].Hostname, check.Equals, "api.ssllabs.com")
	c.Assert(details.HSTSPreloads[3].Hostname, check.Equals, "api.ssllabs.com")

	c.Assert(details.HSTSPreloads[0].Status, check.Equals, HSTS_STATUS_ABSENT)
	c.Assert(details.HSTSPreloads[1].Status, check.Equals, HSTS_STATUS_ABSENT)
	c.Assert(details.HSTSPreloads[2].Status, check.Equals, HSTS_STATUS_ABSENT)
	c.Assert(details.HSTSPreloads[3].Status, check.Equals, HSTS_STATUS_ABSENT)

	c.Assert(details.HSTSPreloads[0].Source, check.Equals, "Chrome")
	c.Assert(details.HSTSPreloads[1].Source, check.Equals, "Edge")
	c.Assert(details.HSTSPreloads[2].Source, check.Equals, "Firefox")
	c.Assert(details.HSTSPreloads[3].Source, check.Equals, "IE")

	c.Assert(details.HPKPPolicy, check.NotNil)
	c.Assert(details.HPKPPolicy.Header, check.Equals, "")
	c.Assert(details.HPKPPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.HPKPPolicy.Pins, check.DeepEquals, []*Pin{})
	c.Assert(details.HPKPPolicy.MatchedPins, check.DeepEquals, []*Pin{})

	c.Assert(details.HPKPRoPolicy, check.NotNil)
	c.Assert(details.HPKPRoPolicy.Header, check.Equals, "")
	c.Assert(details.HPKPRoPolicy.Status, check.Equals, HPKP_STATUS_ABSENT)
	c.Assert(details.HPKPRoPolicy.Pins, check.DeepEquals, []*Pin{})
	c.Assert(details.HPKPRoPolicy.MatchedPins, check.DeepEquals, []*Pin{})

	c.Assert(details.DrownHosts, check.DeepEquals, []*DrownHost{})
}
