// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "gtest/gtest.h"

#include <string>
#include <vector>
#include <optional>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#include "rgw/rgw_rest_sts.h"
#include "rgw/rgw_rest.h"
#include "common/ceph_json.h"
#include "jwt-cpp/jwt.h"
#include "rgw/rgw_rest_sts_detail.h"
#include "common/dout.h"
#include "global/global_context.h"
#include "common/ceph_context.h"
#include "msg/msg_types.h"

// Minimal test prefix provider for logging
static ceph::common::CephContext test_cct(CEPH_ENTITY_TYPE_CLIENT);

struct TestDPP : public DoutPrefixProvider {
  std::ostream& gen_prefix(std::ostream& out) const override {
    return out << "[unittest_rgw_sts] ";
  }
  CephContext* get_cct() const override { return &test_cct; }
  unsigned get_subsys() const override { return ceph_subsys_rgw; }
};
static TestDPP test_dpp; // single instance

using namespace std;
using namespace rgw::auth::sts;

namespace { // anonymous namespace for test helpers

// Export cert PEM to base64 DER for x5c entry
static string pem_to_x5c_b64(const string& pem_cert) {
  unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(pem_cert.data(), pem_cert.size()), BIO_free_all);
  string pw;
  unique_ptr<X509, decltype(&X509_free)> x509(PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);

  if (!x509) return {};

  int len = i2d_X509(x509.get(), nullptr);
  if (len <= 0) return {};
  vector<unsigned char> der(len);
  unsigned char* p = der.data();
  i2d_X509(x509.get(), &p);

  // base64 encode without leaking or double-freeing the BIO chain
  BIO* mem = BIO_new(BIO_s_mem());
  if (!mem) return {};
  BIO* b64 = BIO_new(BIO_f_base64());
  if (!b64) {
    BIO_free(mem);
    return {};
  }
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  b64 = BIO_push(b64, mem); // b64 now owns mem; free with BIO_free_all(b64)
  if (BIO_write(b64, der.data(), der.size()) <= 0) {
    BIO_free_all(b64);
    return {};
  }
  if (BIO_flush(b64) != 1) {
    BIO_free_all(b64);
    return {};
  }
  char* out = nullptr; long outlen = BIO_get_mem_data(mem, &out);
  string out_str(out, outlen);
  BIO_free_all(b64);
  return out_str;
}

// Build a JWKS JSON string with two keys: first x5c wrong, second x5c right
static string build_jwks_with_wrong_then_right(const string& wrong_x5c, const string& right_x5c) {
  // Minimal JWKS compatible with validate_signature() expectations
  string jwks = string("{\"keys\":[") +
    "{\"use\":\"sig\",\"x5c\":[\"" + wrong_x5c + "\"]}," +
    "{\"use\":\"sig\",\"x5c\":[\"" + right_x5c + "\"]}]}";
  return jwks;
}

} // end of anonymous namespace

// Hardcoded certificate and known SHA-1 thumbprint.
// Thumbprint: 7523ff87ad66511531ac7562b2b7d45794b34940
static const char* kKnownCertPem =
"-----BEGIN CERTIFICATE-----\n"
"MIIDSTCCAjGgAwIBAgIULVYzKt4CiREg0f0z0OlDE1dqz8cwDQYJKoZIhvcNAQEL\n"
"BQAwNDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENlcGhUZXN0MRIwEAYDVQQDDAls\n"
"b2NhbGhvc3QwHhcNMjUxMTEwMTA1MjIxWhcNMjYxMTEwMTA1MjIxWjA0MQswCQYD\n"
"VQQGEwJVUzERMA8GA1UECgwIQ2VwaFRlc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDCC\n"
"ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIcIy+Eg4goms6cJlg5mvnLB\n"
"ypyYkuKRZHyJRQFJIup+1QTF1QNI1qaa1F1GnZYDR7MoNfB3YjaPbcX4A+N7C5CM\n"
"eWoXaJzW25KDRbUPcaKQG7PfJjkXI/RqrUsvgvcMR03ryZKZYBXZsUAfkJpNo+CF\n"
"hw9XNQVKHNJTLQJSJ0IPUKRxx+i3b6PfoqWgQJW7A5+EifZlPoMSK6RaFly4wTXM\n"
"hymQ0NVBp4XBdx+NrpDfwqKNEQPoFsL9TBiVol8EVfQzzev5J+M0yTtAgwITpLNj\n"
"tWiqy0z7NoLNJFS6k7TEMERbFjd26LanXEEoFNvytfH+ZEydnURnoKKfeHcD210C\n"
"AwEAAaNTMFEwHQYDVR0OBBYEFBX6OhQrqm6YZjzLvt7tRoNC+IBoMB8GA1UdIwQY\n"
"MBaAFBX6OhQrqm6YZjzLvt7tRoNC+IBoMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI\n"
"hvcNAQELBQADggEBABYdBvMe581I/rh3ytGKtEwqt6Q13XZpi9ZWHx5XbC2uN4DT\n"
"WFFTBDaayUZyo9md+EuV89582RHDRoyNTnwKoOtOq0IMDGkKupeICeIKSweX/t3G\n"
"m024kkrQpq/MkG9UqGtS6Gl77417nJFSjLnXqt86MgUHTn0xqqIuWfGEQ+oZNEj7\n"
"M2F+uOc9x6tJf3NBb1m8VwC6xMWl9ZRF8Uace6SdOd/RUEe1S8DzEbsta7Vo8Shf\n"
"7En+S0lHWpowwfmC2ZtEXgbsGkL8P6i+t2XYZFYV6xT2EugoYAmM7iwHb5fAb8d1\n"
"mJ9ol20+diUptkhQzFGley/dGAbsiUAKgk7ooGo=\n"
"-----END CERTIFICATE-----\n";

// Shared known SHA-1 thumbprint for kKnownCertPem
static const char* kKnownCertThumbSha1 = "7523ff87ad66511531ac7562b2b7d45794b34940";

// Private key PEM for the first cert (kKnownCertPem)
static const char* kKnownPrivPem =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCHCMvhIOIKJrOn\n"
"CZYOZr5ywcqcmJLikWR8iUUBSSLqftUExdUDSNammtRdRp2WA0ezKDXwd2I2j23F\n"
"+APjewuQjHlqF2ic1tuSg0W1D3GikBuz3yY5FyP0aq1LL4L3DEdN68mSmWAV2bFA\n"
"H5CaTaPghYcPVzUFShzSUy0CUidCD1Ckccfot2+j36KloECVuwOfhIn2ZT6DEiuk\n"
"WhZcuME1zIcpkNDVQaeFwXcfja6Q38KijRED6BbC/UwYlaJfBFX0M83r+SfjNMk7\n"
"QIMCE6SzY7VoqstM+zaCzSRUupO0xDBEWxY3dui2p1xBKBTb8rXx/mRMnZ1EZ6Ci\n"
"n3h3A9tdAgMBAAECggEABr1ap67jeUw7NUAWPDvGj6W6fhxjYGmPUWPsjMbgtkGE\n"
"UkupeRN+mywpI0qt/NnHD1sXbhwXS8/W08WwM/9lMV7BhJkMgJ98sBBbP1E5A7sb\n"
"ltuxZbIQ+lcEtTb222vCd1Ioame7Uvvdi+zHY9wyLLedaReaLtxnGdxK582/5d0Z\n"
"QrVmk2IjlBxi6kMaiQLXeABgg3+XHzjFLhY7sjLQjqwWQFXIxvJDEIxA5/ExDNjP\n"
"8gAZLZ3zultAE1mTgmHGDEZJqiPIvN/PP5BIVyDe9JQ60OMzKN4fOp2Rnk9bDcxr\n"
"izcSvPxyaG4yKYW4eUgyrbWD8/dxqsg708m1/SE/pQKBgQC7+ZxKzNQ0gxxB5P0k\n"
"kLjrowfhwfR+QWbUIk9fvfCb69OSYDLfh97tJY4UjgVvPOEOhXEy1zZGZF/nz58k\n"
"RvKvEAuBRXszGSGJESr0NGM0Ujh2+C22xh4I6m9uRrKUBcmI++SVQRpf+ghGXcxG\n"
"YWSX918ZrK7ZzyojPYJMopKyQwKBgQC35qdehlktVYP7gcpBz9Z2noEn8NAHBX47\n"
"B/8luH2UYpM4N3sgSA+IdWKe5PQYWY/6GJDvpk5QYnOQsRSikW78lgYuaDzFs5Ib\n"
"Md53wwdiGbMoIAhOq9xPRN/sYRIlAM5AURoUA87ssF10S8V2bptEugolzZuFEHHM\n"
"6LYJkBlx3wKBgQCwzCy8DbrpSQei0oVlhtjmiAg5xfr3ZPwaOcr9+d/8RupPmjs/\n"
"EsQRuGjR3GIwJcpnpgq6DsD1pCKwHQ9JR5GqJiUsCPW/Mbvg90y3My67XznMa9BT\n"
"QDOvnw//YG9F2cucE48C8qCj9L8jr8UZzTCX3gqMU2aBZd/0FT4gZigjkQKBgArP\n"
"F89KfjtX52YE/upXWPen4VeDo/aFsCGwGqMQ8PCjyptnR2liUudmXuGP+3ji6r98\n"
"aihr0faPktNSVTAo9CkMeFiJ7+h+4XuPts+7OtfdQtZ864AUQeK23aJ7IiHipjzJ\n"
"h4rdnm/y/cs0GOsZHS8w8B/Asf9kNAwjMW/mdFhpAoGASqQUt3924imphY3DrKow\n"
"Ng9fMGMddh7oMaIcDPzfvv+x5UIrpiPViOjoRKnriwU6DwW4ADm76OG4HlUEE5u+\n"
"kUuJcPmQMdbTr3ZZplxhHJ8ULdcU9UFPyGnlB/mQVtIiLk+b8s72h4kHrOjgoVfc\n"
"p4aXW3iptHE8m1lQTkYcBOg=\n"
"-----END PRIVATE KEY-----\n";

// Second static certificate/key set
static const char* kSecondCertPem =
"-----BEGIN CERTIFICATE-----\n"
"MIIDSTCCAjGgAwIBAgIUGmyniHckFa8a/CUMh7SFjTawk7gwDQYJKoZIhvcNAQEL\n"
"BQAwNDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENlcGhUZXN0MRIwEAYDVQQDDAls\n"
"b2NhbGhvc3QwHhcNMjUxMTEwMTEwMzI3WhcNMjYxMTEwMTEwMzI3WjA0MQswCQYD\n"
"VQQGEwJVUzERMA8GA1UECgwIQ2VwaFRlc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDCC\n"
"ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALh8paoUhRBAuAc2LP26b8G8\n"
"Z5xgSIv9L4b5iaeUzXQrdrSBo1FQs3DZuYDy4MAsecgC1aLF99/wCZqhF3OAO5NW\n"
"bvAu/VDW80FUQyXSg21XMEqGoMXhs8Cc0uoSsM5OlBEyL0aJ9HQb1BUkkZbT+Dub\n"
"MLY7CV9gsh8vnN1wwtTep+u2m9Drt7IUIp6qOnLyshffouEENmAveR2ip7LRwuvw\n"
"TNaNjqSC18TFxAhr+pE0c32SrdSYM2ehLdUQg5cDp/5j/0TptodX4GGLu4pxxa1e\n"
"empkb33wB+9e/9/xskNHmvPg0hIngVQMDZCQM2gsMS79D0o/gTlI6N3gEOFlSQMC\n"
"AwEAAaNTMFEwHQYDVR0OBBYEFOT+Ce+kVdZIH9Y6Uo0EsrqjfqDjMB8GA1UdIwQY\n"
"MBaAFOT+Ce+kVdZIH9Y6Uo0EsrqjfqDjMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZI\n"
"hvcNAQELBQADggEBAD6MS2DLZwOeD05/HgU9nt0R3MJG8/wUcV9cnsLLRuTWcCnX\n"
"EBteyiWKffGBQ5Acb5FXdftitAovYJ02dWcNBmaa0MmTLy1QwaB+r0lpzITuLWkb\n"
"pvaoaxLyY+04NihlP6IkXq50uypVyxwxvepVDzd5R5+SrygNsBB5AbqWmiwdJmXN\n"
"FjhxAKACCDY4JC93MLJV2Z/lCshYk77a/0UQyJHtAJzXxJZaNxW5TY+o+NEifQmh\n"
"vUqUrsWdwgBkhy663La6Ikpl/GBUCWGrq2CpyHYR6uo2GCA+MZ6T3BHPx0CaG2nU\n"
"nzkQDBVCTclTsSOl5zUxcJ4uck/3ozTFq8OP7D8=\n"
"-----END CERTIFICATE-----\n";

// Shared known SHA-1 thumbprint for kSecondCertPem
static const char* kSecondCertThumbSha1 = "d532132bab7cb693d251065a3e22c24323eed5be";

// Private key PEM for the second cert (kSecondCertPem)
static const char* kSecondPrivPem =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4fKWqFIUQQLgH\n"
"Niz9um/BvGecYEiL/S+G+YmnlM10K3a0gaNRULNw2bmA8uDALHnIAtWixfff8Ama\n"
"oRdzgDuTVm7wLv1Q1vNBVEMl0oNtVzBKhqDF4bPAnNLqErDOTpQRMi9GifR0G9QV\n"
"JJGW0/g7mzC2OwlfYLIfL5zdcMLU3qfrtpvQ67eyFCKeqjpy8rIX36LhBDZgL3kd\n"
"oqey0cLr8EzWjY6kgtfExcQIa/qRNHN9kq3UmDNnoS3VEIOXA6f+Y/9E6baHV+Bh\n"
"i7uKccWtXnpqZG998AfvXv/f8bJDR5rz4NISJ4FUDA2QkDNoLDEu/Q9KP4E5SOjd\n"
"4BDhZUkDAgMBAAECggEAB4n/InMB4wxPWOrDrj9jAhmcaagHnuzi9yhAZ1WYixxG\n"
"7BEg0ZmzfjOaNeT2/p4dVelDvgn1W184TUDdr/h4DB6BRxXB1VQLZHU4j0BJ4vsn\n"
"++ECNe6cxWIYk7yIIXjVlS77U+3JocBiC4Ekj/OBQTz8zHL01Zh31E1s+CGmXJjb\n"
"ncSJxvvs/68zDfh7VWCDY5bhEbmnpAmyPOTKqn8liaDejdefaJJQOLO1gjtOzbNt\n"
"xQBD7Sp/VI3g4zBBjj3OPG9SPPo2ATAJoXckqu9RqIIg+co+VX6P4Oiwbj/vxNVi\n"
"ZHrnjmPKXWYtDVv7YN/s7L4bVqssanuT7m4+F9Bo3QKBgQDlcg05f+QF6JrdRL73\n"
"RmNSakuym5bzgwpGGvAbnw4/FFNldobM6PilmaHRhShTG6usRtjMzXZvAzh8cdbX\n"
"tVheyKPSYDoZJ6O6BGZfhD/UeA0NYwbDzZTamM8FnFVH71ZmZR13p8izl5/dvxmX\n"
"MbjAUA50vZt0xk8KZsKXB65QfwKBgQDN1pL699PGqZOEziZ3RFgdUHtLKkpSG4w/\n"
"lnEEG56ttxskUu4OIu29EnAH7hnlFJ4xUqqPXt9yDen3DHtI9t74IOg1yUn9n971\n"
"bDDVTTvoBDjkqiWYuU22HHBGEjBaAR3e+MX+ix+w/mf4OwVU9zjxxVPSytnzuYlO\n"
"gmC8U4qFfQKBgEIzVwd5E/R0eYJQHH1CDNQxoSemZrZZ37P8f7yodrbSiYFj4l7q\n"
"9RrqqdrG/ayE9lJdmp30xjAfkMOvINraEuY+I65GX1z0p/O640K56KTIApQTN1d1\n"
"UHaF0m1+/sgjkR04HXlxqqHOpKyZP6v1B6ZNMu6R6nGV6iZJIenrqGrHAoGAUGkc\n"
"rhIWlyszx9PIzxrR2VHReIGi2wSL+2NH7zTi/jXj0oLbIIagnRYQ0ehAEW/GhLoo\n"
"iy2i2Kl61tn3Z3+ZhxFD5Y8m6n+D2BhV014CoxbTKvEVEt6A7z2Y1qbQYLjC9JH2\n"
"twOec8RO1XgpExIpGrndjyFTl5TJgPQJ2khAevkCgYEAzpG4BJNUCILS12skOVxD\n"
"HS2/KPaFwzaLMpxqC2nYck8LaiTi4QHpFBuuV35w1iRD9kvarhtuOs3a3jXPn5B3\n"
"Fmr4JgY4iS3mBhxhOku6F0UQ1rMWzSpGK5RMORLuCqul+GdwwH4XSzhBzgss/rZA\n"
"Mn3a/aVq4YGhFxX9x9qDRP4=\n"
"-----END PRIVATE KEY-----\n";

TEST(RGW_STS_Unit, ThumbprintAndX5CHelpersWork) {
  const std::string known_thumb = kKnownCertThumbSha1; // lowercase, no colons
  std::vector<std::string> tps{known_thumb};
  ASSERT_TRUE(rgw::auth::sts::detail::compute_thumbprint_match(tps, kKnownCertPem));
}

TEST(RGW_STS_Unit, ThumbprintMismatchFails) {
  const std::string known_thumb = kKnownCertThumbSha1;
  const std::string wrong_thumb = "7523ff87ad66511531ac7562b2b7d45794b34941"; // last hex digit altered
  std::vector<std::string> wrong{wrong_thumb};
  ASSERT_FALSE(rgw::auth::sts::detail::compute_thumbprint_match(wrong, kKnownCertPem));
  // Also ensure combining correct and incorrect thumbprints still passes (selection scans all)
  std::vector<std::string> mixed{wrong_thumb, known_thumb};
  ASSERT_TRUE(rgw::auth::sts::detail::compute_thumbprint_match(mixed, kKnownCertPem));
}

// Characterization test for JWKS selection logic shape (no network, pure JSON)
TEST(RGW_STS_Unit, BuildJWKSWrongThenRight) {
  const std::string second_cert_thumbprint = kSecondCertThumbSha1;
  const std::string x5c_not_in_thumbprints = pem_to_x5c_b64(kKnownCertPem);
  const std::string x5c_in_thumbprints = pem_to_x5c_b64(kSecondCertPem);
  auto jwks = build_jwks_with_wrong_then_right(x5c_not_in_thumbprints, x5c_in_thumbprints);

  // Parse jwks using Ceph JSONParser just like real code in rgw_rest_sts.cc does
  JSONParser parser;
  ASSERT_TRUE(parser.parse(jwks.c_str(), jwks.size()));
  JSONObj* val = parser.find_obj("keys");
  ASSERT_TRUE(val != nullptr && val->is_array());
  auto keys = val->get_array_elements();
  ASSERT_EQ(keys.size(), 2u);

  // Characterize current selection behavior: first non-matching x5c prevents selecting second
  // We simulate skip_thumbprint_verification=false to require match.
  std::vector<std::string> thumbprints{second_cert_thumbprint};
  // Parse first key object
  JSONParser k1; ASSERT_TRUE(k1.parse(keys[0].c_str(), keys[0].size()));
  std::vector<std::string> x5c_first; ASSERT_TRUE(JSONDecoder::decode_json("x5c", x5c_first, &k1));
  auto cert_not_in_thumbprints = rgw::auth::sts::detail::select_cert_from_x5c(&test_dpp, thumbprints, x5c_first, false);
  ASSERT_FALSE(cert_not_in_thumbprints.has_value()); // cert not selected, because no thumbprints match

  JSONParser k2; ASSERT_TRUE(k2.parse(keys[1].c_str(), keys[1].size()));
  std::vector<std::string> x5c_second; ASSERT_TRUE(JSONDecoder::decode_json("x5c", x5c_second, &k2));
  auto cert_in_thumbprints = rgw::auth::sts::detail::select_cert_from_x5c(&test_dpp, thumbprints, x5c_second, false);
  ASSERT_TRUE(cert_in_thumbprints.has_value()); // cert is selected, because thumbprint matches
}

// Build and sign a JWT with RS256 using the right key, ensure verify_with_cert succeeds only with selected cert
TEST(RGW_STS_Unit, VerifyWithCertSucceedsWithMatchingCert) {
  const std::string cert_a = kKnownCertPem;
  const std::string priv_a = kKnownPrivPem;
  const std::string cert_b = kSecondCertPem;
  const std::string priv_b = kSecondPrivPem;

  auto make_token = [](const std::string& pub_cert, const std::string& priv_key) {
    return jwt::create()
        .set_issuer("https://issuer.test")
        .set_audience("aud")
        .set_type("JWT")
        .set_algorithm("RS256")
        .set_subject("subj")
        .sign(jwt::algorithm::rs256(pub_cert, priv_key, "", ""));
  };

  // Token signed with pair A (second cert/private key)
  auto token_a = make_token(cert_a, priv_a);
  auto decoded_a = jwt::decode(token_a);
  ASSERT_EQ(decoded_a.get_algorithm(), std::string("RS256"));
  ASSERT_FALSE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded_a, "RS256", cert_b));
  ASSERT_TRUE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded_a, "RS256", cert_a));

  // Token signed with pair B (known cert/private key)
  auto token_b = make_token(cert_b, priv_b);
  auto decoded_b = jwt::decode(token_b);
  ASSERT_EQ(decoded_b.get_algorithm(), std::string("RS256"));
  ASSERT_FALSE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded_b, "RS256", cert_a));
  ASSERT_TRUE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded_b, "RS256", cert_b));
}
