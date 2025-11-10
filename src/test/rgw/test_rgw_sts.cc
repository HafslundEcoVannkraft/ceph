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

// Helper: compute SHA-1 thumbprint of a PEM cert like is_cert_valid()
static string sha1_thumbprint_from_pem(const string& pem_cert) {
  unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(pem_cert.data(), pem_cert.size()), BIO_free_all);
  string pw;
  unique_ptr<X509, decltype(&X509_free)> x509(PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);
  const EVP_MD* md = EVP_sha1();
  unsigned int fsize = 0;
  unsigned char fprint[EVP_MAX_MD_SIZE];
  if (!X509_digest(x509.get(), md, fprint, &fsize)) {
    return {};
  }
  stringstream ss;
  for (unsigned int i = 0; i < fsize; ++i) {
    ss << std::setfill('0') << std::setw(2) << std::hex << (0xFF & (unsigned int)fprint[i]);
  }
  return ss.str();
}

// Very small RSA key + self-signed cert generator (for test-only usage)
static pair<string,string> generate_rsa_key_and_self_signed_cert_pem() {
  unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), EVP_PKEY_free);
  unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
  unique_ptr<BIGNUM, decltype(&BN_free)> e(BN_new(), BN_free);
  BN_set_word(e.get(), RSA_F4);
  RSA_generate_key_ex(rsa.get(), 2048, e.get(), nullptr);
  EVP_PKEY_assign_RSA(pkey.get(), rsa.release());

  // self-signed cert
  unique_ptr<X509, decltype(&X509_free)> x509(X509_new(), X509_free);
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L); // ~1 year
  X509_set_pubkey(x509.get(), pkey.get());

  X509_NAME* name = X509_get_subject_name(x509.get());
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"CephTest", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);
  X509_set_issuer_name(x509.get(), name);

  X509_sign(x509.get(), pkey.get(), EVP_sha256());

  // write private key PEM
  unique_ptr<BIO, decltype(&BIO_free_all)> keybio(BIO_new(BIO_s_mem()), BIO_free_all);
  PEM_write_bio_PrivateKey(keybio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
  char* key_data = nullptr; long key_len = BIO_get_mem_data(keybio.get(), &key_data);
  string key_pem(key_data, key_len);

  // write cert PEM
  unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new(BIO_s_mem()), BIO_free_all);
  PEM_write_bio_X509(certbio.get(), x509.get());
  char* cert_data = nullptr; long cert_len = BIO_get_mem_data(certbio.get(), &cert_data);
  string cert_pem(cert_data, cert_len);

  return {key_pem, cert_pem};
}

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

// Hardcoded certificate and known SHA-1 thumbprint generated externally.
// Thumbprint: 7523ff87ad66511531ac7562b2b7d45794b34940
static const char* kKnownCertPem =
"-----BEGIN CERTIFICATE-----\n"
"MIIDSTCCAjGgAwIBAgIULVYzKt4CiREg0f0z0OlDE1dqz8cwDQYJKoZIhvcNAQELBQAwNDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENlcGhUZXN0MRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjUxMTEwMTA1MjIxWhcNMjYxMTEwMTA1MjIxWjA0MQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2VwaFRlc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIcIy+Eg4goms6cJlg5mvnLBypyYkuKRZHyJRQFJIup+1QTF1QNI1qaa1F1GnZYDR7MoNfB3YjaPbcX4A+N7C5CMeWoXaJzW25KDRbUPcaKQG7PfJjkXI/RqrUsvgvcMR03ryZKZYBXZsUAfkJpNo+CFhw9XNQVKHNJTLQJSJ0IPUKRxx+i3b6PfoqWgQJW7A5+EifZlPoMSK6RaFly4wTXMhymQ0NVBp4XBdx+NrpDfwqKNEQPoFsL9TBiVol8EVfQzzev5J+M0yTtAgwITpLNjtWiqy0z7NoLNJFS6k7TEMERbFjd26LanXEEoFNvytfH+ZEydnURnoKKfeHcD210CAwEAAaNTMFEwHQYDVR0OBBYEFBX6OhQrqm6YZjzLvt7tRoNC+IBoMB8GA1UdIwQYMBaAFBX6OhQrqm6YZjzLvt7tRoNC+IBoMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABYdBvMe581I/rh3ytGKtEwqt6Q13XZpi9ZWHx5XbC2uN4DTWFFTBDaayUZyo9md+EuV89582RHDRoyNTnwKoOtOq0IMDGkKupeICeIKSweX/t3Gm024kkrQpq/MkG9UqGtS6Gl77417nJFSjLnXqt86MgUHTn0xqqIuWfGEQ+oZNEj7M2F+uOc9x6tJf3NBb1m8VwC6xMWl9ZRF8Uace6SdOd/RUEe1S8DzEbsta7Vo8Shf7En+S0lHWpowwfmC2ZtEXgbsGkL8P6i+t2XYZFYV6xT2EugoYAmM7iwHb5fAb8d1mJ9ol20+diUptkhQzFGley/dGAbsiUAKgk7ooGo=\n"
"-----END CERTIFICATE-----\n";

// Shared known SHA-1 thumbprint for kKnownCertPem
static const char* kKnownCertThumbSha1 = "7523ff87ad66511531ac7562b2b7d45794b34940";

// Second static certificate/key set provided by user
// Thumbprint (SHA-1): d532132bab7cb693d251065a3e22c24323eed5be
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

static const char* kSecondCertThumbSha1 = "d532132bab7cb693d251065a3e22c24323eed5be";

// Base64 DER for x5c of the second cert
static const char* kSecondCertX5C =
"MIIDSTCCAjGgAwIBAgIUGmyniHckFa8a/CUMh7SFjTawk7gwDQYJKoZIhvcNAQELBQAwNDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENlcGhUZXN0MRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjUxMTEwMTEwMzI3WhcNMjYxMTEwMTEwMzI3WjA0MQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2VwaFRlc3QxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALh8paoUhRBAuAc2LP26b8G8Z5xgSIv9L4b5iaeUzXQrdrSBo1FQs3DZuYDy4MAsecgC1aLF99/wCZqhF3OAO5NWbvAu/VDW80FUQyXSg21XMEqGoMXhs8Cc0uoSsM5OlBEyL0aJ9HQb1BUkkZbT+DubMLY7CV9gsh8vnN1wwtTep+u2m9Drt7IUIp6qOnLyshffouEENmAveR2ip7LRwuvwTNaNjqSC18TFxAhr+pE0c32SrdSYM2ehLdUQg5cDp/5j/0TptodX4GGLu4pxxa1eempkb33wB+9e/9/xskNHmvPg0hIngVQMDZCQM2gsMS79D0o/gTlI6N3gEOFlSQMCAwEAAaNTMFEwHQYDVR0OBBYEFOT+Ce+kVdZIH9Y6Uo0EsrqjfqDjMB8GA1UdIwQYMBaAFOT+Ce+kVdZIH9Y6Uo0EsrqjfqDjMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAD6MS2DLZwOeD05/HgU9nt0R3MJG8/wUcV9cnsLLRuTWcCnXEBteyiWKffGBQ5Acb5FXdftitAovYJ02dWcNBmaa0MmTLy1QwaB+r0lpzITuLWkbpvaoaxLyY+04NihlP6IkXq50uypVyxwxvepVDzd5R5+SrygNsBB5AbqWmiwdJmXNFjhxAKACCDY4JC93MLJV2Z/lCshYk77a/0UQyJHtAJzXxJZaNxW5TY+o+NEifQmhvUqUrsWdwgBkhy663La6Ikpl/GBUCWGrq2CpyHYR6uo2GCA+MZ6T3BHPx0CaG2nUnzkQDBVCTclTsSOl5zUxcJ4uck/3ozTFq8OP7D8=";

// Private key PEM for the second cert
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
  // Also ensure mixing correct + incorrect still passes (selection scans all)
  std::vector<std::string> mixed{wrong_thumb, known_thumb};
  ASSERT_TRUE(rgw::auth::sts::detail::compute_thumbprint_match(mixed, kKnownCertPem));
}

// Characterization test for JWKS selection logic shape (no network, pure JSON)
TEST(RGW_STS_Unit, BuildJWKSWrongThenRight) {
  const std::string right_thumb = kSecondCertThumbSha1;
  const std::string wrong_x5c = pem_to_x5c_b64(kKnownCertPem);
  const std::string right_x5c = kSecondCertX5C;
  auto jwks = build_jwks_with_wrong_then_right(wrong_x5c, right_x5c);

  // Parse jwks using Ceph JSONParser just like production will
  JSONParser parser;
  ASSERT_TRUE(parser.parse(jwks.c_str(), jwks.size()));
  JSONObj* val = parser.find_obj("keys");
  ASSERT_TRUE(val != nullptr && val->is_array());
  auto keys = val->get_array_elements();
  ASSERT_EQ(keys.size(), 2u);

  // Characterize current selection behavior: first non-matching x5c prevents selecting second
  // We simulate skip_thumbprint_verification=false to require match.
  std::vector<std::string> thumbprints{right_thumb};
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
  const std::string cert_right = kSecondCertPem;
  const std::string priv_right = kSecondPrivPem;
  const std::string cert_wrong = kKnownCertPem;

  // Create a JWT signed by the right private key
  // Extract RSA key for jwt-cpp (PEM)
  auto token = jwt::create()
      .set_issuer("https://issuer.test")
      .set_audience("aud")
      .set_type("JWT")
      .set_algorithm("RS256")
      .set_subject("subj")
      .sign(jwt::algorithm::rs256(cert_right, priv_right, "", ""));

  auto decoded = jwt::decode(token);
  ASSERT_EQ(decoded.get_algorithm(), std::string("RS256"));

  // Wrong cert should fail
  ASSERT_FALSE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded, "RS256", cert_wrong));

  // Right cert should succeed
  ASSERT_TRUE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded, "RS256", cert_right));
}
