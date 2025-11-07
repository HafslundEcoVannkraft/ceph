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

namespace {

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

} // anonymous

TEST(RGW_STS_Unit, ThumbprintAndX5CHelpersWork) {
  auto [priv_pem, cert_pem] = generate_rsa_key_and_self_signed_cert_pem();
  auto thumb = sha1_thumbprint_from_pem(cert_pem);
  ASSERT_FALSE(thumb.empty());
  auto x5c = pem_to_x5c_b64(cert_pem);
  ASSERT_FALSE(x5c.empty());

  std::vector<std::string> tps{thumb};
  // Should match using detail helper
  ASSERT_TRUE(rgw::auth::sts::detail::compute_thumbprint_match(tps, cert_pem));

  // sanity: x5c-based cert can be reconstructed by production code path later
}

// Characterization test for JWKS selection logic shape (no network, pure JSON)
TEST(RGW_STS_Unit, BuildJWKSWrongThenRight) {
  auto [priv_right, cert_right] = generate_rsa_key_and_self_signed_cert_pem();
  auto [priv_wrong, cert_wrong] = generate_rsa_key_and_self_signed_cert_pem();
  auto right_thumb = sha1_thumbprint_from_pem(cert_right);
  auto wrong_x5c = pem_to_x5c_b64(cert_wrong);
  auto right_x5c = pem_to_x5c_b64(cert_right);
  ASSERT_FALSE(right_thumb.empty());
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
  auto sel_first = rgw::auth::sts::detail::select_cert_from_x5c(&test_dpp, thumbprints, x5c_first, false);
  ASSERT_FALSE(sel_first.has_value()); // first cert not selected

  JSONParser k2; ASSERT_TRUE(k2.parse(keys[1].c_str(), keys[1].size()));
  std::vector<std::string> x5c_second; ASSERT_TRUE(JSONDecoder::decode_json("x5c", x5c_second, &k2));
  auto sel_second = rgw::auth::sts::detail::select_cert_from_x5c(&test_dpp, thumbprints, x5c_second, false);
  ASSERT_TRUE(sel_second.has_value()); // second cert selected
}

// Build and sign a JWT with RS256 using the right key, ensure verify_with_cert succeeds only with selected cert
TEST(RGW_STS_Unit, VerifyWithCertSucceedsWithMatchingCert) {
  auto [priv_right, cert_right] = generate_rsa_key_and_self_signed_cert_pem();
  auto [priv_wrong, cert_wrong] = generate_rsa_key_and_self_signed_cert_pem();
  auto right_thumb = sha1_thumbprint_from_pem(cert_right);
  auto wrong_x5c = pem_to_x5c_b64(cert_wrong);
  auto right_x5c = pem_to_x5c_b64(cert_right);

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

  std::vector<std::string> thumbprints{right_thumb};
  // Wrong cert should fail
  ASSERT_FALSE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded, "RS256", cert_wrong));
  // Right cert should succeed
  ASSERT_TRUE(rgw::auth::sts::detail::verify_with_cert(&test_dpp, decoded, "RS256", cert_right));
}
