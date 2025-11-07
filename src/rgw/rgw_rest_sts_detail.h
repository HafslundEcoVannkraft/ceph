// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab ft=cpp

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>

#include <boost/optional.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "jwt-cpp/jwt.h"
#include "rgw_common.h" // DoutPrefixProvider

namespace rgw { namespace auth { namespace sts { namespace detail {

// Compute if PEM certificate's SHA-1 thumbprint matches any in list
inline bool compute_thumbprint_match(const std::vector<std::string>& thumbprints,
                                     const std::string& cert_pem)
{
  std::unique_ptr<BIO, decltype(&BIO_free_all)> certbio(BIO_new_mem_buf(cert_pem.data(), cert_pem.size()), BIO_free_all);
  std::string pw;
  std::unique_ptr<X509, decltype(&X509_free)> x509(PEM_read_bio_X509(certbio.get(), nullptr, nullptr, const_cast<char*>(pw.c_str())), X509_free);
  const EVP_MD* md = EVP_sha1();
  unsigned int fsize = 0;
  unsigned char fprint[EVP_MAX_MD_SIZE];
  if (!x509 || !X509_digest(x509.get(), md, fprint, &fsize)) {
    return false;
  }
  std::stringstream ss;
  for (unsigned int i = 0; i < fsize; ++i) {
    ss << std::setfill('0') << std::setw(2) << std::hex << (0xFF & (unsigned int)fprint[i]);
  }
  const std::string digest = ss.str();
  for (const auto& tp : thumbprints) {
    if (boost::iequals(tp, digest)) {
      return true;
    }
  }
  return false;
}

// Select first matching certificate from x5c (order preserved). If skip_thumbprint_verification
// is true, returns the first certificate in x5c.
inline boost::optional<std::string> select_cert_from_x5c(
    const DoutPrefixProvider* dpp,
    const std::vector<std::string>& thumbprints,
    const std::vector<std::string>& x5c,
    bool skip_thumbprint_verification)
{
  std::string cert;
  for (const auto& it : x5c) {
    cert = std::string("-----BEGIN CERTIFICATE-----\n") + it + "\n-----END CERTIFICATE-----";
    ldpp_dout(dpp, 20) << "Certificate is: " << cert.c_str() << dendl;
    if (skip_thumbprint_verification || compute_thumbprint_match(thumbprints, cert)) {
      return cert;
    }
  }
  return boost::none;
}

// Verify a decoded JWT against a single PEM certificate for supported algorithms.
inline bool verify_with_cert(
    const DoutPrefixProvider* dpp,
    const jwt::decoded_jwt& decoded,
    const std::string& algorithm,
    const std::string& cert)
{
  try {
    if (algorithm == "RS256") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs256{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "RS384") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs384{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "RS512") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::rs512{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "ES256") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::es256{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "ES384") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::es384{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "ES512") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::es512{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "PS256") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::ps256{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "PS384") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::ps384{cert});
      verifier.verify(decoded);
      return true;
    } else if (algorithm == "PS512") {
      auto verifier = jwt::verify().allow_algorithm(jwt::algorithm::ps512{cert});
      verifier.verify(decoded);
      return true;
    } else {
      ldpp_dout(dpp, 5) << "Unsupported algorithm: " << algorithm << dendl;
    }
  } catch (const std::exception& e) {
    ldpp_dout(dpp, 10) << "Signature validation using x5c failed" << e.what() << dendl;
    return false;
  }
  return false;
}

}}}} // namespaces
