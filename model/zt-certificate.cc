#include "zt-certificate.h"
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <sstream>
#include <ns3/log.h>
#include <ns3/simulator.h>

using namespace CryptoPP;

NS_LOG_COMPONENT_DEFINE("ZtCertificate");

/**
 * \class CertificateAuthority
 * \brief Issues and signs certificates for Zero Trust identity validation.
 */
CertificateAuthority::CertificateAuthority() {
  AutoSeededRandomPool prng;
  privateKey.Initialize(prng, ASN1::secp256r1());
  privateKey.MakePublicKey(publicKey);
}

/**
 * \brief Signs a certificate with node ID, role, and expiry.
 * \param nodeId ID of the node requesting certificate
 * \param role Role assigned to the node (e.g., sensor, gateway)
 * \param expiry Absolute simulation time at which the certificate expires
 * \return Signed certificate string with base64-encoded signature
 */
std::string CertificateAuthority::SignIdentity(uint32_t nodeId, const std::string& role, ns3::Time expiry) {
  AutoSeededRandomPool prng;

  // EXP is stored in simulator time steps so it round-trips exactly
  std::ostringstream cert;
  cert << "ID:" << nodeId << "|ROLE:" << role << "|EXP:" << expiry.GetTimeStep();

  ZtCaSigner::Signer signer(privateKey);
  std::string signature;
  StringSource(cert.str(), true,
    new SignerFilter(prng, signer,
      new StringSink(signature)));

  std::string encodedSig;
  StringSource(signature, true,
    new Base64Encoder(new StringSink(encodedSig), false));

  return cert.str() + "|SIG:" + encodedSig;
}

/**
 * \brief Returns the public key of the Certificate Authority.
 * \return ECDSA public key
 */
ZtCaSigner::PublicKey CertificateAuthority::GetPublicKey() const {
  return publicKey;
}

bool VerifyIdentityCertificate(const ZtCaSigner::PublicKey& caPublicKey,
                               uint32_t nodeId,
                               const std::string& role,
                               const std::string& certStr) {
  size_t sigPos = certStr.find("|SIG:");
  if (sigPos == std::string::npos) return false;
  std::string content = certStr.substr(0, sigPos);
  std::string sig = certStr.substr(sigPos + 5);

  std::string decodedSig;
  StringSource(sig, true, new Base64Decoder(new StringSink(decodedSig)));

  ZtCaSigner::Verifier verifier(caPublicKey);
  bool valid = false;
  StringSource(decodedSig + content, true,
    new SignatureVerificationFilter(verifier,
      new ArraySink((byte*)&valid, sizeof(valid)),
      SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_BEGIN));

  if (!valid) {
    NS_LOG_INFO("ZT-CERT: Signature invalid");
    return false;
  }

  std::istringstream ss(content);
  std::string token;
  uint32_t idParsed = 0;
  std::string roleParsed;
  int64_t expiry = 0;

  while (std::getline(ss, token, '|')) {
    if (token.find("ID:") == 0)
      idParsed = std::stoul(token.substr(3));
    else if (token.find("ROLE:") == 0)
      roleParsed = token.substr(5);
    else if (token.find("EXP:") == 0)
      expiry = std::stoll(token.substr(4));
  }

  if (idParsed != nodeId || roleParsed != role) {
    NS_LOG_INFO("ZT-CERT: Identity mismatch");
    return false;
  }

  if (ns3::Simulator::Now() > ns3::TimeStep(expiry)) {
    NS_LOG_INFO("ZT-CERT: Certificate expired");
    return false;
  }

  return true;
}

/**
 * \brief Sets the CA public key for the policy engine.
 * \param pub Public key of the certificate authority
 */
void ZtPolicyEngineWithCert::SetCaPublicKey(ZtCaSigner::PublicKey pub) {
  caPublicKey = pub;
}

/**
 * \brief Revokes access for a specific node.
 * \param nodeId ID of the node to be revoked
 */
void ZtPolicyEngineWithCert::Revoke(uint32_t nodeId) {
  revoke.insert(nodeId);
}

/**
 * \brief Verifies and authorizes a node based on its certificate.
 * \param nodeId ID of the node attempting access
 * \param role Role of the node
 * \param certStr Certificate string to validate
 * \return True if the certificate is valid and authorization succeeds
 */
bool ZtPolicyEngineWithCert::Authorize(uint32_t nodeId, const std::string& role, const std::string& certStr) {
  if (revoke.find(nodeId) != revoke.end()) {
    NS_LOG_INFO("ZT-CERT: Node " << nodeId << " is revoked");
    return false;
  }
  return VerifyIdentityCertificate(caPublicKey, nodeId, role, certStr);
}
