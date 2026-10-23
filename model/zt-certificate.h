#ifndef ZT_CERTIFICATE_H
#define ZT_CERTIFICATE_H

#include <string>
#include <unordered_set>
#include <cryptopp/eccrypto.h>
#include <cryptopp/sha.h>
#include <ns3/nstime.h>

/// ECDSA over secp256r1 (P-256) with SHA-256: small signatures suited to constrained IoT links.
using ZtCaSigner = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;

/**
 * \class CertificateAuthority
 * \brief Simulates a Certificate Authority (CA) that issues and signs identity certificates.
 *
 * The CA generates an ECDSA (secp256r1) key pair and uses it to sign certificates
 * for nodes, which include identity, role, and expiry information.
 */
class CertificateAuthority {
public:
  /**
   * \brief Constructor that initializes and generates the ECDSA key pair.
   */
  CertificateAuthority();

  /**
   * \brief Signs an identity certificate with node ID, role, and expiry.
   * \param nodeId The unique identifier of the node.
   * \param role The assigned role of the node (e.g., "sensor", "gateway").
   * \param expiry Absolute simulation time at which the certificate expires.
   * \return A signed certificate string in plain format with a base64-encoded signature.
   */
  std::string SignIdentity(uint32_t nodeId, const std::string& role, ns3::Time expiry);

  /**
   * \brief Retrieves the public key of the CA.
   * \return The public key corresponding to the CA's private key.
   */
  ZtCaSigner::PublicKey GetPublicKey() const;

private:
  ZtCaSigner::PrivateKey privateKey; ///< Private key used for signing certificates.
  ZtCaSigner::PublicKey publicKey;   ///< Public key distributed for verification.
};

/**
 * \brief Verifies a certificate's signature, identity, role and expiry (against simulation time).
 * \param caPublicKey The public key of the trusted Certificate Authority.
 * \param nodeId The node's claimed ID.
 * \param role The role the node claims to perform.
 * \param certStr The certificate string presented by the node.
 * \return True if the certificate is authentic, matches the node and role, and has not expired.
 */
bool VerifyIdentityCertificate(const ZtCaSigner::PublicKey& caPublicKey,
                               uint32_t nodeId,
                               const std::string& role,
                               const std::string& certStr);

/**
 * \class ZtPolicyEngineWithCert
 * \brief Simulates a Zero Trust policy engine that enforces access control using certificates.
 *
 * This engine validates node certificates, verifies digital signatures, checks role and expiry,
 * and maintains a list of revoked node IDs.
 */
class ZtPolicyEngineWithCert {
public:
  /**
   * \brief Sets the CA's public key used for certificate verification.
   * \param pub The public key of the trusted Certificate Authority.
   */
  void SetCaPublicKey(ZtCaSigner::PublicKey pub);

  /**
   * \brief Revokes a node by its ID, preventing it from being authorized.
   * \param nodeId The node ID to be added to the revocation list.
   */
  void Revoke(uint32_t nodeId);

  /**
   * \brief Authorizes a node based on its certificate.
   * \param nodeId The node's claimed ID.
   * \param role The role the node claims to perform.
   * \param certStr The certificate string presented by the node.
   * \return True if the certificate is valid, not expired, matches the node, and not revoked.
   */
  bool Authorize(uint32_t nodeId, const std::string& role, const std::string& certStr);

private:
  ZtCaSigner::PublicKey caPublicKey;   ///< Trusted public key used for signature verification.
  std::unordered_set<uint32_t> revoke; ///< Set of node IDs that are explicitly revoked.
};

#endif // ZT_CERTIFICATE_H
