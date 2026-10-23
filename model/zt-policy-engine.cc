

// === zt-policy-engine.cc ===
#include "zt-policy-engine.h"
#include "zt-identity-registry.h"
#include "zt-hash-utils.h"

#include <ns3/log.h>
#include <ns3/simulator.h>
#include <sstream>
#include <algorithm>

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("ZtPolicyEngine");
NS_OBJECT_ENSURE_REGISTERED(ZtPolicyEngine);

// ===================== TypeId =====================
TypeId ZtPolicyEngine::GetTypeId() {
  static TypeId tid = TypeId("ZtPolicyEngine")
    .SetParent<Object>()
    .SetGroupName("ZeroTrust")
    .AddConstructor<ZtPolicyEngine>();
  return tid;
}

// ===================== Constructor =====================
ZtPolicyEngine::ZtPolicyEngine()
  : m_policyVersion(0)
{
}

// ===================== Destructor (ADDED FIX) =====================
ZtPolicyEngine::~ZtPolicyEngine()
{
}

// ===================== BASIC AUTH =====================
void ZtPolicyEngine::AddAuthorized(uint32_t nodeId, const std::string& role) {
  authTable[nodeId] = role;
}

bool ZtPolicyEngine::Authorize(uint32_t nodeId, const std::string& role) {
  return authTable.find(nodeId) != authTable.end() &&
         authTable[nodeId] == role;
}

// ===================== CERTIFICATE =====================
void ZtPolicyEngine::SetCaPublicKey(ZtCaSigner::PublicKey pub) {
  caPublicKey = pub;
}

void ZtPolicyEngine::Revoke(uint32_t nodeId) {
  revoke.insert(nodeId);
}

bool ZtPolicyEngine::AuthorizeWithCert(uint32_t nodeId,
                                       const std::string& role,
                                       const std::string& certStr) {
  if (revoke.find(nodeId) != revoke.end()) {
    NS_LOG_INFO("ZT-CERT: Node " << nodeId << " is revoked");
    return false;
  }

  return VerifyIdentityCertificate(caPublicKey, nodeId, role, certStr);
}

// ===================== MICRO-SEGMENTATION =====================

// Add rule
void ZtPolicyEngine::AddRolePolicyRule(const RolePolicyRule& rule) {
  m_rules.push_back(rule);
  m_policyVersion++;

  NS_LOG_INFO("[POLICY] Rule Added. Version: " << m_policyVersion);
}

// Time check
bool ZtPolicyEngine::IsWithinTime(uint32_t startHour,
                                 uint32_t endHour) {
  // Simulation time 0 is midnight of day 0
  uint32_t hour = static_cast<uint32_t>(Simulator::Now().GetHours()) % 24;

  return (hour >= startHour && hour < endHour);
}

// Behavior tracking
uint32_t ZtPolicyEngine::GetBehaviorState(uint32_t nodeId,
                                          uint32_t windowSeconds) {
  Time now = Simulator::Now();
  auto& history = m_transferHistory[nodeId];

  history.erase(
    std::remove_if(history.begin(), history.end(),
      [&](const Time& t) { return now - t > Seconds(windowSeconds); }),
    history.end());

  return history.size();
}

// Core evaluation
bool ZtPolicyEngine::EvaluateMicroSegmentation(
    Ptr<Node> srcNode,
    Ptr<Node> dstNode,
    const std::string& action) {

  if (!srcNode || !dstNode) {
    NS_LOG_WARN("[MICRO-SEG] Invalid Node Pointer");
    return false;
  }

  IdentityRegistry& registry =
      IdentityRegistry::GetInstance();

  std::string Hs = registry.GetIdentityHash(srcNode);
  std::string Hd = registry.GetIdentityHash(dstNode);

  std::string srcRole = registry.GetRole(srcNode);
  std::string dstRole = registry.GetRole(dstNode);

  uint32_t nodeId = srcNode->GetId();

  Time now = Simulator::Now();
  uint32_t currentHour = static_cast<uint32_t>(now.GetHours()) % 24;

  for (const auto& rule : m_rules) {
    if (rule.srcRole == srcRole &&
        rule.dstRole == dstRole &&
        (rule.action == action || rule.action == "*")) {

      if (!IsWithinTime(rule.startHour, rule.endHour))
        continue;

      uint32_t transferCount =
          GetBehaviorState(nodeId, rule.windowSeconds);

      uint32_t behaviorState =
          (transferCount <= rule.maxTransfers) ? 0 : 1;

      std::string S =
          Hs + Hd +
          action +
          std::to_string(currentHour) +
          rule.srcRole +
          rule.dstRole +
          std::to_string(behaviorState);

      std::string Psi = ns3::ComputeSha256(S);

      NS_LOG_DEBUG("[MICRO-SEG] Ψ: " << Psi);

      if (behaviorState == 0 &&
          rule.effect == ALLOW) {

        if (action == "TRANSFER" || action == "WITHDRAW") {
          m_transferHistory[nodeId].push_back(now);
        }

        return true;
      }

      if (rule.effect == DENY) {
        return false;
      }
    }
  }

  NS_LOG_INFO("[MICRO-SEG] Default DENY (Least Privilege)");
  return false;
}

// ===================== POLICY INTEGRITY =====================
uint32_t ZtPolicyEngine::GetPolicyVersion() const {
  return m_policyVersion;
}

std::string ZtPolicyEngine::GetPolicyIntegrityHash() const {
  std::stringstream ss;

  ss << m_policyVersion;

  for (const auto& rule : m_rules) {
    ss << rule.srcRole
       << rule.dstRole
       << rule.action
       << rule.startHour
       << rule.endHour
       << rule.windowSeconds
       << rule.maxTransfers
       << rule.effect;
  }

  return ns3::ComputeSha256(ss.str());
}

} // namespace ns3
