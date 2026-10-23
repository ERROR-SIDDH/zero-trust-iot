#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/zero-trust-iot-module.h"

using namespace ns3;

/**
 * \brief Certificates are ECDSA-signed and expire against simulation time.
 */
class ZtCertificateTestCase : public TestCase
{
public:
  ZtCertificateTestCase() : TestCase("ECDSA certificate signing, verification and expiry") {}

private:
  void DoRun() override
  {
    CertificateAuthority ca;
    CertificateAuthority rogue;
    std::string cert = ca.SignIdentity(7, "sensor", Seconds(10));

    NS_TEST_ASSERT_MSG_EQ(VerifyIdentityCertificate(ca.GetPublicKey(), 7, "sensor", cert), true,
                          "valid certificate rejected");
    NS_TEST_ASSERT_MSG_EQ(VerifyIdentityCertificate(ca.GetPublicKey(), 8, "sensor", cert), false,
                          "wrong node id accepted");
    NS_TEST_ASSERT_MSG_EQ(VerifyIdentityCertificate(ca.GetPublicKey(), 7, "sensor",
                                                    rogue.SignIdentity(7, "sensor", Seconds(10))),
                          false, "certificate from untrusted CA accepted");

    std::string forged = cert;
    forged.replace(forged.find("ROLE:sensor"), 11, "ROLE:admin!");
    NS_TEST_ASSERT_MSG_EQ(VerifyIdentityCertificate(ca.GetPublicKey(), 7, "admin!", forged), false,
                          "tampered certificate accepted");

    bool expired = true;
    Simulator::Schedule(Seconds(11), [&] {
      expired = !VerifyIdentityCertificate(ca.GetPublicKey(), 7, "sensor", cert);
    });
    Simulator::Run();
    Simulator::Destroy();
    NS_TEST_ASSERT_MSG_EQ(expired, true, "certificate still valid after its simulated expiry");
  }
};

/**
 * \brief Micro-segmentation time windows and rate limits follow simulation time.
 */
class ZtMicroSegmentationTestCase : public TestCase
{
public:
  ZtMicroSegmentationTestCase() : TestCase("Micro-segmentation uses simulation time") {}

private:
  void DoRun() override
  {
    NodeContainer nodes;
    nodes.Create(2);
    IdentityRegistry::GetInstance().RegisterNode(nodes.Get(0), "Maint");
    IdentityRegistry::GetInstance().RegisterNode(nodes.Get(1), "Server");

    Ptr<ZtPolicyEngine> engine = CreateObject<ZtPolicyEngine>();
    engine->AddRolePolicyRule({"Maint", "Server", "UPDATE", 2, 4, 60, 2, ZtPolicyEngine::ALLOW});
    engine->AddRolePolicyRule({"Maint", "Server", "TRANSFER", 0, 24, 60, 1, ZtPolicyEngine::ALLOW});

    auto eval = [&](const std::string& action) {
      return engine->EvaluateMicroSegmentation(nodes.Get(0), nodes.Get(1), action);
    };

    // Simulation time 0 is 00:00, outside the 02:00-04:00 window
    NS_TEST_ASSERT_MSG_EQ(eval("UPDATE"), false, "UPDATE allowed outside its time window");

    bool at3h[4] = {};
    bool afterWindow = false;
    Simulator::Schedule(Hours(3), [&] {
      at3h[0] = eval("UPDATE");
      for (int i = 1; i < 4; i++)
      {
        at3h[i] = eval("TRANSFER");
      }
    });
    Simulator::Schedule(Hours(3) + Seconds(61), [&] { afterWindow = eval("TRANSFER"); });
    Simulator::Run();
    Simulator::Destroy();

    NS_TEST_ASSERT_MSG_EQ(at3h[0], true, "UPDATE denied inside its time window");
    NS_TEST_ASSERT_MSG_EQ(at3h[1], true, "first TRANSFER denied");
    NS_TEST_ASSERT_MSG_EQ(at3h[2], true, "second TRANSFER denied");
    NS_TEST_ASSERT_MSG_EQ(at3h[3], false, "TRANSFER over the rate limit allowed");
    NS_TEST_ASSERT_MSG_EQ(afterWindow, true, "TRANSFER still denied after the window slid");
  }
};

class ZeroTrustIotTestSuite : public TestSuite
{
public:
  ZeroTrustIotTestSuite() : TestSuite("zero-trust-iot", Type::UNIT)
  {
    AddTestCase(new ZtCertificateTestCase, TestCase::Duration::QUICK);
    AddTestCase(new ZtMicroSegmentationTestCase, TestCase::Duration::QUICK);
  }
};

static ZeroTrustIotTestSuite g_zeroTrustIotTestSuite;
