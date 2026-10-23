# Uses the C++ zero-trust-iot library from Python through ns-3's cppyy bindings.
# Run from the ns-3 root: ./ns3 run contrib/zero-trust-iot/examples/certificate-example.py

from ns import ns
import cppyy

ca = cppyy.gbl.CertificateAuthority()
cert = ca.SignIdentity(7, "sensor", ns.Seconds(10))
print("Issued:", cert)

engine = ns.CreateObject[ns.ZtPolicyEngine]()
engine.SetCaPublicKey(ca.GetPublicKey())
print("Node 7 as sensor:", engine.AuthorizeWithCert(7, "sensor", cert))
print("Node 8 with node 7's cert:", engine.AuthorizeWithCert(8, "sensor", cert))

engine.Revoke(7)
print("Node 7 after revocation:", engine.AuthorizeWithCert(7, "sensor", cert))
