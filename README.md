# Zero trust Module for IoT devices in  ns-3
The modules developed within this Zero Trust IoT library for ns-3 work in close coordination to form a comprehensive, layered security architecture that simulates the real-world enforcement of Zero Trust principles in constrained, distributed environments like the Internet of Things (IoT). Each module addresses a distinct facet of Zero Trust—identity, policy enforcement, encryption, session security, and observability—but their true strength lies in how they interact to build a coherent and enforceable trust boundary around every node and communication event within the network.

## Getting Started

1. Clone the ns-3 mainline code

    ```bash
    git clone -b ns-3.45 https://gitlab.com/nsnam/ns-3-dev.git
    ```
2. Change into the contrib directory

    ```bash
    cd contrib
    ```
3. Clone the Zero Trust Simulation Module

    ```bash
    git clone https://github.com/the-ns3-programmer/zero-trust-iot.git
    ```
4. Configure ns-3 and build it. Ensure [cryptopp](https://github.com/weidai11/cryptopp) is installed:

    ```bash
    ./ns3 configure --enable-examples --enable-tests -- -DNS3_CRYPTOPP=ON
    ```

    ```bash
    ./ns3 build
    ```
5. Run the examples and the test suite from the ns-3 root:

    ```bash
    ./ns3 run mitm-mitigation
    ./test.py -s zero-trust-iot
    ```
6. The C++ library can also be used from Python through ns-3's cppyy bindings (configure with `--enable-python-bindings`):

    ```bash
    ./ns3 run contrib/zero-trust-iot/examples/certificate-example.py
    ```

Simulation time is the only clock the module uses: certificate expiry is an `ns3::Time`, and micro-segmentation hour windows treat simulation time 0 as 00:00.
Core components log through `NS_LOG`, e.g. `NS_LOG="ZtPolicyEngine=level_info|ZtCertificate=level_info"`.

## What's New (since v2.0.0)

### Fixes
- **Deterministic simulation time:** the policy engine, certificate verification and `ZtLogger` used the computer's wall clock (`std::time`/`std::localtime`). They now use `Simulator::Now()`, so time-window rules, certificate expiry and log timestamps give the same result on every run.
- **Build fix:** `zt-context-drift-validator.cc` did not compile (`CalculateDrift` was missing `const`). A missing `{ }` also made every revalidated node print "revoked due to low trust".

### Security
- **ECDSA certificates:** the Certificate Authority now signs with ECDSA on secp256r1 (P-256) with SHA-256, replacing RSA-1024 with SHA-1. Signatures are smaller, which suits constrained IoT links, and key generation is faster.
- **Single verification path:** `ZtPolicyEngine::AuthorizeWithCert` and `ZtPolicyEngineWithCert::Authorize` share one `VerifyIdentityCertificate()` function instead of two copies of the same code.

### Developer experience
- **Scoped logging:** the core engine logs through `NS_LOG_INFO`/`NS_LOG_DEBUG` (`ZtPolicyEngine`, `ZtCertificate`) instead of `NS_LOG_UNCOND`/`std::cout`, so you can turn verbosity up or down.
- **Native examples:** examples build with `--enable-examples` and run with `./ns3 run <name>`. You no longer copy them into `scratch/`.
- **Test suite:** `./test.py -s zero-trust-iot` checks certificate signing, forgery and tampering rejection, simulated expiry, the micro-segmentation time window and the rate limit.
- **Python:** the C++ library can be used from Python through ns-3's cppyy bindings (`examples/certificate-example.py`). No separate Python port is needed.

### API changes when upgrading
- `CertificateAuthority::SignIdentity(nodeId, role, expiry)` and `ZtLogger::LogCertIssued(...)` take an `ns3::Time` expiry, e.g. `Simulator::Now() + Seconds(60)`, instead of `time_t`.
- `GetPublicKey()` / `SetCaPublicKey()` use `ZtCaSigner::PublicKey` (ECDSA) instead of `CryptoPP::RSA::PublicKey`.
- Micro-segmentation `startHour`/`endHour` are hours of the simulated day, with simulation time 0 counted as 00:00.

## Contributors

### Core Maintainers

| Name | Affiliation | Contact |
| :--- | :--- | :--- |
| **Arun Santhosh R A** | Final year B.Tech CSE, VIT Chennai | [arunsanthosh.rashok@gmail.com](mailto:arunsanthosh.rashok@gmail.com) |
| **Dr. Subbulakshmi T** | Professor, VIT Chennai | [subbulakshmibest@gmail.com](mailto:subbulakshmibest@gmail.com) |

### Release v2.0.0 Contributors

| Name | Affiliation | Contact |
| :--- | :--- | :--- |
| **Rahul S** | IInd year B.Tech CSE, VIT Chennai | [rahulsaravanan3052@gmail.com](mailto:rahulsaravanan3052@gmail.com) |
| **Muthu Venkatesh M** | IInd year B.Tech CSE, VIT Chennai | [muthuvenkat2426@gmail.com](mailto:muthuvenkat2426@gmail.com) |
| **Rahul R** | IInd year B.Tech CSE, VIT Chennai | [rahulsubha1983@gmail.com](mailto:rahulsubha1983@gmail.com) |



## License

This software is licensed under the terms of the GNU GPLv2, as like as ns-3.
See the LICENSES folder for more details.

