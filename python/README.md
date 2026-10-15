# Zero Trust IoT Python Simulation (ns-3)

This directory contains the complete Python migration of the **Zero Trust Module for IoT in ns-3**.

---

##  Directory Structure

```text
python/
├── model/                               # Core Zero Trust security modules
│   ├── __init__.py                      # Package entry point
│   ├── zt_hash_utils.py                 # SHA-256 hash utilities
│   ├── zt_logger.py                     # Structured simulation logger
│   ├── zt_identity_registry.py          # Singleton Identity Registry
│   ├── zt_certificate.py                # RSA Certificate Authority & verification
│   ├── zt_encryption_utils.py           # AES-CBC 128-bit encryption/decryption
│   ├── zt_policy_engine.py              # Micro-segmentation & Policy Engine
│   ├── zt_tls_handshake.py              # TLS-like session key handshake
│   ├── zt_dynamic_trust_scorer.py       # Sliding-window dynamic trust scorer
│   ├── zt_context_drift_validator.py    # Continuous context drift validator
│   ├── zt_ipv4_hook.py                  # IP-layer transmission hook
│   └── zt_scheduler.py                  # ns-3 event scheduling bridge (cppyy)
├── examples/                            # Zero Trust simulation examples
│   ├── micro-segmentation-test.py       # Role & time-based micro-segmentation test
│   ├── trust-scorer-test.py             # Burst violation and trust penalty test
│   ├── context-drift-test.py            # Context drift and rare outlier detection
│   ├── mitm/
│   │   ├── mitm-attack.py               # Man-in-the-Middle attack scenario
│   │   └── mitm-mitigation.py           # Zero Trust mitigation against MITM
│   ├── spoofing/
│   │   ├── spoofing-attack.py           # Identity spoofing attack scenario
│   │   └── spoofing-mitigation.py       # Identity hash & trust mitigation
│   └── unauthorized-access/
│       ├── unauthorized-access-attack.py     # Unauthorized device access attempt
│       └── unauthorized-access-mitigation.py # Continuous revalidation mitigation
└── run_all_tests.py                     # Automated test runner for all 9 scenarios
```

---

##  Running Examples

### Prerequisites

1. ns-3 with Python bindings enabled:
   ```bash
   cd ~/Desktop/ns-allinone-3.46.1/ns-3.46.1
   ./ns3 configure --enable-python-bindings
   ./ns3 build
   ```

2. Python dependencies:
   ```bash
   pip install cryptography cppyy
   ```

### Run an Individual Example

From the ns-3 root directory:

```bash
cd ~/Desktop/ns-allinone-3.46.1/ns-3.46.1
./ns3 run /python/examples/micro-segmentation-test.py
./ns3 run /python/examples/trust-scorer-test.py
./ns3 run /python/examples/context-drift-test.py
./ns3 run /python/examples/mitm/mitm-attack.py
./ns3 run /python/examples/mitm/mitm-mitigation.py
./ns3 run /python/examples/spoofing/spoofing-attack.py
./ns3 run /python/examples/spoofing/spoofing-mitigation.py
./ns3 run /python/examples/unauthorized-access/unauthorized-access-attack.py
./ns3 run /zero-trust-iot/python/examples/unauthorized-access/unauthorized-access-mitigation.py
```

### Run All Tests

To run the entire suite in one go:

```bash
python3 /home/err/Documents/zero-trust-iot/python/run_all_tests.py
```
