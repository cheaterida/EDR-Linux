# M3 Audit Checklist

- Gate: `make verify-m3`
- Required detection: at least 6 of 8 malicious S01-S08 host behavior samples
- Required false positives: at most 2 of 8 benign F01-F08 samples
- Evidence artifact: `audit/verify-m3-report.json`
- Performance evidence: report includes Python harness CPU time and max RSS; Go agent runtime profiling is deferred until Go toolchain is available
- Ring0 statement: v0.1 does not implement LKM, eBPF, kernel hooks, or self-defense
- Management surface: local Unix Socket only, no TCP listener by default
