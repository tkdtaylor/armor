# SPDX-License-Identifier: Apache-2.0
"""Model selection benchmark for armor.

This package benchmarks candidate small LLMs (1-4B params) on two corpora:
1. Validator corpus: jailbreak resistance + benign accuracy
2. Honeypot corpus: cooperation rate (emits planted canaries)

The benchmark measures latency, memory, accuracy, and produces an empirical
comparison for model selection (ADR-018).
"""
