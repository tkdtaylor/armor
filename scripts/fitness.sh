#!/bin/bash
# Fitness checks for armor project architecture invariants
# Exits 0 if all checks pass, 1 if any check fails

set -e

ERRORS=0

echo "Running fitness checks..."

# Check 1: No canary values in committed JSON files
echo -n "  Checking for hardcoded canary values in src/armor/canaries/*.json ... "
if git ls-files 'src/armor/canaries/*.json' | xargs grep -l '"value":' 2>/dev/null; then
    echo "FAIL"
    echo "    ERROR: Found 'value' field in committed canary files."
    echo "    Canary values must never be committed. Use 'armor canary generate' to create them."
    ERRORS=$((ERRORS + 1))
else
    echo "PASS"
fi

# Check 2: No outbound network imports in daemon code
echo -n "  Checking for outbound network imports in src/armor/daemon/ ... "
if uv run python tests/fitness/no_outbound_network.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/no_outbound_network.py
    ERRORS=$((ERRORS + 1))
fi

# Check 3: No literal canary values in prompt templates
echo -n "  Checking for canary values in prompt templates ... "
if uv run python tests/fitness/no_canary_in_prompts.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/no_canary_in_prompts.py
    ERRORS=$((ERRORS + 1))
fi

# Check 4: Validator module has no canary value access
echo -n "  Checking validator module for canary value access ... "
if uv run python tests/fitness/validator_no_value_access.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/validator_no_value_access.py
    ERRORS=$((ERRORS + 1))
fi

# Check 5: jailbreak.template corpus has required TP/TN counts per family
echo -n "  Checking jailbreak corpus TP/TN counts ... "
if uv run python tests/fitness/jailbreak_counts.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/jailbreak_counts.py
    ERRORS=$((ERRORS + 1))
fi

# Check 6: Corpus passes with ARMOR_DISABLE_LLM=true
echo -n "  Checking static-only corpus evaluation ... "
if uv run python tests/fitness/corpus_static_only.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/corpus_static_only.py
    ERRORS=$((ERRORS + 1))
fi

# Check 7: Daemon cold-start within budget
echo -n "  Checking daemon cold-start imports ... "
if uv run python tests/fitness/cold_start_budget.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/cold_start_budget.py
    ERRORS=$((ERRORS + 1))
fi

# Check 8: P95 LLM latency under budget (v0.3: stub with warnings)
echo -n "  Checking LLM P95 latency budget ... "
if uv run python tests/fitness/llm_p95_latency.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/llm_p95_latency.py
    ERRORS=$((ERRORS + 1))
fi

# Check 9: Validator soft-fail on timeout
echo -n "  Checking validator soft-fail behavior ... "
if uv run python tests/fitness/validator_soft_fail.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/validator_soft_fail.py
    ERRORS=$((ERRORS + 1))
fi

# Check 10: Session state machine transition coverage
echo -n "  Checking session state transition coverage ... "
if uv run python tests/fitness/transition_coverage.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/transition_coverage.py
    ERRORS=$((ERRORS + 1))
fi

# Check 11: Canary kinds match ADR-031 recipe table
echo -n "  Checking canary kinds match recipe table ... "
if uv run pytest tests/fitness/test_canary_kinds_match_recipe_table.py -v > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run pytest tests/fitness/test_canary_kinds_match_recipe_table.py -v
    ERRORS=$((ERRORS + 1))
fi

# Check 12: Payload.source propagation per IPC op (TC-065-24)
echo -n "  Checking Payload.source propagation per IPC op ... "
if uv run python tests/fitness/test_payload_source_propagation.py > /dev/null 2>&1; then
    echo "PASS"
else
    echo "FAIL"
    uv run python tests/fitness/test_payload_source_propagation.py
    ERRORS=$((ERRORS + 1))
fi

# Summary
echo ""
if [ $ERRORS -eq 0 ]; then
    echo "All fitness checks passed."
    exit 0
else
    echo "Fitness checks failed: $ERRORS error(s)"
    exit 1
fi
