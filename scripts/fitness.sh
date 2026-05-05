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

# Summary
echo ""
if [ $ERRORS -eq 0 ]; then
    echo "All fitness checks passed."
    exit 0
else
    echo "Fitness checks failed: $ERRORS error(s)"
    exit 1
fi
