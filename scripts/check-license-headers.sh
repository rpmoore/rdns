#!/usr/bin/env bash
# Checks that every Rust source file contains the Apache 2.0 license header.
set -euo pipefail

HEADER_LINE="Licensed under the Apache License, Version 2.0"
FAILED=0

while IFS= read -r -d '' file; do
    if ! grep -q "$HEADER_LINE" "$file"; then
        echo "ERROR: Missing Apache 2.0 license header in: $file"
        FAILED=1
    fi
done < <(find . -name "*.rs" -not -path "./.git/*" -print0)

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "One or more Rust source files are missing the Apache 2.0 license header."
    echo "Each .rs file must start with a header containing:"
    echo "  // Licensed under the Apache License, Version 2.0"
    exit 1
fi

echo "All Rust source files have the Apache 2.0 license header."
