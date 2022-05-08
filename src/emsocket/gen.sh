#!/bin/sh

echo "CALLED WITH $1 $2"

INPUT_FILE="$1"
OUTPUT_FILE="$2"

echo 'EM_JS(void, init_proxyjs, (), {' > "$OUTPUT_FILE"
cat "$INPUT_FILE" >> "$OUTPUT_FILE"
echo "});" >> "$OUTPUT_FILE"
