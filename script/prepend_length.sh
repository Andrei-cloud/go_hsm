#!/bin/bash

# prepend_length.sh prepends a 2-byte big-endian length and 4-byte incremental header to binary stdin and writes to stdout.
# Usage: cat file | ./prepend_length.sh > out

set -euo pipefail

# Initialize or read counter from file.
counterFile="/tmp/prepend_length_counter"
if [ ! -f "$counterFile" ]; then
	printf '0' > "$counterFile"
fi

counter=$(cat "$counterFile")
nextCounter=$(((counter + 1) % 4294967296))
printf '%s' "$nextCounter" > "$counterFile"

# Read all input from stdin as binary data.
message=$(cat)

# Calculate the length of the message in bytes.
messageLength=$(printf '%s' "$message" | wc -c | tr -d ' ')

# Total length = header (4 bytes) + message length.
totalLength=$((4 + messageLength))

# Check if total length fits in 2 bytes.
if [ "$totalLength" -gt 65535 ]; then
	printf 'error: message too long (max 65531 bytes)\n' >&2
	exit 1
fi

# Split total length into high and low bytes.
high=$((totalLength >> 8))
low=$((totalLength & 0xFF))

# Format length as a 2-byte binary sequence.
lengthBin=$(printf '\\x%02x\\x%02x' "$high" "$low")

# Format 4-byte incremental header as big-endian binary.
headerBin=$(printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((counter >> 24 & 0xFF)) $((counter >> 16 & 0xFF)) $((counter >> 8 & 0xFF)) $((counter & 0xFF)))

# Prepend binary length, header, and original message.
printf '%b' "$lengthBin$headerBin$message"
