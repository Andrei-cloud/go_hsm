#!/bin/bash

# parse_command.sh - Parses a command with binary field formatting and sends it to HSM server.
# Usage: ./parse_command.sh <command_string> <host> <port>
#
# Field format examples:
# - 8B:1111111111111100 - 8 bytes binary (hex value converted to binary)
# - 2H:74 - 2 hex characters representing decimal value 74 as hex "4A" 
# - 4B:52BF4585 - 4 bytes binary (hex value converted to binary)
# - B:0000000123000000000000000784800004800008402505220052BF45851800005E06011203; - variable length binary (until ';', delimiter included in output)
# - value without prefix - passed as-is
#
# Example:
# ./parse_command.sh "KQ00U7475636CC30B93B493CF5EA53799EBCC|8B:1111111111111100|2B:005E|4B:52BF4585|2H:74|B:0000000123000000000000000784800004800008402505220052BF45851800005E06011203;|8B:076C5766F738E9A6" 127.0.0.1 1500

set -euo pipefail

if [ "$#" -ne 3 ]; then
	printf 'usage: %s <command_string> <host> <port>\n' "$0" >&2
	printf '\nExample command format:\n' >&2
	printf 'KQ00U7475636CC30B93B493CF5EA53799EBCC|8B:1111111111111100|2B:005E|4B:52BF4585|2H:74|B:0000000123...;|8B:076C5766F738E9A6\n' >&2
	printf '\nField prefixes:\n' >&2
	printf '  8B: - 8 bytes binary (hex converted to binary)\n' >&2
	printf '  2H: - 2 hex characters\n' >&2
	printf '  4B: - 4 bytes binary (hex converted to binary)\n' >&2
	printf '  B:  - variable length binary (until ";", delimiter included in output)\n' >&2
	printf '  |   - field delimiter\n' >&2
	printf '  no prefix - value passed as-is\n' >&2
	exit 1
fi

commandString="$1"
host="$2"
port="$3"

# Function to convert hex string to binary.
hex_to_binary() {
	local hexString="$1"
	printf '%s' "$hexString" | xxd -r -p
}

# Function to validate hex string length is even.
validate_hex_length() {
	local hexString="$1"
	local expectedBytes="$2"
	
	if [ $((${#hexString} % 2)) -ne 0 ]; then
		printf 'error: hex string length must be even: %s\n' "$hexString" >&2
		return 1
	fi
	
	if [ -n "$expectedBytes" ] && [ $((${#hexString} / 2)) -ne "$expectedBytes" ]; then
		printf 'error: hex string must be exactly %d bytes (%d hex chars): %s\n' "$expectedBytes" $((expectedBytes * 2)) "$hexString" >&2
		return 1
	fi
	
	return 0
}

# Function to convert hex char to decimal.
hex_to_decimal() {
	local hexChar="$1"
	printf '%d' "0x$hexChar" 2>/dev/null || {
		printf 'error: invalid hex character: %s\n' "$hexChar" >&2
		return 1
	}
}

# Function to process a single field.
process_field() {
	local field="$1"
	local output=""
	
	# Check if field has a prefix.
	if [[ "$field" =~ ^([0-9]+)([BH]):(.*)$ ]]; then
		local size="${BASH_REMATCH[1]}"
		local format="${BASH_REMATCH[2]}"
		local value="${BASH_REMATCH[3]}"
		
		case "$format" in
			"B")
				# Binary format - hex converted to binary.
				if ! validate_hex_length "$value" "$size"; then
					return 1
				fi
				output=$(hex_to_binary "$value")
				;;
			"H")
				# Hex format - convert decimal value to hex and output as ASCII hex.
				# The size represents the number of hex characters, not bytes.
				# Check if value is a valid decimal number.
				if ! [[ "$value" =~ ^[0-9]+$ ]]; then
					printf 'error: hex field value must be a decimal number: %s\n' "$value" >&2
					return 1
				fi
				
				# Convert decimal to hex.
				local hexValue
				hexValue=$(printf '%x' "$value" 2>/dev/null) || {
					printf 'error: failed to convert decimal to hex: %s\n' "$value" >&2
					return 1
				}
				
				# Pad with leading zeros to match expected hex character length.
				local expectedHexChars="$size"
				while [ ${#hexValue} -lt "$expectedHexChars" ]; do
					hexValue="0$hexValue"
				done
				
				# Check if hex value fits in specified character length.
				if [ ${#hexValue} -gt "$expectedHexChars" ]; then
					printf 'error: decimal value %s (hex: %s) too large for %d hex characters\n' "$value" "$hexValue" "$size" >&2
					return 1
				fi
				
				# Convert to uppercase and output as ASCII hex.
				output=$(printf '%s' "$hexValue" | tr '[:lower:]' '[:upper:]')
				;;
			*)
				printf 'error: unknown format: %s\n' "$format" >&2
				return 1
				;;
		esac
	elif [[ "$field" =~ ^B:(.*)$ ]]; then
		# Variable length binary field (ends with ';').
		local value="${BASH_REMATCH[1]}"
		
		# Check if value ends with ';' and extract the hex data.
		if [[ "$value" =~ ^(.*)\;$ ]]; then
			local hexData="${BASH_REMATCH[1]}"
		else
			printf 'error: variable length binary field must end with ";": %s\n' "$field" >&2
			return 1
		fi
		
		if ! validate_hex_length "$hexData" ""; then
			return 1
		fi
		# Output the converted binary data followed by the semicolon delimiter.
		output="$(hex_to_binary "$hexData");"
	else
		# No prefix - pass as-is.
		output="$field"
	fi
	
	printf '%s' "$output"
}

# Parse the command string and build the binary message.
IFS='|' read -ra fields <<< "$commandString"

tempFile=$(mktemp)
trap 'rm -f "$tempFile"' EXIT

for field in "${fields[@]}"; do
	if ! process_field "$field" >> "$tempFile"; then
		printf 'error: failed to process field: %s\n' "$field" >&2
		exit 1
	fi
done

# Debug: show the hex representation of the parsed message.
printf 'parsed message hex: ' >&2
hexdump -v -e '/1 "%02x"' "$tempFile" >&2
printf '\n' >&2

# Send the message using the existing send_with_length.sh script.
cat "$tempFile" | "$(dirname "$0")/send_with_length.sh" "$host" "$port"
