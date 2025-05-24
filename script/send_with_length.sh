#!/bin/bash

# send_with_length.sh sends a binary message to a server using nc, prepending a 2-byte big-endian length.
# Usage: echo -n "message" | ./send_with_length.sh <host> <port> [count]
#    or: ./send_with_length.sh <host> <port> <message_file> [count]

set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
	printf 'usage: %s <host> <port> [message_file] [count]\n' "$0" >&2
	exit 1
fi

host="$1"
port="$2"
count=1

# Parse arguments to determine message source and count.
if [ "$#" -eq 3 ]; then
	# Check if third argument is a file or a count.
	if [ -f "$3" ]; then
		messageFile="$3"
	elif [[ "$3" =~ ^[0-9]+$ ]]; then
		count="$3"
	else
		printf 'error: third argument must be a file or a number\n' >&2
		exit 1
	fi
elif [ "$#" -eq 4 ]; then
	messageFile="$3"
	if [[ "$4" =~ ^[0-9]+$ ]]; then
		count="$4"
	else
		printf 'error: count must be a number\n' >&2
		exit 1
	fi
fi

# Validate message file if specified.
if [ -n "${messageFile:-}" ]; then
	if [ ! -f "$messageFile" ]; then
		printf 'error: message file not found: %s\n' "$messageFile" >&2
		exit 1
	fi
fi

# Function to send a single message.
sendMessage() {
	if [ -n "${messageFile:-}" ]; then
		cat "$messageFile" | "$(dirname "$0")/prepend_length.sh" | tee >(printf '' >&2; hexdump -C >&2) | nc "$host" "$port" | (printf '' >&2; hexdump -C >&2)
	else
		"$(dirname "$0")/prepend_length.sh" | tee >(printf '' >&2; hexdump -C >&2) | nc "$host" "$port" | (printf '' >&2; hexdump -C >&2)
	fi
}

# Send messages based on count.
if [ -n "${messageFile:-}" ]; then
	printf 'sending message from file: %s (%d times)\n' "$messageFile" "$count" >&2
	for ((i=1; i<=count; i++)); do
		printf 'request %d/%d:\n' "$i" "$count" >&2
		sendMessage
		if [ "$i" -lt "$count" ]; then
			printf '\n' >&2
		fi
	done
else
	printf 'sending message from stdin (%d times)\n' "$count" >&2
	# Read stdin once and store it.
	message=$(cat)
	for ((i=1; i<=count; i++)); do
		printf 'request %d/%d:\n' "$i" "$count" >&2
		printf '%s' "$message" | "$(dirname "$0")/prepend_length.sh" | tee >(printf '' >&2; hexdump -C >&2) | nc "$host" "$port" | (printf '' >&2; hexdump -C >&2)
		if [ "$i" -lt "$count" ]; then
			printf '\n' >&2
		fi
	done
fi
