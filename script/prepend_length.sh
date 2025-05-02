#!/bin/bash

# Read binary message from stdin.
read message

# Calculate the length of the message in bytes.
message_length=${#message}

# Split length into high and low bytes.
high=$((message_length >> 8))
low=$((message_length & 0xFF))

# Format length as a 2-byte binary sequence.
length_bin=$(printf '\\x%02x\\x%02x' $high $low)

# Prepend binary length to the original message and send.
echo -ne "$length_bin$message"
