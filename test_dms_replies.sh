#!/bin/bash

# Test script for hoot CLI - testing DM and reply functionality

echo "=== Testing Hoot CLI ==="
echo

# Test version
echo "1. Testing version flag:"
./hoot.exe -version
echo

# Test help shows new flags
echo "2. Testing help (should show -dms and -replies flags):"
./hoot.exe -h | grep -E "dms|replies"
echo

# Test without key (should show no DMs available)
echo "3. Testing DMs flag without key (should show error):"
./hoot.exe -dms 2>&1 | head -5
echo

# Test replies flag with fake event ID
echo "4. Testing replies flag with fake event ID:"
./hoot.exe -replies "test123" 2>&1 | head -5
echo

echo "=== Basic tests completed ==="
echo "For full DM/reply testing, you'll need a valid Nostr key and network connection."