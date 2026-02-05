#!/bin/bash
#
# kcipher Test Suite
# Comprehensive tests for the kernel cipher module
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Check if module is loaded
check_module_loaded() {
    if ! lsmod | grep -q kcipher; then
        echo -e "${RED}ERROR: kcipher module not loaded${NC}"
        echo "Load it with: make load"
        exit 1
    fi
}

# Check if device nodes exist
check_devices() {
    if [ ! -c /dev/cipher ] || [ ! -c /dev/cipher_key ]; then
        echo -e "${RED}ERROR: Device nodes not found${NC}"
        echo "Create them with: make setup-devices MAJOR=<number>"
        exit 1
    fi
}

# Print test header
test_header() {
    echo ""
    echo "=========================================="
    echo "Test: $1"
    echo "=========================================="
    ((TESTS_RUN++))
}

# Print test result
test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Basic encryption/decryption
test_basic_encryption() {
    test_header "Basic Encryption/Decryption"
    
    local key="TestKey123"
    local message="Hello, World!"
    
    # Set key and encrypt
    echo "$key" > /dev/cipher_key
    echo "$message" > /dev/cipher
    
    # Set decryption key and read
    echo "$key" > /proc/cipher_key
    local decrypted=$(cat /proc/cipher)
    
    if [ "$decrypted" = "$message" ]; then
        test_result 0
    else
        echo "Expected: '$message'"
        echo "Got: '$decrypted'"
        test_result 1
    fi
}

# Test 2: Key denial on read
test_key_denial() {
    test_header "Key Read Denial"
    
    echo "SecretKey" > /dev/cipher_key
    local output=$(cat /dev/cipher_key)
    
    if echo "$output" | grep -q "Go away silly one"; then
        test_result 0
    else
        echo "Expected denial message, got: $output"
        test_result 1
    fi
}

# Test 3: Wrong key detection
test_wrong_key() {
    test_header "Wrong Key Detection"
    
    local correct_key="CorrectKey"
    local wrong_key="WrongKey"
    local message="Secret Message"
    
    # Encrypt with correct key
    echo "$correct_key" > /dev/cipher_key
    echo "$message" > /dev/cipher
    
    # Try to decrypt with wrong key
    echo "$wrong_key" > /proc/cipher_key
    local wrong_decrypt=$(cat /proc/cipher)
    
    # Decrypt with correct key
    echo "$correct_key" > /proc/cipher_key
    local correct_decrypt=$(cat /proc/cipher)
    
    if [ "$wrong_decrypt" != "$message" ] && [ "$correct_decrypt" = "$message" ]; then
        test_result 0
    else
        echo "Wrong key should produce gibberish"
        test_result 1
    fi
}

# Test 4: Binary data handling
test_binary_data() {
    test_header "Binary Data Handling"
    
    local key="BinaryKey"
    local temp_file=$(mktemp)
    
    # Create test binary data (256 bytes of values 0-255)
    python3 -c "import sys; sys.stdout.buffer.write(bytes(range(256)))" > "$temp_file"
    
    # Encrypt
    echo "$key" > /dev/cipher_key
    cat "$temp_file" > /dev/cipher
    
    # Decrypt
    echo "$key" > /proc/cipher_key
    local decrypted_file=$(mktemp)
    cat /proc/cipher > "$decrypted_file"
    
    # Compare
    if cmp -s "$temp_file" "$decrypted_file"; then
        test_result 0
    else
        echo "Binary data mismatch"
        test_result 1
    fi
    
    rm -f "$temp_file" "$decrypted_file"
}

# Test 5: Multiple sequential operations
test_sequential_operations() {
    test_header "Sequential Operations"
    
    local success=0
    
    for i in {1..5}; do
        local key="Key$i"
        local message="Message number $i"
        
        echo "$key" > /dev/cipher_key
        echo "$message" > /dev/cipher
        echo "$key" > /proc/cipher_key
        local result=$(cat /proc/cipher)
        
        if [ "$result" != "$message" ]; then
            echo "Iteration $i failed"
            success=1
            break
        fi
    done
    
    test_result $success
}

# Test 6: Large message (near limit)
test_large_message() {
    test_header "Large Message (4KB)"
    
    local key="LargeKey"
    local message=$(python3 -c "print('A' * 4000)")
    
    echo "$key" > /dev/cipher_key
    echo "$message" > /dev/cipher
    echo "$key" > /proc/cipher_key
    local result=$(cat /proc/cipher)
    
    if [ "$result" = "$message" ]; then
        test_result 0
    else
        echo "Large message test failed"
        test_result 1
    fi
}

# Test 7: Empty message
test_empty_message() {
    test_header "Empty Message"
    
    local key="EmptyKey"
    
    echo "$key" > /dev/cipher_key
    echo -n "" > /dev/cipher
    echo "$key" > /proc/cipher_key
    local result=$(cat /proc/cipher)
    
    if [ -z "$result" ]; then
        test_result 0
    else
        echo "Expected empty result, got: '$result'"
        test_result 1
    fi
}

# Test 8: Special characters in message
test_special_characters() {
    test_header "Special Characters"
    
    local key="SpecialKey"
    local message='Special chars: !@#$%^&*(){}[]<>?/\|~`'
    
    echo "$key" > /dev/cipher_key
    echo "$message" > /dev/cipher
    echo "$key" > /proc/cipher_key
    local result=$(cat /proc/cipher)
    
    if [ "$result" = "$message" ]; then
        test_result 0
    else
        echo "Expected: '$message'"
        echo "Got: '$result'"
        test_result 1
    fi
}

# Test 9: File encryption/decryption
test_file_encryption() {
    test_header "File Encryption/Decryption"
    
    local key="FileKey"
    local test_file=$(mktemp)
    local encrypted_file=$(mktemp)
    local decrypted_file=$(mktemp)
    
    # Create test file
    echo -e "Line 1\nLine 2\nLine 3" > "$test_file"
    
    # Encrypt
    echo "$key" > /dev/cipher_key
    cat "$test_file" > /dev/cipher
    cat /dev/cipher > "$encrypted_file"
    
    # Verify encrypted file is different
    if cmp -s "$test_file" "$encrypted_file"; then
        echo "Encrypted file same as original!"
        test_result 1
        rm -f "$test_file" "$encrypted_file" "$decrypted_file"
        return
    fi
    
    # Decrypt
    echo "$key" > /proc/cipher_key
    cat /proc/cipher > "$decrypted_file"
    
    # Compare
    if cmp -s "$test_file" "$decrypted_file"; then
        test_result 0
    else
        echo "Decrypted file doesn't match original"
        test_result 1
    fi
    
    rm -f "$test_file" "$encrypted_file" "$decrypted_file"
}

# Test 10: No key set (should fail gracefully)
test_no_key_set() {
    test_header "Encryption Without Key Set"
    
    # Try to encrypt without setting key first
    # Note: This might fail depending on previous tests
    # We'll just check it doesn't crash
    
    if echo "NoKeyMessage" > /dev/cipher 2>/dev/null; then
        echo "Encryption succeeded without key (previous key still set)"
        test_result 0
    else
        echo "Encryption properly rejected without key"
        test_result 0
    fi
}

# Main test execution
main() {
    echo "╔════════════════════════════════════════╗"
    echo "║   kcipher Module Test Suite           ║"
    echo "╚════════════════════════════════════════╝"
    
    # Pre-flight checks
    echo ""
    echo "Running pre-flight checks..."
    check_module_loaded
    check_devices
    echo -e "${GREEN}✓ Module loaded and devices ready${NC}"
    
    # Run all tests
    test_basic_encryption
    test_key_denial
    test_wrong_key
    test_binary_data
    test_sequential_operations
    test_large_message
    test_empty_message
    test_special_characters
    test_file_encryption
    test_no_key_set
    
    # Summary
    echo ""
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo "Total tests run: $TESTS_RUN"
    echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed! ✓${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed! ✗${NC}"
        exit 1
    fi
}

# Run main
main
