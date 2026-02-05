#!/bin/bash
#
# kcipher Examples
# Demonstrates various use cases of the kcipher module
#

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_example() {
    echo -e "${BLUE}==== Example $1: $2 ====${NC}"
}

print_command() {
    echo -e "${GREEN}$ $1${NC}"
}

print_output() {
    echo -e "${YELLOW}$1${NC}"
}

wait_user() {
    echo ""
    read -p "Press Enter to continue..."
    echo ""
}

# Example 1: Basic Usage
example_basic() {
    print_example "1" "Basic Encryption and Decryption"
    
    print_command "echo 'MySecretKey' > /dev/cipher_key"
    echo 'MySecretKey' > /dev/cipher_key
    echo "✓ Encryption key set"
    
    echo ""
    print_command "echo 'Hello, World!' > /dev/cipher"
    echo 'Hello, World!' > /dev/cipher
    echo "✓ Message encrypted"
    
    echo ""
    print_command "cat /dev/cipher | od -c"
    echo "Output: (encrypted gibberish)"
    cat /dev/cipher | od -c | head -3
    
    echo ""
    print_command "echo 'MySecretKey' > /proc/cipher_key"
    echo 'MySecretKey' > /proc/cipher_key
    echo "✓ Decryption key set"
    
    echo ""
    print_command "cat /proc/cipher"
    output=$(cat /proc/cipher)
    print_output "$output"
    
    wait_user
}

# Example 2: Key Security
example_key_security() {
    print_example "2" "Key Security - Can't Read Back Keys"
    
    print_command "echo 'SuperSecretKey123' > /dev/cipher_key"
    echo 'SuperSecretKey123' > /dev/cipher_key
    
    echo ""
    print_command "cat /dev/cipher_key"
    output=$(cat /dev/cipher_key)
    print_output "$output"
    echo ""
    echo "✓ The module refuses to reveal the encryption key!"
    
    wait_user
}

# Example 3: Wrong Key
example_wrong_key() {
    print_example "3" "Wrong Key Detection"
    
    print_command "echo 'CorrectKey' > /dev/cipher_key"
    echo 'CorrectKey' > /dev/cipher_key
    
    print_command "echo 'Secret Message!' > /dev/cipher"
    echo 'Secret Message!' > /dev/cipher
    
    echo ""
    print_command "echo 'WrongKey' > /proc/cipher_key"
    echo 'WrongKey' > /proc/cipher_key
    
    print_command "cat /proc/cipher"
    wrong_output=$(cat /proc/cipher)
    print_output "Gibberish: $wrong_output"
    
    echo ""
    print_command "echo 'CorrectKey' > /proc/cipher_key"
    echo 'CorrectKey' > /proc/cipher_key
    
    print_command "cat /proc/cipher"
    correct_output=$(cat /proc/cipher)
    print_output "Correct: $correct_output"
    
    wait_user
}

# Example 4: File Encryption
example_file_encryption() {
    print_example "4" "Encrypting a File"
    
    # Create a test file
    cat > /tmp/test_document.txt << EOF
This is a confidential document.
It contains sensitive information.
Line 3 of the document.
EOF
    
    print_command "cat /tmp/test_document.txt"
    cat /tmp/test_document.txt
    
    echo ""
    print_command "echo 'FilePassword' > /dev/cipher_key"
    echo 'FilePassword' > /dev/cipher_key
    
    print_command "cat /tmp/test_document.txt > /dev/cipher"
    cat /tmp/test_document.txt > /dev/cipher
    
    echo ""
    print_command "cat /dev/cipher > /tmp/encrypted_document.bin"
    cat /dev/cipher > /tmp/encrypted_document.bin
    echo "✓ File encrypted and saved"
    
    echo ""
    print_command "hexdump -C /tmp/encrypted_document.bin | head -5"
    hexdump -C /tmp/encrypted_document.bin | head -5
    
    echo ""
    print_command "echo 'FilePassword' > /proc/cipher_key"
    echo 'FilePassword' > /proc/cipher_key
    
    print_command "cat /proc/cipher > /tmp/decrypted_document.txt"
    cat /proc/cipher > /tmp/decrypted_document.txt
    
    echo ""
    print_command "cat /tmp/decrypted_document.txt"
    cat /tmp/decrypted_document.txt
    
    echo ""
    print_command "diff /tmp/test_document.txt /tmp/decrypted_document.txt"
    if diff /tmp/test_document.txt /tmp/decrypted_document.txt > /dev/null; then
        echo "✓ Files are identical - decryption successful!"
    else
        echo "✗ Files differ!"
    fi
    
    # Cleanup
    rm -f /tmp/test_document.txt /tmp/encrypted_document.bin /tmp/decrypted_document.txt
    
    wait_user
}

# Example 5: Multiple Messages
example_multiple_messages() {
    print_example "5" "Multiple Sequential Messages"
    
    for i in {1..3}; do
        print_command "echo 'Key$i' > /dev/cipher_key"
        echo "Key$i" > /dev/cipher_key
        
        print_command "echo 'Message $i' > /dev/cipher"
        echo "Message $i" > /dev/cipher
        
        print_command "echo 'Key$i' > /proc/cipher_key"
        echo "Key$i" > /proc/cipher_key
        
        print_command "cat /proc/cipher"
        output=$(cat /proc/cipher)
        print_output "$output"
        
        echo ""
    done
    
    wait_user
}

# Example 6: Binary Data
example_binary_data() {
    print_example "6" "Encrypting Binary Data"
    
    # Get a small binary file
    print_command "head -c 256 /dev/urandom > /tmp/random_data.bin"
    head -c 256 /dev/urandom > /tmp/random_data.bin
    
    print_command "md5sum /tmp/random_data.bin"
    original_md5=$(md5sum /tmp/random_data.bin | awk '{print $1}')
    echo "$original_md5"
    
    echo ""
    print_command "echo 'BinaryKey' > /dev/cipher_key"
    echo 'BinaryKey' > /dev/cipher_key
    
    print_command "cat /tmp/random_data.bin > /dev/cipher"
    cat /tmp/random_data.bin > /dev/cipher
    
    print_command "echo 'BinaryKey' > /proc/cipher_key"
    echo 'BinaryKey' > /proc/cipher_key
    
    print_command "cat /proc/cipher > /tmp/decrypted_data.bin"
    cat /proc/cipher > /tmp/decrypted_data.bin
    
    print_command "md5sum /tmp/decrypted_data.bin"
    decrypted_md5=$(md5sum /tmp/decrypted_data.bin | awk '{print $1}')
    echo "$decrypted_md5"
    
    echo ""
    if [ "$original_md5" = "$decrypted_md5" ]; then
        echo "✓ MD5 hashes match - binary data preserved!"
    else
        echo "✗ MD5 mismatch!"
    fi
    
    # Cleanup
    rm -f /tmp/random_data.bin /tmp/decrypted_data.bin
    
    wait_user
}

# Example 7: Special Characters
example_special_chars() {
    print_example "7" "Special Characters and Unicode"
    
    local special_msg='Special: !@#$%^&*()[]{}|<>?/\~`"'"'"
    
    print_command "echo 'SpecialKey' > /dev/cipher_key"
    echo 'SpecialKey' > /dev/cipher_key
    
    print_command "echo '$special_msg' > /dev/cipher"
    echo "$special_msg" > /dev/cipher
    
    print_command "echo 'SpecialKey' > /proc/cipher_key"
    echo 'SpecialKey' > /proc/cipher_key
    
    print_command "cat /proc/cipher"
    output=$(cat /proc/cipher)
    print_output "$output"
    
    echo ""
    if [ "$output" = "$special_msg" ]; then
        echo "✓ Special characters preserved!"
    fi
    
    wait_user
}

# Example 8: Practical Use Case
example_practical() {
    print_example "8" "Practical Use Case - Encrypting Config File"
    
    # Create a fake config file
    cat > /tmp/app_config.ini << EOF
[database]
host=localhost
port=5432
username=admin
password=secret123

[api]
key=abc123xyz789
secret=top_secret_value
EOF
    
    print_command "cat /tmp/app_config.ini"
    cat /tmp/app_config.ini
    
    echo ""
    echo "Let's encrypt this config file..."
    
    print_command "read -sp 'Enter password: ' PASS"
    PASS="MyConfigPassword"
    echo "(Using: MyConfigPassword)"
    
    print_command "echo \$PASS > /dev/cipher_key"
    echo "$PASS" > /dev/cipher_key
    
    print_command "cat /tmp/app_config.ini > /dev/cipher"
    cat /tmp/app_config.ini > /dev/cipher
    
    print_command "cat /dev/cipher > /tmp/app_config.enc"
    cat /dev/cipher > /tmp/app_config.enc
    
    print_command "rm /tmp/app_config.ini"
    rm /tmp/app_config.ini
    echo "✓ Original deleted, only encrypted version remains"
    
    echo ""
    echo "Later, to decrypt..."
    
    print_command "read -sp 'Enter password: ' PASS"
    echo "(Using: MyConfigPassword)"
    
    print_command "echo \$PASS > /proc/cipher_key"
    echo "$PASS" > /proc/cipher_key
    
    print_command "cat /proc/cipher"
    cat /proc/cipher
    
    # Cleanup
    rm -f /tmp/app_config.ini /tmp/app_config.enc
    
    wait_user
}

# Main menu
main() {
    echo "╔════════════════════════════════════════╗"
    echo "║   kcipher Usage Examples              ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    # Check if module is loaded
    if ! lsmod | grep -q kcipher; then
        echo "ERROR: kcipher module not loaded"
        echo "Run: sudo make load"
        exit 1
    fi
    
    # Check if devices exist
    if [ ! -c /dev/cipher ]; then
        echo "ERROR: Device nodes not found"
        echo "Run: sudo make setup-devices MAJOR=<number>"
        exit 1
    fi
    
    PS3="Select an example (0 to quit): "
    options=(
        "Basic Encryption/Decryption"
        "Key Security"
        "Wrong Key Detection"
        "File Encryption"
        "Multiple Messages"
        "Binary Data"
        "Special Characters"
        "Practical Use Case"
        "Run All Examples"
    )
    
    while true; do
        echo ""
        select opt in "${options[@]}"; do
            case $REPLY in
                1) example_basic; break;;
                2) example_key_security; break;;
                3) example_wrong_key; break;;
                4) example_file_encryption; break;;
                5) example_multiple_messages; break;;
                6) example_binary_data; break;;
                7) example_special_chars; break;;
                8) example_practical; break;;
                9) 
                    example_basic
                    example_key_security
                    example_wrong_key
                    example_file_encryption
                    example_multiple_messages
                    example_binary_data
                    example_special_chars
                    example_practical
                    echo "All examples completed!"
                    break
                    ;;
                0) echo "Goodbye!"; exit 0;;
                *) echo "Invalid option"; break;;
            esac
        done
    done
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script should be run as root (for device access)"
    echo "Run: sudo $0"
    exit 1
fi

main