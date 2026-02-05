#!/bin/bash
#
# kcipher Setup Script
# Automates the build, load, and device node creation process
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root"
        echo "Usage: sudo ./setup.sh"
        exit 1
    fi
}

check_dependencies() {
    print_header "Checking Dependencies"
    
    local missing_deps=0
    
    # Check for make
    if ! command -v make &> /dev/null; then
        print_error "make not found"
        missing_deps=1
    else
        print_success "make found"
    fi
    
    # Check for gcc
    if ! command -v gcc &> /dev/null; then
        print_error "gcc not found"
        missing_deps=1
    else
        print_success "gcc found"
    fi
    
    # Check for kernel headers
    if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
        print_error "Kernel headers not found"
        print_info "Install with: sudo apt install linux-headers-\$(uname -r)"
        missing_deps=1
    else
        print_success "Kernel headers found"
    fi
    
    if [ $missing_deps -eq 1 ]; then
        print_error "Missing dependencies. Please install them first."
        exit 1
    fi
    
    echo ""
}

build_module() {
    print_header "Building Module"
    
    if make clean > /dev/null 2>&1; then
        print_success "Cleaned previous build"
    fi
    
    if make > /dev/null 2>&1; then
        print_success "Module built successfully"
    else
        print_error "Module build failed"
        echo "Run 'make' to see detailed error messages"
        exit 1
    fi
    
    echo ""
}

unload_old_module() {
    if lsmod | grep -q kcipher; then
        print_info "Unloading old module..."
        rmmod kcipher || true
        print_success "Old module unloaded"
    fi
}

load_module() {
    print_header "Loading Module"
    
    unload_old_module
    
    if insmod src/kcipher.ko; then
        print_success "Module loaded successfully"
    else
        print_error "Failed to load module"
        print_info "Check dmesg for errors: sudo dmesg | tail -20"
        exit 1
    fi
    
    # Wait a moment for module to initialize
    sleep 1
    
    echo ""
}

get_major_number() {
    local major=$(dmesg | grep "kcipher: Allocated major number" | tail -1 | awk '{print $NF}')
    
    if [ -z "$major" ]; then
        print_error "Could not determine major number"
        print_info "Check dmesg: sudo dmesg | grep kcipher"
        exit 1
    fi
    
    echo "$major"
}

create_device_nodes() {
    print_header "Creating Device Nodes"
    
    local major=$(get_major_number)
    print_info "Using major number: $major"
    
    # Remove old nodes if they exist
    rm -f /dev/cipher /dev/cipher_key
    
    # Create new nodes
    if mknod /dev/cipher c "$major" 0; then
        print_success "Created /dev/cipher"
    else
        print_error "Failed to create /dev/cipher"
        exit 1
    fi
    
    if mknod /dev/cipher_key c "$major" 1; then
        print_success "Created /dev/cipher_key"
    else
        print_error "Failed to create /dev/cipher_key"
        exit 1
    fi
    
    # Set permissions
    if chmod 666 /dev/cipher /dev/cipher_key; then
        print_success "Set device permissions"
    else
        print_error "Failed to set permissions"
        exit 1
    fi
    
    echo ""
}

verify_installation() {
    print_header "Verifying Installation"
    
    # Check module is loaded
    if lsmod | grep -q kcipher; then
        print_success "Module is loaded"
    else
        print_error "Module not loaded"
        return 1
    fi
    
    # Check device nodes
    if [ -c /dev/cipher ] && [ -c /dev/cipher_key ]; then
        print_success "Device nodes exist"
    else
        print_error "Device nodes missing"
        return 1
    fi
    
    # Check proc entries
    if [ -e /proc/cipher ] && [ -e /proc/cipher_key ]; then
        print_success "Proc entries exist"
    else
        print_error "Proc entries missing"
        return 1
    fi
    
    echo ""
}

run_quick_test() {
    print_header "Running Quick Test"
    
    # Set key
    echo "TestKey" > /dev/cipher_key
    
    # Encrypt
    echo "Hello, kcipher!" > /dev/cipher
    
    # Decrypt
    echo "TestKey" > /proc/cipher_key
    local result=$(cat /proc/cipher)
    
    if [ "$result" = "Hello, kcipher!" ]; then
        print_success "Quick test PASSED"
    else
        print_error "Quick test FAILED"
        echo "Expected: 'Hello, kcipher!'"
        echo "Got: '$result'"
        return 1
    fi
    
    echo ""
}

print_usage_info() {
    print_header "Setup Complete!"
    
    echo "The kcipher module is now installed and ready to use."
    echo ""
    echo "Quick Start:"
    echo "  1. Set encryption key:    echo 'MyKey' > /dev/cipher_key"
    echo "  2. Encrypt a message:     echo 'Secret' > /dev/cipher"
    echo "  3. Read encrypted:        cat /dev/cipher"
    echo "  4. Set decryption key:    echo 'MyKey' > /proc/cipher_key"
    echo "  5. Read decrypted:        cat /proc/cipher"
    echo ""
    echo "Useful Commands:"
    echo "  View logs:       sudo dmesg | grep kcipher"
    echo "  Module status:   make status"
    echo "  Run tests:       sudo tests/test_kcipher.sh"
    echo "  Unload module:   make unload"
    echo ""
    echo "Documentation:"
    echo "  README:          cat README.md"
    echo "  API Docs:        cat docs/API.md"
    echo "  Install Guide:   cat docs/INSTALL.md"
    echo ""
}

main() {
    echo ""
    echo "╔════════════════════════════════════════╗"
    echo "║   kcipher Setup Script                ║"
    echo "╚════════════════════════════════════════╝"
    echo ""
    
    check_root
    check_dependencies
    build_module
    load_module
    create_device_nodes
    verify_installation
    run_quick_test
    print_usage_info
    
    print_success "All done!"
}

main
