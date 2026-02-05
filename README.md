# kcipher - Kernel Cipher Device Module

A Linux kernel module that implements encrypted character devices for educational purposes. This module demonstrates kernel programming concepts including character device drivers, the `/proc` filesystem, encryption, and kernel synchronization primitives.

## ⚠️ Security Warning

**This module uses RC4 encryption, which is cryptographically broken and insecure. This project is for educational purposes only and should NEVER be used in production environments or for protecting sensitive data.**

## 🎯 Features

- **Dual Interface Design**: Both `/dev` and `/proc` filesystem interfaces
- **Symmetric Encryption**: RC4 stream cipher (educational implementation)
- **Thread-Safe**: Mutex-based synchronization for concurrent access
- **Security-Conscious**: Secure memory zeroing for sensitive data
- **Statistics Tracking**: Monitor encryption/decryption operations
- **Comprehensive Logging**: Detailed kernel logs for debugging

## 📋 Requirements

- Linux kernel headers (matching your running kernel)
- GCC compiler
- Make
- Root/sudo access for loading modules and creating device nodes

### Installing Requirements (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
```

### Installing Requirements (Fedora/RHEL)

```bash
sudo dnf install gcc make kernel-devel kernel-headers
```

## 🚀 Quick Start

### 1. Build the Module

```bash
make
```

### 2. Load the Module

```bash
make load
```

### 3. Check the Assigned Major Number

```bash
sudo dmesg | grep kcipher
# Look for: "kcipher: Allocated major number: XXX"
```

### 4. Create Device Nodes

```bash
make setup-devices MAJOR=XXX  # Replace XXX with the major number from step 3
```

### 5. Test the Module

```bash
# Set the encryption key
echo "MySecretKey123" > /dev/cipher_key

# Try to read the key (will be denied)
cat /dev/cipher_key
# Output: Go away silly one, you cannot see my key >-:

# Encrypt a message
echo "Hello, World!" > /dev/cipher

# Read encrypted message (gibberish)
cat /dev/cipher
# Output: (binary garbage)

# Decrypt the message
echo "MySecretKey123" > /proc/cipher_key
cat /proc/cipher
# Output: Hello, World!
```

## 📚 Architecture

### Device Interfaces

| Interface | Path | Mode | Purpose |
|-----------|------|------|---------|
| Cipher Device | `/dev/cipher` | R/W | Write plaintext (encrypts), read ciphertext |
| Key Device | `/dev/cipher_key` | W only* | Set encryption key |
| Proc Cipher | `/proc/cipher` | R only | Read decrypted message |
| Proc Key | `/proc/cipher_key` | W only | Set decryption key |

*Technically readable, but returns a denial message

### Data Flow

```
Encryption Flow:
User → /dev/cipher_key (write key)
User → /dev/cipher (write plaintext) → RC4 encryption → Stored ciphertext
User → /dev/cipher (read) → Returns ciphertext

Decryption Flow:
User → /proc/cipher_key (write key)
User → /proc/cipher (read) → RC4 decryption → Returns plaintext
```

### Internal Structure

```c
// Global state (protected by mutexes)
message[4096]           // Plaintext buffer
encrypted_message[4096] // Ciphertext buffer
key[128]                // Encryption/decryption key

// Synchronization
cipher_mutex            // Protects message buffers
key_mutex               // Protects key buffer
```

## 🔧 Usage Examples

### Example 1: Encrypt a File

```bash
# Set encryption key
echo "MyPassword" > /dev/cipher_key

# Encrypt /etc/hosts
cat /etc/hosts > /dev/cipher

# Save encrypted version
cat /dev/cipher > encrypted_hosts.bin

# Decrypt it
echo "MyPassword" > /proc/cipher_key
cat /proc/cipher
```

### Example 2: Wrong Key Detection

```bash
# Encrypt with one key
echo "CorrectKey" > /dev/cipher_key
echo "Secret Message" > /dev/cipher

# Try to decrypt with wrong key
echo "WrongKey" > /proc/cipher_key
cat /proc/cipher
# Output: (gibberish - decryption with wrong key)

# Decrypt with correct key
echo "CorrectKey" > /proc/cipher_key
cat /proc/cipher
# Output: Secret Message
```

### Example 3: Binary Data

```bash
# Works with binary files too
echo "MyKey" > /dev/cipher_key
cat /bin/ls > /dev/cipher

# Decrypt
echo "MyKey" > /proc/cipher_key
cat /proc/cipher > decrypted_ls
```

## 🛠️ Makefile Targets

| Target | Description |
|--------|-------------|
| `make` | Build the kernel module |
| `make clean` | Remove build artifacts |
| `make load` | Load module into kernel |
| `make unload` | Unload module from kernel |
| `make reload` | Unload and reload module |
| `make setup-devices MAJOR=N` | Create `/dev` nodes |
| `make remove-devices` | Remove `/dev` nodes |
| `make status` | Show module status |
| `make logs` | View recent kernel logs |
| `make help` | Show all available targets |

## 📊 Monitoring and Debugging

### View Kernel Logs

```bash
# Recent kcipher logs
make logs

# Or use dmesg directly
sudo dmesg | grep kcipher

# Follow logs in real-time
sudo dmesg -w | grep kcipher
```

### Check Module Status

```bash
make status
```

### Module Statistics

The module tracks encryption/decryption operations, visible in logs when unloading:

```bash
make unload
# Check dmesg for: "Stats - Encryptions: X, Decryptions: Y"
```

## 🔍 Educational Concepts Demonstrated

This module teaches several important kernel programming concepts:

1. **Character Device Drivers**
   - Device registration with `alloc_chrdev_region()`
   - Character device initialization with `cdev_init()` and `cdev_add()`
   - File operations structure

2. **Proc Filesystem**
   - Creating proc entries with `proc_create()`
   - Custom proc operations structure

3. **Kernel Synchronization**
   - Mutex usage for protecting shared data
   - Proper locking order to prevent deadlocks

4. **User-Kernel Space Communication**
   - `copy_from_user()` and `copy_to_user()`
   - Error handling for user space operations

5. **Memory Management**
   - Kernel memory allocation with `kmalloc()`
   - Secure memory zeroing for sensitive data

6. **Module Lifecycle**
   - Initialization and cleanup functions
   - Proper resource cleanup on errors

## 🐛 Troubleshooting

### Module won't load

**Error**: `insmod: ERROR: could not insert module`

**Solution**: Check kernel logs
```bash
sudo dmesg | tail -20
```

### Device nodes not working

**Error**: Permission denied when accessing `/dev/cipher`

**Solution**: Check permissions
```bash
ls -l /dev/cipher*
# Should show: crw-rw-rw-

# If not, fix permissions:
sudo chmod 666 /dev/cipher /dev/cipher_key
```

### Wrong major number

**Error**: Device operations fail

**Solution**: Ensure major number matches
```bash
# Check loaded module's major number
sudo dmesg | grep "Allocated major number"

# Check device node's major number
ls -l /dev/cipher
# First number in the middle should match

# If they don't match, recreate nodes:
make remove-devices
make setup-devices MAJOR=XXX  # Use correct number
```

### Module won't unload

**Error**: `rmmod: ERROR: Module kcipher is in use`

**Solution**: Close all file handles
```bash
# Find processes using the module
lsof | grep cipher

# Kill those processes or wait for them to finish
# Then try again:
make unload
```

---

**Remember**: This is for learning only. Never use RC4 or this module for actual security needs!