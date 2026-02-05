# Kernel Cipher Module Makefile
# 
# Builds the kcipher kernel module for educational purposes
#

# Module name
MODULE_NAME := kcipher

# Object files
obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := cipher_module.o RC4.o

# Kernel build directory (adjust for your system)
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

# Current directory
PWD := $(shell pwd)

# Compiler flags for extra warnings and security
ccflags-y := -Wall -Wextra

# Default target
all: module

# Build the kernel module
module:
	@echo "Building kcipher kernel module..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD)/src modules

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD)/src clean
	rm -f src/*.o src/*.ko src/*.mod.* src/.*.cmd src/Module.symvers src/modules.order
	rm -rf src/.tmp_versions

# Install the module (requires root)
install: module
	@echo "Installing kcipher module..."
	sudo $(MAKE) -C $(KERNEL_DIR) M=$(PWD)/src modules_install
	sudo depmod -a
	@echo "Module installed. Load with: sudo modprobe $(MODULE_NAME)"

# Uninstall the module
uninstall:
	@echo "Uninstalling kcipher module..."
	sudo rm -f /lib/modules/$(shell uname -r)/extra/$(MODULE_NAME).ko
	sudo depmod -a

# Load the module
load: module
	@echo "Loading kcipher module..."
	sudo insmod src/$(MODULE_NAME).ko

# Unload the module
unload:
	@echo "Unloading kcipher module..."
	sudo rmmod $(MODULE_NAME) || true

# Reload the module (useful during development)
reload: unload load

# Create device nodes
setup-devices:
	@echo "Setting up device nodes..."
	@if [ -z "$(MAJOR)" ]; then \
		echo "ERROR: MAJOR number not specified."; \
		echo "Usage: make setup-devices MAJOR=<number>"; \
		echo "Get the major number from dmesg after loading the module."; \
		exit 1; \
	fi
	sudo mknod /dev/cipher c $(MAJOR) 0 || true
	sudo mknod /dev/cipher_key c $(MAJOR) 1 || true
	sudo chmod 666 /dev/cipher /dev/cipher_key
	@echo "Device nodes created with major number $(MAJOR)"

# Remove device nodes
remove-devices:
	@echo "Removing device nodes..."
	sudo rm -f /dev/cipher /dev/cipher_key

# Show module info
info:
	@if [ -f src/$(MODULE_NAME).ko ]; then \
		modinfo src/$(MODULE_NAME).ko; \
	else \
		echo "Module not built yet. Run 'make' first."; \
	fi

# Check module status
status:
	@echo "Module status:"
	@lsmod | grep $(MODULE_NAME) || echo "Module not loaded"
	@echo ""
	@echo "Device nodes:"
	@ls -l /dev/cipher* 2>/dev/null || echo "Device nodes not created"
	@echo ""
	@echo "Proc entries:"
	@ls -l /proc/cipher* 2>/dev/null || echo "Proc entries not available"

# View kernel logs related to the module
logs:
	@echo "Recent kernel logs for kcipher:"
	@sudo dmesg | grep -i kcipher | tail -20

# Help target
help:
	@echo "Kernel Cipher Module - Makefile Help"
	@echo "====================================="
	@echo ""
	@echo "Available targets:"
	@echo "  make              - Build the kernel module"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make load         - Load the module into kernel"
	@echo "  make unload       - Unload the module from kernel"
	@echo "  make reload       - Unload and reload the module"
	@echo "  make install      - Install module to system (requires root)"
	@echo "  make uninstall    - Remove installed module"
	@echo "  make setup-devices MAJOR=<num> - Create /dev nodes"
	@echo "  make remove-devices - Remove /dev nodes"
	@echo "  make status       - Show module and device status"
	@echo "  make logs         - Show recent kernel logs"
	@echo "  make info         - Display module information"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make"
	@echo "  2. make load"
	@echo "  3. Check dmesg for the major number"
	@echo "  4. make setup-devices MAJOR=<number_from_dmesg>"
	@echo "  5. Test with: echo 'mykey' > /dev/cipher_key"

.PHONY: all module clean install uninstall load unload reload setup-devices remove-devices info status logs help
