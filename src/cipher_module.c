/*
 * Kernel Cipher Device Module (kcipher)
 * 
 * A Linux kernel module that implements encrypted character devices.
 * Provides both /dev and /proc interfaces for encryption/decryption operations.
 *
 * Author: [Your Name]
 * License: GPL v2
 *
 * Security Warning: This module uses RC4, which is cryptographically broken.
 * This is for educational purposes only and should NOT be used in production.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include "RC4.h"

/* Module Information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel Cipher Device - Educational Encryption Module");
MODULE_VERSION("1.0");

/* Device and buffer configuration */
#define DEVICE_NAME "cipher"
#define KEY_DEVICE_NAME "cipher_key"
#define BUFFER_SIZE 4096
#define KEY_SIZE 128

/* Minor device numbers */
#define MINOR_CIPHER 0
#define MINOR_KEY 1

/* Global state */
static int major;
static struct cdev cipher_cdev;
static dev_t dev_num;

/* Data buffers - separated for clarity */
static unsigned char message[BUFFER_SIZE];
static size_t message_len = 0;

static unsigned char encrypted_message[BUFFER_SIZE];
static size_t encrypted_len = 0;

static unsigned char key[KEY_SIZE];
static size_t key_len = 0;

/* Proc filesystem entries */
static struct proc_dir_entry *proc_cipher;
static struct proc_dir_entry *proc_cipher_key;

/* Synchronization primitives */
static DEFINE_MUTEX(cipher_mutex);  /* Protects message and encrypted_message */
static DEFINE_MUTEX(key_mutex);      /* Protects key */

/* Statistics (useful for debugging and monitoring) */
static unsigned long encrypt_count = 0;
static unsigned long decrypt_count = 0;

/*
 * secure_zero - Securely zero out sensitive memory
 * @data: Pointer to memory to zero
 * @len: Length of memory region
 *
 * Uses volatile to prevent compiler optimization that might remove the zeroing.
 */
static void secure_zero(void *data, size_t len)
{
    volatile unsigned char *p = data;
    while (len--)
        *p++ = 0;
}

/*
 * Character Device Operations
 */

static int cipher_open(struct inode *inode, struct file *file)
{
    unsigned int minor = iminor(inode);
    
    pr_info("kcipher: Device opened (minor: %u)\n", minor);
    return 0;
}

static int cipher_release(struct inode *inode, struct file *file)
{
    unsigned int minor = iminor(inode);
    
    pr_info("kcipher: Device closed (minor: %u)\n", minor);
    return 0;
}

static ssize_t cipher_write(struct file *file, const char __user *buf,
                           size_t len, loff_t *offset)
{
    unsigned int minor = iminor(file->f_inode);
    int ret;

    if (minor == MINOR_CIPHER) {
        /* Writing to /dev/cipher - store and encrypt message */
        if (len > BUFFER_SIZE) {
            pr_warn("kcipher: Message too large (%zu > %d)\n", len, BUFFER_SIZE);
            return -EINVAL;
        }

        mutex_lock(&cipher_mutex);
        mutex_lock(&key_mutex);

        /* Check if key is set */
        if (key_len == 0) {
            mutex_unlock(&key_mutex);
            mutex_unlock(&cipher_mutex);
            pr_warn("kcipher: Encryption key not set\n");
            return -EPERM;
        }

        /* Copy message from userspace */
        ret = copy_from_user(message, buf, len);
        if (ret) {
            mutex_unlock(&key_mutex);
            mutex_unlock(&cipher_mutex);
            return -EFAULT;
        }
        message_len = len;

        /* Encrypt the message */
        rc4(message, key, encrypted_message, message_len, key_len);
        encrypted_len = message_len;
        encrypt_count++;

        pr_info("kcipher: Message encrypted (%zu bytes)\n", message_len);

        /* Zero out plaintext for security */
        secure_zero(message, BUFFER_SIZE);
        message_len = 0;

        mutex_unlock(&key_mutex);
        mutex_unlock(&cipher_mutex);

        return len;

    } else if (minor == MINOR_KEY) {
        /* Writing to /dev/cipher_key - store encryption key */
        if (len > KEY_SIZE) {
            pr_warn("kcipher: Key too large (%zu > %d)\n", len, KEY_SIZE);
            return -EINVAL;
        }

        mutex_lock(&key_mutex);

        ret = copy_from_user(key, buf, len);
        if (ret) {
            mutex_unlock(&key_mutex);
            return -EFAULT;
        }

        /* Remove trailing newline if present */
        if (len > 0 && key[len - 1] == '\n') {
            key[len - 1] = '\0';
            key_len = len - 1;
        } else {
            key_len = len;
        }

        pr_info("kcipher: Encryption key set (%zu bytes)\n", key_len);
        mutex_unlock(&key_mutex);

        return len;
    }

    return -EINVAL;
}

static ssize_t cipher_read(struct file *file, char __user *buf,
                          size_t len, loff_t *offset)
{
    unsigned int minor = iminor(file->f_inode);
    int ret;
    size_t to_read;

    if (minor == MINOR_KEY) {
        /* Reading from /dev/cipher_key - return amusing denial message */
        const char *msg = "Go away silly one, you cannot see my key >-:\n";
        return simple_read_from_buffer(buf, len, offset, msg, strlen(msg));
    }

    if (minor == MINOR_CIPHER) {
        /* Reading from /dev/cipher - return encrypted message */
        mutex_lock(&cipher_mutex);

        if (encrypted_len == 0) {
            mutex_unlock(&cipher_mutex);
            pr_info("kcipher: No encrypted message available\n");
            return 0;
        }

        /* Handle EOF */
        if (*offset >= encrypted_len) {
            mutex_unlock(&cipher_mutex);
            return 0;
        }

        /* Calculate how much to read */
        to_read = min(len, encrypted_len - (size_t)*offset);

        /* Copy encrypted data to userspace */
        ret = copy_to_user(buf, encrypted_message + *offset, to_read);
        if (ret) {
            mutex_unlock(&cipher_mutex);
            return -EFAULT;
        }

        *offset += to_read;
        mutex_unlock(&cipher_mutex);

        pr_info("kcipher: Read %zu encrypted bytes\n", to_read);
        return to_read;
    }

    return -EINVAL;
}

static struct file_operations cipher_fops = {
    .owner = THIS_MODULE,
    .open = cipher_open,
    .read = cipher_read,
    .write = cipher_write,
    .release = cipher_release,
};

/*
 * Proc Filesystem Operations
 */

static ssize_t proc_cipher_read(struct file *file, char __user *buf,
                               size_t len, loff_t *offset)
{
    unsigned char *decrypted_message;
    size_t to_read;
    ssize_t ret;

    mutex_lock(&cipher_mutex);
    mutex_lock(&key_mutex);

    /* Validate that we have both key and encrypted message */
    if (key_len == 0) {
        mutex_unlock(&key_mutex);
        mutex_unlock(&cipher_mutex);
        pr_warn("kcipher: Cannot decrypt - key not set\n");
        return -EPERM;
    }

    if (encrypted_len == 0) {
        mutex_unlock(&key_mutex);
        mutex_unlock(&cipher_mutex);
        pr_info("kcipher: No encrypted message to decrypt\n");
        return 0;
    }

    /* Handle EOF */
    if (*offset >= encrypted_len) {
        mutex_unlock(&key_mutex);
        mutex_unlock(&cipher_mutex);
        return 0;
    }

    /* Allocate temporary buffer for decryption */
    decrypted_message = kmalloc(encrypted_len, GFP_KERNEL);
    if (!decrypted_message) {
        mutex_unlock(&key_mutex);
        mutex_unlock(&cipher_mutex);
        return -ENOMEM;
    }

    /* Decrypt the message */
    rc4(encrypted_message, key, decrypted_message, encrypted_len, key_len);
    decrypt_count++;

    pr_info("kcipher: Message decrypted (%zu bytes)\n", encrypted_len);

    /* Calculate how much to read */
    to_read = min(len, encrypted_len - (size_t)*offset);

    /* Copy decrypted data to userspace */
    ret = copy_to_user(buf, decrypted_message + *offset, to_read);
    if (ret) {
        ret = -EFAULT;
        goto cleanup;
    }

    *offset += to_read;
    ret = to_read;

cleanup:
    /* Securely zero and free decrypted message */
    secure_zero(decrypted_message, encrypted_len);
    kfree(decrypted_message);

    mutex_unlock(&key_mutex);
    mutex_unlock(&cipher_mutex);

    return ret;
}

static ssize_t proc_cipher_key_write(struct file *file, const char __user *buf,
                                    size_t len, loff_t *offset)
{
    int ret;

    if (len > KEY_SIZE) {
        pr_warn("kcipher: Key too large (%zu > %d)\n", len, KEY_SIZE);
        return -EINVAL;
    }

    mutex_lock(&key_mutex);

    ret = copy_from_user(key, buf, len);
    if (ret) {
        mutex_unlock(&key_mutex);
        return -EFAULT;
    }

    /* Remove trailing newline if present */
    if (len > 0 && key[len - 1] == '\n') {
        key[len - 1] = '\0';
        key_len = len - 1;
    } else {
        key_len = len;
    }

    pr_info("kcipher: Decryption key set via /proc (%zu bytes)\n", key_len);
    mutex_unlock(&key_mutex);

    return len;
}

static struct proc_ops proc_cipher_ops = {
    .proc_read = proc_cipher_read,
};

static struct proc_ops proc_cipher_key_ops = {
    .proc_write = proc_cipher_key_write,
};

/*
 * Module Initialization and Cleanup
 */

static int __init cipher_init(void)
{
    int ret;

    pr_info("kcipher: Initializing kernel cipher module\n");

    /* Allocate device numbers */
    ret = alloc_chrdev_region(&dev_num, 0, 2, DEVICE_NAME);
    if (ret < 0) {
        pr_err("kcipher: Failed to allocate device numbers\n");
        return ret;
    }

    major = MAJOR(dev_num);
    pr_info("kcipher: Allocated major number: %d\n", major);

    /* Initialize and add character device */
    cdev_init(&cipher_cdev, &cipher_fops);
    cipher_cdev.owner = THIS_MODULE;

    ret = cdev_add(&cipher_cdev, dev_num, 2);
    if (ret < 0) {
        pr_err("kcipher: Failed to add character device\n");
        goto fail_cdev_add;
    }

    /* Create /proc/cipher */
    proc_cipher = proc_create("cipher", 0444, NULL, &proc_cipher_ops);
    if (!proc_cipher) {
        pr_err("kcipher: Failed to create /proc/cipher\n");
        ret = -ENOMEM;
        goto fail_proc_cipher;
    }

    /* Create /proc/cipher_key */
    proc_cipher_key = proc_create("cipher_key", 0222, NULL, &proc_cipher_key_ops);
    if (!proc_cipher_key) {
        pr_err("kcipher: Failed to create /proc/cipher_key\n");
        ret = -ENOMEM;
        goto fail_proc_key;
    }

    pr_info("kcipher: Module loaded successfully\n");
    pr_info("kcipher: Create device nodes with:\n");
    pr_info("kcipher:   sudo mknod /dev/cipher c %d 0\n", major);
    pr_info("kcipher:   sudo mknod /dev/cipher_key c %d 1\n", major);
    pr_info("kcipher:   sudo chmod 666 /dev/cipher /dev/cipher_key\n");

    return 0;

fail_proc_key:
    proc_remove(proc_cipher);
fail_proc_cipher:
    cdev_del(&cipher_cdev);
fail_cdev_add:
    unregister_chrdev_region(dev_num, 2);
    return ret;
}

static void __exit cipher_exit(void)
{
    pr_info("kcipher: Unloading module\n");
    pr_info("kcipher: Stats - Encryptions: %lu, Decryptions: %lu\n",
            encrypt_count, decrypt_count);

    /* Remove proc entries */
    proc_remove(proc_cipher_key);
    proc_remove(proc_cipher);

    /* Remove character device */
    cdev_del(&cipher_cdev);
    unregister_chrdev_region(dev_num, 2);

    /* Securely zero all sensitive data */
    mutex_lock(&cipher_mutex);
    mutex_lock(&key_mutex);
    
    secure_zero(message, BUFFER_SIZE);
    secure_zero(encrypted_message, BUFFER_SIZE);
    secure_zero(key, KEY_SIZE);
    
    message_len = 0;
    encrypted_len = 0;
    key_len = 0;
    
    mutex_unlock(&key_mutex);
    mutex_unlock(&cipher_mutex);

    pr_info("kcipher: Module unloaded, all data cleared\n");
}

module_init(cipher_init);
module_exit(cipher_exit);
