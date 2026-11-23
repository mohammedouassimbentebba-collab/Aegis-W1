/*
 * W1™ Aerospace Radar Unit: Custom Linux Kernel Ring-0 Driver
 * File: w1_vhf_stealth_radar.c
 * Target: Linux Kernel 5.x / 6.x (x86_64)
 *
 * Description:
 *   Ring-0 Kernel Module providing hardware abstraction, coherent DMA ring
 *   buffering, and high-resolution timer interrupt handling for real-time
 *   VHF/UHF Anti-Stealth radar antenna phased-arrays.
 *
 * Exposes:
 *   /dev/w1_vhf_radar (Character device node)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/capability.h>

#include "w1_radar_ioctl.h"

#define DRIVER_NAME "w1_vhf_stealth_radar"
#define CLASS_NAME  "w1_radar"
#define DMA_BUFFER_SIZE (1024 * 1024 * 4) /* 4 MB Coherent DMA Ring Buffer */
#define MAX_ACTIVE_TRACKS 32
#define W1_MIN_PRF_HZ 1U
#define W1_MAX_PRF_HZ 10000U
#define W1_MAX_ANTENNA_ELEMENTS 4096U

MODULE_LICENSE("GPL");
MODULE_AUTHOR("W1™ Cognitive Defense Fortress Engineering Directorate");
MODULE_DESCRIPTION("W1 VHF/UHF Metric/Decimetric Anti-Stealth Radar Ring-0 Driver");
MODULE_VERSION("2.4.0");

static dev_t dev_num;
static struct cdev w1_cdev;
static struct class *w1_class = NULL;
static struct device *w1_device = NULL;

/* Device State Context */
struct w1_radar_device {
    struct w1_radar_config current_config;
    struct w1_radar_telemetry telemetry;
    struct w1_radar_target_track tracks[MAX_ACTIVE_TRACKS];
    uint32_t active_track_count;

    /* DMA Buffer for High-Rate ADC Stream */
    void *dma_virt_addr;
    dma_addr_t dma_phys_addr;

    /* PRF Timer and Concurrency Controls */
    struct hrtimer prf_timer;
    ktime_t prf_period;
    spinlock_t lock;
    bool is_sweeping;
};

static struct w1_radar_device *radar_ctx = NULL;

/* High-Resolution Timer Callback: Simulates Radar PRF (Pulse Repetition Frequency) */
static enum hrtimer_restart w1_prf_timer_callback(struct hrtimer *timer)
{
    struct w1_radar_device *dev = container_of(timer, struct w1_radar_device, prf_timer);
    unsigned long flags;
    ktime_t period;

    spin_lock_irqsave(&dev->lock, flags);

    if (!dev->is_sweeping) {
        spin_unlock_irqrestore(&dev->lock, flags);
        return HRTIMER_NORESTART;
    }

    dev->telemetry.total_pulses_transmitted++;
    dev->telemetry.total_echoes_processed++;
    period = dev->prf_period;

    /* In hardware: Trigger DMA scatter-gather read of antenna element ADC buffers */

    spin_unlock_irqrestore(&dev->lock, flags);

    /* Forward timer period for next radar pulse */
    hrtimer_forward_now(timer, period);
    return HRTIMER_RESTART;
}

/* File Operations: Open */
static int w1_radar_open(struct inode *inodep, struct file *filep)
{
    filep->private_data = radar_ctx;
    pr_info("%s: Device opened by PID %d\n", DRIVER_NAME, current->pid);
    return 0;
}

/* File Operations: Release (SYS-05: hrtimer_cancel MUST run outside spinlock) */
static int w1_radar_release(struct inode *inodep, struct file *filep)
{
    struct w1_radar_device *dev = filep->private_data;
    unsigned long flags;
    bool was_sweeping = false;

    if (!dev)
        return 0;

    spin_lock_irqsave(&dev->lock, flags);
    if (dev->is_sweeping) {
        dev->is_sweeping = false;
        was_sweeping = true;
    }
    spin_unlock_irqrestore(&dev->lock, flags);

    if (was_sweeping)
        hrtimer_cancel(&dev->prf_timer);

    pr_info("%s: Device closed\n", DRIVER_NAME);
    return 0;
}

/* File Operations: IOCTL Dispatcher (SYS-05 hardened: CAP_SYS_ADMIN, PRF bounds, no sleeping/hrtimer_cancel under spinlock) */
static long w1_radar_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    struct w1_radar_device *dev = filep->private_data;
    unsigned long flags;
    int ret = 0;

    if (!dev)
        return -ENODEV;

    switch (cmd) {
    case W1_RADAR_IOCTL_SET_CONFIG: {
        struct w1_radar_config cfg;
        uint64_t period_ns;

        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;

        if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
            return -EFAULT;

        /* Strict bounds validation to prevent divide-by-zero and IRQ storm DoS */
        if (cfg.pulse_repetition_freq_hz < W1_MIN_PRF_HZ ||
            cfg.pulse_repetition_freq_hz > W1_MAX_PRF_HZ) {
            return -EINVAL;
        }
        if (cfg.antenna_elements == 0 || cfg.antenna_elements > W1_MAX_ANTENNA_ELEMENTS) {
            return -EINVAL;
        }
        if (cfg.frequency_band != W1_BAND_VHF_METRIC &&
            cfg.frequency_band != W1_BAND_UHF_DECIMETRIC &&
            cfg.frequency_band != W1_BAND_X_CENTIMETRIC) {
            return -EINVAL;
        }

        period_ns = 1000000000ULL / cfg.pulse_repetition_freq_hz;

        spin_lock_irqsave(&dev->lock, flags);
        dev->current_config = cfg;
        dev->prf_period = ktime_set(0, period_ns);
        spin_unlock_irqrestore(&dev->lock, flags);

        pr_info("%s: Configured band 0x%02X, carrier %u Hz, PRF %u Hz\n",
                DRIVER_NAME, cfg.frequency_band, cfg.carrier_freq_hz, cfg.pulse_repetition_freq_hz);
        break;
    }

    case W1_RADAR_IOCTL_GET_CONFIG: {
        struct w1_radar_config cfg_copy;

        /* Zero-init stack snapshot before locking to prevent kernel padding info leaks */
        memset(&cfg_copy, 0, sizeof(cfg_copy));
        spin_lock_irqsave(&dev->lock, flags);
        cfg_copy = dev->current_config;
        spin_unlock_irqrestore(&dev->lock, flags);

        if (copy_to_user((void __user *)arg, &cfg_copy, sizeof(cfg_copy)))
            ret = -EFAULT;
        break;
    }

    case W1_RADAR_IOCTL_START_SWEEP: {
        ktime_t period_copy;
        bool should_start = false;

        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;

        spin_lock_irqsave(&dev->lock, flags);
        if (!dev->is_sweeping) {
            dev->is_sweeping = true;
            period_copy = dev->prf_period;
            should_start = true;
        }
        spin_unlock_irqrestore(&dev->lock, flags);

        if (should_start)
            hrtimer_start(&dev->prf_timer, period_copy, HRTIMER_MODE_REL);

        pr_info("%s: Radar sweep initiated\n", DRIVER_NAME);
        break;
    }

    case W1_RADAR_IOCTL_STOP_SWEEP: {
        bool was_sweeping = false;

        if (!capable(CAP_SYS_ADMIN))
            return -EPERM;

        spin_lock_irqsave(&dev->lock, flags);
        if (dev->is_sweeping) {
            dev->is_sweeping = false;
            was_sweeping = true;
        }
        spin_unlock_irqrestore(&dev->lock, flags);

        if (was_sweeping)
            hrtimer_cancel(&dev->prf_timer);

        pr_info("%s: Radar sweep halted\n", DRIVER_NAME);
        break;
    }

    case W1_RADAR_IOCTL_READ_TRACKS: {
        struct w1_radar_target_track *tracks_copy;

        tracks_copy = kzalloc(sizeof(dev->tracks), GFP_KERNEL);
        if (!tracks_copy)
            return -ENOMEM;

        spin_lock_irqsave(&dev->lock, flags);
        memcpy(tracks_copy, dev->tracks, sizeof(dev->tracks));
        spin_unlock_irqrestore(&dev->lock, flags);

        if (copy_to_user((void __user *)arg, tracks_copy, sizeof(dev->tracks)))
            ret = -EFAULT;

        kfree(tracks_copy);
        break;
    }

    case W1_RADAR_IOCTL_GET_TELEMETRY: {
        struct w1_radar_telemetry tel_copy;

        /* Zero-init stack snapshot before locking to prevent kernel padding info leaks */
        memset(&tel_copy, 0, sizeof(tel_copy));
        spin_lock_irqsave(&dev->lock, flags);
        tel_copy = dev->telemetry;
        spin_unlock_irqrestore(&dev->lock, flags);

        if (copy_to_user((void __user *)arg, &tel_copy, sizeof(tel_copy)))
            ret = -EFAULT;
        break;
    }

    default:
        ret = -ENOTTY;
        break;
    }

    return ret;
}

static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = w1_radar_open,
    .release        = w1_radar_release,
    .unlocked_ioctl = w1_radar_ioctl,
};

static int __init w1_radar_init(void)
{
    int ret;

    radar_ctx = kzalloc(sizeof(*radar_ctx), GFP_KERNEL);
    if (!radar_ctx) return -ENOMEM;

    spin_lock_init(&radar_ctx->lock);

    /* Set default configuration to VHF Metric Anti-Stealth Band (180 MHz, λ = 1.66 m)
     * Use IEEE-754 integer bit patterns to avoid SSE/FP instructions in kernel space.
     */
    {
        static const u32 default_pulse_width_bits = 0x42480000U; /* 50.0f */
        static const u32 default_bandwidth_bits   = 0x41200000U; /* 10.0f */

        radar_ctx->current_config.frequency_band = W1_BAND_VHF_METRIC;
        radar_ctx->current_config.carrier_freq_hz = 180000000;
        radar_ctx->current_config.pulse_repetition_freq_hz = 1000;
        memcpy(&radar_ctx->current_config.pulse_width_us, &default_pulse_width_bits, sizeof(u32));
        memcpy(&radar_ctx->current_config.bandwidth_mhz, &default_bandwidth_bits, sizeof(u32));
        radar_ctx->current_config.antenna_elements = 64;
        radar_ctx->current_config.stap_enabled = 1;
    }

    radar_ctx->prf_period = ktime_set(0, 1000000); /* 1 ms = 1000 Hz PRF */
    hrtimer_init(&radar_ctx->prf_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    radar_ctx->prf_timer.function = w1_prf_timer_callback;

    /* Register Character Device */
    ret = alloc_chrdev_region(&dev_num, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        kfree(radar_ctx);
        return ret;
    }

    cdev_init(&w1_cdev, &fops);
    ret = cdev_add(&w1_cdev, dev_num, 1);
    if (ret < 0) {
        unregister_chrdev_region(dev_num, 1);
        kfree(radar_ctx);
        return ret;
    }

    w1_class = class_create(CLASS_NAME);
    if (IS_ERR(w1_class)) {
        cdev_del(&w1_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(radar_ctx);
        return PTR_ERR(w1_class);
    }

    w1_device = device_create(w1_class, NULL, dev_num, NULL, DRIVER_NAME);
    if (IS_ERR(w1_device)) {
        class_destroy(w1_class);
        cdev_del(&w1_cdev);
        unregister_chrdev_region(dev_num, 1);
        kfree(radar_ctx);
        return PTR_ERR(w1_device);
    }

    pr_info("%s: VHF/UHF Anti-Stealth Radar Ring-0 Driver Loaded Successfully (/dev/%s)\n",
            DRIVER_NAME, DRIVER_NAME);
    return 0;
}

static void __exit w1_radar_exit(void)
{
    device_destroy(w1_class, dev_num);
    class_destroy(w1_class);
    cdev_del(&w1_cdev);
    unregister_chrdev_region(dev_num, 1);

    if (radar_ctx) {
        radar_ctx->is_sweeping = false;
        hrtimer_cancel(&radar_ctx->prf_timer);
        kfree(radar_ctx);
        radar_ctx = NULL;
    }

    pr_info("%s: Driver Unloaded\n", DRIVER_NAME);
}

module_init(w1_radar_init);
module_exit(w1_radar_exit);
