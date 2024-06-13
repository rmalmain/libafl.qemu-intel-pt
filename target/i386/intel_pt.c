/*
 * QEMU Intel PT for target tracing
 *
 *
 * Author:
 *      Marco Cavenati <cavenati.marco@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <stdint.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

#include "intel_pt.h"
#include "qemu/atomic.h"
#include "qemu/osdep.h"
#include "qemu/error-report.h"

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif
#define PAGE_SIZE 4096

#define PT_EVENT_TYPE_PATH "/sys/bus/event_source/devices/intel_pt/type"
// TODO: consider reading /sys/bus/event_source/devices/intel_pt/format/
// TODO: Tune PSBFreq
// TODO: multiple threads
// TODO: enable/disable PT on vm enter/exit
// TODO: consider RIP addresses: Intel SDM 33.3.1.1
/* Enable Cycle Count packets, aka CYCEn in Intel SDM */
#define PT_CONFIG_CYC BIT(1)
/* Enable Power Event packets, aka PwrEvtEn in Intel SDM */
#define PT_CONFIG_PWR_EVT BIT(4)
/* Enable Mini Time Counter packets, aka MTCEn in INtel SDM */
#define PT_CONFIG_MTC BIT(9)
/* Enable Time-Stamp Counter packets, aka TSCEn in Intel SDM */
#define PT_CONFIG_TSC BIT(10)
/* Disable call return address compression, aka DisRETC in Intel SDM */
#define PT_CONFIG_NORETCOMP BIT(11)
/* Enable PTWRITE packets, aka PTWEn in Intel SDM */
#define PT_CONFIG_PTW BIT(12)
/* Enable Change Of Flow instr. packets, aka BranchEn in Intel SDM */
#define PT_CONFIG_BRANCH BIT(13)

#define PERF_BUFFER_SIZE (1 + (1 << 7)) * PAGE_SIZE
_Static_assert(((PERF_BUFFER_SIZE - PAGE_SIZE) & (PERF_BUFFER_SIZE - PAGE_SIZE - 1)) == 0,
               "PERF_BUFFER_SIZE should be 1+2^n pages");
#define PERF_AUX_BUFFER_SIZE 64 * 1024 * 1024
static_assert((PERF_AUX_BUFFER_SIZE % PAGE_SIZE) == 0,
               "PERF_AUX_BUFFER_SIZE must be page aligned");
static_assert((PERF_AUX_BUFFER_SIZE & (PERF_AUX_BUFFER_SIZE - 1)) == 0,
               "PERF_AUX_BUFFER_SIZE must be a power of two");

static struct perf_event_attr pe;
static int perf_fd;
static void *perf_buff;
static void *perf_aux_buf;
static struct perf_event_mmap_page *pc;

static inline int perf_event_open(struct perf_event_attr *attr,
                                  pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static size_t next_page_aligned_addr(size_t address)
{
    return (address + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

static int64_t intel_pt_perf_type(void)
{
    FILE *f;
    int64_t perf_type;

    f = fopen(PT_EVENT_TYPE_PATH, "r");
    if (!f)
    {
        error_report("IntelPT: Failed to open %s", PT_EVENT_TYPE_PATH);
        return -ENODEV;
    }

    if (fscanf(f, "%ld", &perf_type) != 1)
    {
        error_report("IntelPT: Failed to read perf type from %s", PT_EVENT_TYPE_PATH);
        return -ENODEV;
    }

    fclose(f);
    return perf_type;
}

static void perf_event_attr_init(void)
{
    memset(&pe, 0, sizeof(pe));

    pe.type = intel_pt_perf_type();
    pe.size = sizeof(struct perf_event_attr);
    pe.disabled = 1;
    /* Enabled features, PT_CONFIG_BRANCH is on by default */
    pe.config |= PT_CONFIG_NORETCOMP;
}

// TODO: expose this to libafl
static int set_ip_filter(void) {
    const char *argp = "filter 0x7c00/512";
    return ioctl(perf_fd, PERF_EVENT_IOC_SET_FILTER, argp);
}

int perf_intel_pt_open(int thread_id)
{
    int ret = 0;

    // TODO ensure that the CPU supports Intel PT and all features we need somewhere?

    if (!pe.size)
    {
        /* The same event_attr can be used to setup multiple threads, init just once */
        perf_event_attr_init();
    }

    perf_fd = perf_event_open(&pe, (pid_t)thread_id, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd < 0)
    {
        error_report("IntelPT: Failed to open perf event");
        goto fail;
    }

    perf_buff = mmap(NULL, PERF_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    if (perf_buff == MAP_FAILED)
    {
        error_report("IntelPT: Failed to mmap perf buffer");
        goto fail;
    }

    // the first page is a metadata page
    pc = (struct perf_event_mmap_page *)perf_buff;
    pc->aux_offset = next_page_aligned_addr(pc->data_offset + pc->data_size);
    pc->aux_size = PERF_AUX_BUFFER_SIZE;

    /* PROT_WRITE sets PT to stop when the buffer is full */
    perf_aux_buf = mmap(NULL, pc->aux_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, perf_fd,
                        pc->aux_offset);
    if (perf_aux_buf == MAP_FAILED)
    {
        error_report("IntelPT: Failed to mmap perf aux buffer");
        goto fail;
    }

    if (set_ip_filter())
    {
        error_report("IntelPT: Failed to set IP filter");
        goto fail;
    }

    if(ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0))
    {
        error_report("IntelPT: Failed to enable perf event");
        goto fail;
    }

    return 0;

fail:
    error_report("errno: %d", errno);
    perf_intel_pt_close();
    return ret;
}

static inline uint64_t wrap_aux_pointer(uint64_t ptr)
{
    return  ptr & (PERF_AUX_BUFFER_SIZE - 1);
}

void perf_intel_pt_log(void)
{
    if (!pc)
    {
        return;
    }

    FILE *f;

    f = fopen("./ipt_raw_trace", "a");
    if (!f)
    {
        error_report("IntelPT: Failed to open log file");
        return;
    }

    uint64_t head = wrap_aux_pointer(pc->aux_head);
    uint64_t tail = wrap_aux_pointer(pc->aux_tail);
    smp_rmb();

    fwrite(perf_aux_buf + tail, 1, head - tail, f);

    pc->aux_tail = head;
}

void perf_intel_pt_close(void)
{
    if (perf_aux_buf != NULL)
    {
        munmap(perf_aux_buf, PERF_AUX_BUFFER_SIZE);
        perf_aux_buf = NULL;
    }

    pc = NULL;
    if (perf_buff != NULL)
    {
        munmap(perf_buff, PERF_BUFFER_SIZE);
        perf_buff = NULL;
    }

    if (perf_fd >= 0)
    {
        close(perf_fd);
        perf_fd = -1;
    }
}

// TODO better understand sudo/capabilities requirements

// In case we need to increase locked memory

// // Get the current limit
// if (getrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
//     perror("getrlimit");
//     return 1;
// }

// printf("Current RLIMIT_MEMLOCK: soft limit = %llu, hard limit = %llu\n",
//        (unsigned long long)limit.rlim_cur, (unsigned long long)limit.rlim_max);

// // Set a new limit (for example, 64 MB)
// limit.rlim_cur = 64 * 1024 * 1024; // 64 MB
// limit.rlim_max = 64 * 1024 * 1024; // 64 MB

// if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0) {
//     perror("setrlimit");
//     return 1;
// }
