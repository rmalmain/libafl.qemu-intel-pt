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

#include "intel_pt.h"
#include "qemu/osdep.h"
#include "qemu/error-report.h"

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif
#define PAGE_SIZE 4096

#define PT_EVENT_TYPE_PATH "/sys/bus/event_source/devices/intel_pt/type"
#define PT_CONFIG_NORETCOMP BIT(11) // aka DisRETC in Intel SDM, TODO: consider reading /sys/bus/event_source/devices/*/format/

/* should be 1+2^n pages */
#define PERF_BUFFER_SIZE (1 + (1 << 7)) * PAGE_SIZE
/* must be page aligned and must be a power of two */
#define PERF_AUX_BUFFER_SIZE 4096 * PAGE_SIZE

// TODO multiple threads
static int perf_fd;
static void *perf_buff;
static void *perf_aux_buf;
static struct perf_event_attr pe;

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

static void intel_pt_perf_event_attr_init(void)
{
    memset(&pe, 0, sizeof(pe));

    pe.type = intel_pt_perf_type();
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PT_CONFIG_NORETCOMP;
}

int perf_intel_pt_open(int thread_id)
{
    int ret = 0;

    // TODO ensure that the CPU supports Intel PT and all features we need somewhere

    if (!pe.size)
    {
        intel_pt_perf_event_attr_init();
    }

    perf_fd = perf_event_open(&pe, (pid_t)thread_id, 0, -1, 0);
    if (perf_fd < 0)
    {
        error_report("IntelPT: Failed to open perf event");
        goto fail;
    }

    // TODO move these structures to a global state
    perf_buff = mmap(NULL, PERF_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    if (perf_buff == MAP_FAILED)
    {
        error_report("IntelPT: Failed to mmap perf buffer");
        goto fail;
    }

    // the first page is a metadata page
    struct perf_event_mmap_page *pc = (struct perf_event_mmap_page *)perf_buff;
    pc->aux_offset = next_page_aligned_addr(pc->data_offset + pc->data_size);
    pc->aux_size = PERF_AUX_BUFFER_SIZE;

    perf_aux_buf = mmap(NULL, pc->aux_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, perf_fd,
                        pc->aux_offset);
    if (perf_aux_buf == MAP_FAILED)
    {
        error_report("IntelPT: Failed to mmap perf aux buffer");
        goto fail;
    }

    return 0;

fail:
    error_report("errno: %d", errno);
    perf_intel_pt_close();
    exit(1);
    return ret;
}

void perf_intel_pt_close(void)
{
    if (perf_aux_buf > 0)
    {
        munmap(perf_aux_buf, PERF_AUX_BUFFER_SIZE);
    }

    if (perf_buff > 0)
    {
        munmap(perf_buff, PERF_BUFFER_SIZE);
    }

    if (perf_fd > 0)
    {
        close(perf_fd);
    }
}

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
