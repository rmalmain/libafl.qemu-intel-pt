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
#ifndef INTEL_PT_H
#define INTEL_PT_H

int perf_intel_pt_open(int thread_id);
void perf_intel_pt_close(void);
void perf_intel_pt_log(void);

#endif /* INTEL_PT_H */
