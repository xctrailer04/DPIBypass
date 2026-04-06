/**
 * lwIP system architecture for NO_SYS=1 (no OS)
 * Since we use GCD manually, no threading primitives needed
 */

#ifndef SYS_ARCH_H
#define SYS_ARCH_H

/* NO_SYS=1 means lwIP doesn't use any OS-level threading.
 * All lwIP calls must happen on the same GCD queue.
 * These typedefs are required but unused. */

typedef int sys_prot_t;
typedef int sys_sem_t;
typedef int sys_mutex_t;
typedef int sys_mbox_t;
typedef int sys_thread_t;

#define SYS_SEM_NULL   0
#define SYS_MBOX_NULL  0

#define sys_arch_protect()    0
#define sys_arch_unprotect(x) (void)(x)

#endif /* SYS_ARCH_H */
