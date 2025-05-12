/*
 * ntsync - userspace synchronization primitives
 * Header for Wine userspace ntsync backend (macOS-compatible)
 *
 * Originally inspired by the Linux ntsync backend for Wine.
 * This implementation is designed to be used as a replacement for Wine's unix/sync.c
 * and provides userspace versions of NT synchronization objects on macOS.
 */


#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"

/* Check if ntsync is enabled via the WINENTSYNC environment variable */
extern int do_ntsync(void);

/* Initialize the ntsync backend (lazy init wrapper) */
extern void ntsync_init(void);

/* Release an object handle */
NTSTATUS ntsync_close(HANDLE handle);

/* Event API */
NTSTATUS ntsync_create_event(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr, EVENT_TYPE type, BOOLEAN initial);

NTSTATUS ntsync_open_event(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr);

NTSTATUS ntsync_set_event(HANDLE handle);
NTSTATUS ntsync_reset_event(HANDLE handle);
NTSTATUS ntsync_pulse_event(HANDLE handle);

NTSTATUS ntsync_query_event(HANDLE handle, void *info, ULONG *ret_len);

/* Wait API */
NTSTATUS ntsync_wait_objects(DWORD count, const HANDLE *handles, BOOLEAN wait_any,
                             BOOLEAN alertable, const LARGE_INTEGER *timeout);

NTSTATUS ntsync_signal_and_wait(HANDLE signal, HANDLE wait, BOOLEAN alertable,
                                const LARGE_INTEGER *timeout);

/* Mutex API */
NTSTATUS ntsync_create_mutex(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr, BOOLEAN initial);

NTSTATUS ntsync_open_mutex(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr);

NTSTATUS ntsync_release_mutex(HANDLE handle, LONG *prev);
NTSTATUS ntsync_query_mutex(HANDLE handle, void *info, ULONG *ret_len);

/* Semaphore API */
NTSTATUS ntsync_create_semaphore(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr, LONG initial, LONG max);

NTSTATUS ntsync_open_semaphore(HANDLE *handle, ACCESS_MASK access,
    const OBJECT_ATTRIBUTES *attr);

NTSTATUS ntsync_release_semaphore(HANDLE handle, ULONG count, ULONG *prev);
NTSTATUS ntsync_query_semaphore(HANDLE handle, void *info, ULONG *ret_len);

/* Generic object query (type/name info) */
NTSTATUS ntsync_query_object(HANDLE handle, void *info, ULONG *ret_len,
    OBJECT_INFORMATION_CLASS info_class);
