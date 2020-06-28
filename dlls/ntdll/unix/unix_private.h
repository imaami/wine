/*
 * Ntdll Unix private interface
 *
 * Copyright (C) 2020 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __NTDLL_UNIX_PRIVATE_H
#define __NTDLL_UNIX_PRIVATE_H

#include <pthread.h>
#include <signal.h>
#include "unixlib.h"
#include "wine/list.h"

#ifndef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8
#define InterlockedCompareExchange64(dest,xchg,cmp) RtlInterlockedCompareExchange64(dest,xchg,cmp)
#endif

#ifdef __i386__
static const enum cpu_type client_cpu = CPU_x86;
#elif defined(__x86_64__)
static const enum cpu_type client_cpu = CPU_x86_64;
#elif defined(__arm__)
static const enum cpu_type client_cpu = CPU_ARM;
#elif defined(__aarch64__)
static const enum cpu_type client_cpu = CPU_ARM64;
#endif

struct debug_info
{
    unsigned int str_pos;       /* current position in strings buffer */
    unsigned int out_pos;       /* current position in output buffer */
    char         strings[1024]; /* buffer for temporary strings */
    char         output[1024];  /* current output line */
};

/* thread private data, stored in NtCurrentTeb()->GdiTebBatch */
struct ntdll_thread_data
{
    void              *cpu_data[16];  /* reserved for CPU-specific data */
    struct debug_info *debug_info;    /* info for debugstr functions */
    void              *start_stack;   /* stack for thread startup */
    int                request_fd;    /* fd for sending server requests */
    int                reply_fd;      /* fd for receiving server replies */
    int                wait_fd[2];    /* fd for sleeping server requests */
    pthread_t          pthread_id;    /* pthread thread id */
    struct list        entry;         /* entry in TEB list */
    PRTL_THREAD_START_ROUTINE start;  /* thread entry point */
    void              *param;         /* thread entry point parameter */
    int                esync_apc_fd;  /* fd to wait on for user APCs */
    int               *fsync_apc_futex;
};

C_ASSERT( sizeof(struct ntdll_thread_data) <= sizeof(((TEB *)0)->GdiTebBatch) );

static inline struct ntdll_thread_data *ntdll_get_thread_data(void)
{
    return (struct ntdll_thread_data *)&NtCurrentTeb()->GdiTebBatch;
}

static const SIZE_T page_size = 0x1000;
static const SIZE_T signal_stack_mask = 0xffff;
#ifdef _WIN64
static const SIZE_T teb_size = 0x2000;
static const SIZE_T teb_offset = 0;
static const SIZE_T signal_stack_size = 0x10000 - 0x2000;
#else
static const SIZE_T teb_size = 0x3000;  /* TEB64 + TEB */
static const SIZE_T teb_offset = 0x2000;
static const SIZE_T signal_stack_size = 0x10000 - 0x3000;
#endif

/* callbacks to PE ntdll from the Unix side */
extern void     (WINAPI *pDbgUiRemoteBreakin)( void *arg ) DECLSPEC_HIDDEN;
extern void     (WINAPI *pKiRaiseUserExceptionDispatcher)(void) DECLSPEC_HIDDEN;
extern NTSTATUS (WINAPI *pKiUserExceptionDispatcher)(EXCEPTION_RECORD*,CONTEXT*) DECLSPEC_HIDDEN;
extern void     (WINAPI *pLdrInitializeThunk)(CONTEXT*,void**,ULONG_PTR,ULONG_PTR) DECLSPEC_HIDDEN;
extern void     (WINAPI *pRtlUserThreadStart)( PRTL_THREAD_START_ROUTINE entry, void *arg ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlpWaitForCriticalSection( RTL_CRITICAL_SECTION *crit, int timeout ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlpUnWaitCriticalSection( RTL_CRITICAL_SECTION *crit ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlDeleteCriticalSection( RTL_CRITICAL_SECTION *crit ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlTryAcquireSRWLockExclusive( RTL_SRWLOCK *lock ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlAcquireSRWLockExclusive( RTL_SRWLOCK *lock ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlTryAcquireSRWLockShared( RTL_SRWLOCK *lock ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlAcquireSRWLockShared( RTL_SRWLOCK *lock ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlReleaseSRWLockExclusive( RTL_SRWLOCK *lock ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlReleaseSRWLockShared( RTL_SRWLOCK *lock ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlSleepConditionVariableSRW( RTL_CONDITION_VARIABLE *variable, RTL_SRWLOCK *lock,
                                                         const LARGE_INTEGER *timeout, ULONG flags ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlSleepConditionVariableCS( RTL_CONDITION_VARIABLE *variable,
                                                        RTL_CRITICAL_SECTION *cs,
                                                        const LARGE_INTEGER *timeout ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL fast_RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable, int count ) DECLSPEC_HIDDEN;
extern LONGLONG CDECL fast_RtlGetSystemTimePrecise(void) DECLSPEC_HIDDEN;

void CDECL mmap_add_reserved_area( void *addr, SIZE_T size ) DECLSPEC_HIDDEN;
void CDECL mmap_remove_reserved_area( void *addr, SIZE_T size ) DECLSPEC_HIDDEN;
int  CDECL mmap_is_in_reserved_area( void *addr, SIZE_T size ) DECLSPEC_HIDDEN;
int  CDECL mmap_enum_reserved_areas( int (CDECL *enum_func)(void *base, SIZE_T size, void *arg), void *arg,
                                     int top_down ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL get_initial_environment( WCHAR **wargv[], WCHAR *env, SIZE_T *size ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL get_startup_info( startup_info_t *info, SIZE_T *total_size, SIZE_T *info_size ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL get_dynamic_environment( WCHAR *env, SIZE_T *size ) DECLSPEC_HIDDEN;
extern void CDECL get_initial_directory( UNICODE_STRING *dir ) DECLSPEC_HIDDEN;
extern void CDECL get_initial_console( HANDLE *handle, HANDLE *std_in, HANDLE *std_out, HANDLE *std_err ) DECLSPEC_HIDDEN;
extern USHORT * CDECL get_unix_codepage_data(void) DECLSPEC_HIDDEN;
extern void CDECL get_locales( WCHAR *sys, WCHAR *user ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL virtual_map_section( HANDLE handle, PVOID *addr_ptr, unsigned short zero_bits_64, SIZE_T commit_size,
                                           const LARGE_INTEGER *offset_ptr, SIZE_T *size_ptr, ULONG alloc_type,
                                           ULONG protect, pe_image_info_t *image_info ) DECLSPEC_HIDDEN;
extern ssize_t CDECL virtual_locked_recvmsg( int fd, struct msghdr *hdr, int flags ) DECLSPEC_HIDDEN;
extern void CDECL virtual_release_address_space(void) DECLSPEC_HIDDEN;

extern void CDECL server_send_fd( int fd ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL server_fd_to_handle( int fd, unsigned int access, unsigned int attributes,
                                           HANDLE *handle ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL server_handle_to_fd( HANDLE handle, unsigned int access, int *unix_fd,
                                           unsigned int *options ) DECLSPEC_HIDDEN;
extern void CDECL server_release_fd( HANDLE handle, int unix_fd ) DECLSPEC_HIDDEN;
extern void CDECL server_init_process_done( void *relay, BOOL force_large_address_aware ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL exec_process( UNICODE_STRING *path, UNICODE_STRING *cmdline, NTSTATUS status ) DECLSPEC_HIDDEN;
extern NTSTATUS CDECL unwind_builtin_dll( ULONG type, struct _DISPATCHER_CONTEXT *dispatch,
                                          CONTEXT *context ) DECLSPEC_HIDDEN;

extern void CDECL set_show_dot_files( BOOL enable ) DECLSPEC_HIDDEN;

extern const char *home_dir DECLSPEC_HIDDEN;
extern const char *data_dir DECLSPEC_HIDDEN;
extern const char *build_dir DECLSPEC_HIDDEN;
extern const char *config_dir DECLSPEC_HIDDEN;
extern const char *user_name DECLSPEC_HIDDEN;
extern const char **dll_paths DECLSPEC_HIDDEN;
extern USHORT *uctable DECLSPEC_HIDDEN;
extern USHORT *lctable DECLSPEC_HIDDEN;
extern SIZE_T startup_info_size DECLSPEC_HIDDEN;
extern int main_argc DECLSPEC_HIDDEN;
extern char **main_argv DECLSPEC_HIDDEN;
extern char **main_envp DECLSPEC_HIDDEN;
extern unsigned int server_cpus DECLSPEC_HIDDEN;
extern BOOL is_wow64 DECLSPEC_HIDDEN;
extern HANDLE keyed_event DECLSPEC_HIDDEN;
extern timeout_t server_start_time DECLSPEC_HIDDEN;
extern sigset_t server_block_set DECLSPEC_HIDDEN;
extern struct _KUSER_SHARED_DATA *user_shared_data DECLSPEC_HIDDEN;
#ifdef __i386__
extern struct ldt_copy __wine_ldt_copy DECLSPEC_HIDDEN;
#endif

extern void init_environment( int argc, char *argv[], char *envp[] ) DECLSPEC_HIDDEN;
extern DWORD ntdll_umbstowcs( const char *src, DWORD srclen, WCHAR *dst, DWORD dstlen ) DECLSPEC_HIDDEN;
extern int ntdll_wcstoumbs( const WCHAR *src, DWORD srclen, char *dst, DWORD dstlen, BOOL strict ) DECLSPEC_HIDDEN;
extern char **build_envp( const WCHAR *envW ) DECLSPEC_HIDDEN;
extern NTSTATUS exec_wineloader( char **argv, int socketfd, const pe_image_info_t *pe_info ) DECLSPEC_HIDDEN;
extern void start_server( BOOL debug ) DECLSPEC_HIDDEN;
extern ULONG_PTR get_image_address(void) DECLSPEC_HIDDEN;

extern unsigned int server_call_unlocked( void *req_ptr ) DECLSPEC_HIDDEN;
extern void server_enter_uninterrupted_section( pthread_mutex_t *mutex, sigset_t *sigset ) DECLSPEC_HIDDEN;
extern void server_leave_uninterrupted_section( pthread_mutex_t *mutex, sigset_t *sigset ) DECLSPEC_HIDDEN;
extern unsigned int server_select( const select_op_t *select_op, data_size_t size, UINT flags,
                                   timeout_t abs_timeout, CONTEXT *context, pthread_mutex_t *mutex,
                                   user_apc_t *user_apc ) DECLSPEC_HIDDEN;
extern unsigned int server_wait( const select_op_t *select_op, data_size_t size, UINT flags,
                                 const LARGE_INTEGER *timeout ) DECLSPEC_HIDDEN;
extern unsigned int server_queue_process_apc( HANDLE process, const apc_call_t *call,
                                              apc_result_t *result ) DECLSPEC_HIDDEN;
extern int server_get_unix_fd( HANDLE handle, unsigned int wanted_access, int *unix_fd,
                               int *needs_close, enum server_fd_type *type, unsigned int *options ) DECLSPEC_HIDDEN;
extern void server_init_process(void) DECLSPEC_HIDDEN;
extern size_t server_init_thread( void *entry_point, BOOL *suspend ) DECLSPEC_HIDDEN;
extern int server_pipe( int fd[2] ) DECLSPEC_HIDDEN;

extern NTSTATUS context_to_server( context_t *to, const CONTEXT *from ) DECLSPEC_HIDDEN;
extern NTSTATUS context_from_server( CONTEXT *to, const context_t *from ) DECLSPEC_HIDDEN;
extern void DECLSPEC_NORETURN abort_thread( int status ) DECLSPEC_HIDDEN;
extern void DECLSPEC_NORETURN abort_process( int status ) DECLSPEC_HIDDEN;
extern void DECLSPEC_NORETURN exit_process( int status ) DECLSPEC_HIDDEN;
extern void wait_suspend( CONTEXT *context ) DECLSPEC_HIDDEN;
extern NTSTATUS send_debug_event( EXCEPTION_RECORD *rec, CONTEXT *context, BOOL first_chance ) DECLSPEC_HIDDEN;
extern NTSTATUS set_thread_context( HANDLE handle, const context_t *context, BOOL *self ) DECLSPEC_HIDDEN;
extern NTSTATUS get_thread_context( HANDLE handle, context_t *context, unsigned int flags, BOOL *self ) DECLSPEC_HIDDEN;
extern NTSTATUS alloc_object_attributes( const OBJECT_ATTRIBUTES *attr, struct object_attributes **ret,
                                         data_size_t *ret_len ) DECLSPEC_HIDDEN;

extern void *steamclient_handle_fault( LPCVOID addr, DWORD err ) DECLSPEC_HIDDEN;

extern void virtual_init(void) DECLSPEC_HIDDEN;
extern NTSTATUS virtual_map_ntdll( int fd, void **module ) DECLSPEC_HIDDEN;
extern ULONG_PTR get_system_affinity_mask(void) DECLSPEC_HIDDEN;
extern void virtual_get_system_info( SYSTEM_BASIC_INFORMATION *info ) DECLSPEC_HIDDEN;
extern NTSTATUS virtual_create_builtin_view( void *module ) DECLSPEC_HIDDEN;
extern TEB *virtual_alloc_first_teb(void) DECLSPEC_HIDDEN;
extern NTSTATUS virtual_alloc_teb( TEB **ret_teb ) DECLSPEC_HIDDEN;
extern void virtual_free_teb( TEB *teb ) DECLSPEC_HIDDEN;
extern NTSTATUS virtual_clear_tls_index( ULONG index ) DECLSPEC_HIDDEN;
extern NTSTATUS virtual_alloc_thread_stack( INITIAL_TEB *stack, SIZE_T reserve_size, SIZE_T commit_size,
                                            SIZE_T *pthread_size ) DECLSPEC_HIDDEN;
extern void virtual_map_user_shared_data(void) DECLSPEC_HIDDEN;
extern NTSTATUS virtual_handle_fault( void *addr, DWORD err, void *stack ) DECLSPEC_HIDDEN;
extern unsigned int virtual_locked_server_call( void *req_ptr ) DECLSPEC_HIDDEN;
extern ssize_t virtual_locked_read( int fd, void *addr, size_t size ) DECLSPEC_HIDDEN;
extern ssize_t virtual_locked_pread( int fd, void *addr, size_t size, off_t offset ) DECLSPEC_HIDDEN;
extern BOOL virtual_is_valid_code_address( const void *addr, SIZE_T size ) DECLSPEC_HIDDEN;
extern void *virtual_setup_exception( void *stack_ptr, size_t size, EXCEPTION_RECORD *rec ) DECLSPEC_HIDDEN;
extern BOOL virtual_check_buffer_for_read( const void *ptr, SIZE_T size ) DECLSPEC_HIDDEN;
extern BOOL virtual_check_buffer_for_write( void *ptr, SIZE_T size ) DECLSPEC_HIDDEN;
extern SIZE_T virtual_uninterrupted_read_memory( const void *addr, void *buffer, SIZE_T size ) DECLSPEC_HIDDEN;
extern NTSTATUS virtual_uninterrupted_write_memory( void *addr, const void *buffer, SIZE_T size ) DECLSPEC_HIDDEN;
extern void virtual_set_force_exec( BOOL enable ) DECLSPEC_HIDDEN;
extern void virtual_set_large_address_space(void) DECLSPEC_HIDDEN;
extern void virtual_fill_image_information( const pe_image_info_t *pe_info,
                                            SECTION_IMAGE_INFORMATION *info ) DECLSPEC_HIDDEN;

extern NTSTATUS get_thread_ldt_entry( HANDLE handle, void *data, ULONG len, ULONG *ret_len ) DECLSPEC_HIDDEN;
extern BOOL get_thread_times( int unix_pid, int unix_tid, LARGE_INTEGER *kernel_time,
                              LARGE_INTEGER *user_time ) DECLSPEC_HIDDEN;
extern void signal_init_threading(void) DECLSPEC_HIDDEN;
extern NTSTATUS signal_alloc_thread( TEB *teb ) DECLSPEC_HIDDEN;
extern void signal_free_thread( TEB *teb ) DECLSPEC_HIDDEN;
extern void signal_init_thread( TEB *teb ) DECLSPEC_HIDDEN;
extern void signal_init_process(void) DECLSPEC_HIDDEN;
extern void DECLSPEC_NORETURN signal_start_thread( PRTL_THREAD_START_ROUTINE entry, void *arg,
                                                   BOOL suspend, void *relay, TEB *teb ) DECLSPEC_HIDDEN;
extern void DECLSPEC_NORETURN signal_exit_thread( int status, void (*func)(int) ) DECLSPEC_HIDDEN;
extern void __wine_syscall_dispatcher(void) DECLSPEC_HIDDEN;
extern void fill_vm_counters( VM_COUNTERS_EX *pvmi, int unix_pid ) DECLSPEC_HIDDEN;

extern NTSTATUS cdrom_DeviceIoControl( HANDLE device, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                       IO_STATUS_BLOCK *io, ULONG code, void *in_buffer,
                                       ULONG in_size, void *out_buffer, ULONG out_size ) DECLSPEC_HIDDEN;
extern NTSTATUS serial_DeviceIoControl( HANDLE device, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                        IO_STATUS_BLOCK *io, ULONG code, void *in_buffer,
                                        ULONG in_size, void *out_buffer, ULONG out_size ) DECLSPEC_HIDDEN;
extern NTSTATUS serial_FlushBuffersFile( int fd ) DECLSPEC_HIDDEN;
extern NTSTATUS tape_DeviceIoControl( HANDLE device, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                      IO_STATUS_BLOCK *io, ULONG code, void *in_buffer,
                                      ULONG in_size, void *out_buffer, ULONG out_size ) DECLSPEC_HIDDEN;

extern NTSTATUS errno_to_status( int err ) DECLSPEC_HIDDEN;
extern NTSTATUS nt_to_unix_file_name( const UNICODE_STRING *nameW, char **name_ret, UINT disposition ) DECLSPEC_HIDDEN;
extern NTSTATUS unix_to_nt_file_name( const char *name, WCHAR **nt ) DECLSPEC_HIDDEN;
extern NTSTATUS open_unix_file( HANDLE *handle, const char *unix_name, ACCESS_MASK access,
                                OBJECT_ATTRIBUTES *attr, ULONG attributes, ULONG sharing, ULONG disposition,
                                ULONG options, void *ea_buffer, ULONG ea_length ) DECLSPEC_HIDDEN;
extern void init_files(void) DECLSPEC_HIDDEN;
extern void init_cpu_info(void) DECLSPEC_HIDDEN;

extern void dbg_init(void) DECLSPEC_HIDDEN;

extern void WINAPI call_user_exception_dispatcher( EXCEPTION_RECORD *rec, CONTEXT *context,
                                                   NTSTATUS (WINAPI *dispatcher)(EXCEPTION_RECORD*,CONTEXT*) ) DECLSPEC_HIDDEN;

#define TICKSPERSEC 10000000
#define SECS_1601_TO_1970  ((369 * 365 + 89) * (ULONGLONG)86400)
#define TICKS_1601_TO_1970 (SECS_1601_TO_1970 * TICKSPERSEC)

static inline const char *debugstr_us( const UNICODE_STRING *us )
{
    if (!us) return "<null>";
    return debugstr_wn( us->Buffer, us->Length / sizeof(WCHAR) );
}

/* convert from straight ASCII to Unicode without depending on the current codepage */
static inline void ascii_to_unicode( WCHAR *dst, const char *src, size_t len )
{
    while (len--) *dst++ = (unsigned char)*src++;
}

static inline IMAGE_NT_HEADERS *get_exe_nt_header(void)
{
    IMAGE_DOS_HEADER *module = (IMAGE_DOS_HEADER *)NtCurrentTeb()->Peb->ImageBaseAddress;
    return (IMAGE_NT_HEADERS *)((char *)module + module->e_lfanew);
}

static inline void *get_signal_stack(void)
{
    return (char *)NtCurrentTeb() + teb_size - teb_offset;
}

#ifndef _WIN64
static inline TEB64 *NtCurrentTeb64(void) { return (TEB64 *)NtCurrentTeb()->GdiBatchCount; }
#endif

static inline size_t ntdll_wcslen( const WCHAR *str )
{
    const WCHAR *s = str;
    while (*s) s++;
    return s - str;
}

static inline WCHAR *ntdll_wcscpy( WCHAR *dst, const WCHAR *src )
{
    WCHAR *p = dst;
    while ((*p++ = *src++));
    return dst;
}

static inline WCHAR *ntdll_wcscat( WCHAR *dst, const WCHAR *src )
{
    ntdll_wcscpy( dst + ntdll_wcslen(dst), src );
    return dst;
}

static inline int ntdll_wcscmp( const WCHAR *str1, const WCHAR *str2 )
{
    while (*str1 && (*str1 == *str2)) { str1++; str2++; }
    return *str1 - *str2;
}

static inline int ntdll_wcsncmp( const WCHAR *str1, const WCHAR *str2, int n )
{
    if (n <= 0) return 0;
    while ((--n > 0) && *str1 && (*str1 == *str2)) { str1++; str2++; }
    return *str1 - *str2;
}

static inline WCHAR *ntdll_wcschr( const WCHAR *str, WCHAR ch )
{
    do { if (*str == ch) return (WCHAR *)(ULONG_PTR)str; } while (*str++);
    return NULL;
}

static inline WCHAR *ntdll_wcsrchr( const WCHAR *str, WCHAR ch )
{
    WCHAR *ret = NULL;
    do { if (*str == ch) ret = (WCHAR *)(ULONG_PTR)str; } while (*str++);
    return ret;
}

static inline WCHAR *ntdll_wcspbrk( const WCHAR *str, const WCHAR *accept )
{
    for ( ; *str; str++) if (ntdll_wcschr( accept, *str )) return (WCHAR *)(ULONG_PTR)str;
    return NULL;
}

static inline WCHAR ntdll_towupper( WCHAR ch )
{
    return ch + uctable[uctable[uctable[ch >> 8] + ((ch >> 4) & 0x0f)] + (ch & 0x0f)];
}

static inline WCHAR ntdll_towlower( WCHAR ch )
{
    return ch + lctable[lctable[lctable[ch >> 8] + ((ch >> 4) & 0x0f)] + (ch & 0x0f)];
}

static inline WCHAR *ntdll_wcsupr( WCHAR *str )
{
    WCHAR *ret;
    for (ret = str; *str; str++) *str = ntdll_towupper(*str);
    return ret;
}

static inline int ntdll_wcsicmp( const WCHAR *str1, const WCHAR *str2 )
{
    int ret;
    for (;;)
    {
        if ((ret = ntdll_towupper( *str1 ) - ntdll_towupper( *str2 )) || !*str1) return ret;
        str1++;
        str2++;
    }
}

static inline int ntdll_wcsnicmp( const WCHAR *str1, const WCHAR *str2, int n )
{
    int ret;
    for (ret = 0; n > 0; n--, str1++, str2++)
        if ((ret = ntdll_towupper(*str1) - ntdll_towupper(*str2)) || !*str1) break;
    return ret;
}

#define wcslen(str)        ntdll_wcslen(str)
#define wcscpy(dst,src)    ntdll_wcscpy(dst,src)
#define wcscat(dst,src)    ntdll_wcscat(dst,src)
#define wcscmp(s1,s2)      ntdll_wcscmp(s1,s2)
#define wcsncmp(s1,s2,n)   ntdll_wcsncmp(s1,s2,n)
#define wcschr(str,ch)     ntdll_wcschr(str,ch)
#define wcsrchr(str,ch)    ntdll_wcsrchr(str,ch)
#define wcspbrk(str,ac)    ntdll_wcspbrk(str,ac)
#define wcsicmp(s1, s2)    ntdll_wcsicmp(s1,s2)
#define wcsnicmp(s1, s2,n) ntdll_wcsnicmp(s1,s2,n)
#define wcsupr(str)        ntdll_wcsupr(str)
#define towupper(c)        ntdll_towupper(c)
#define towlower(c)        ntdll_towlower(c)

#endif /* __NTDLL_UNIX_PRIVATE_H */
