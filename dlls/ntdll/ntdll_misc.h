/*
 * Copyright 2000 Juergen Schmied
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

#ifndef __WINE_NTDLL_MISC_H
#define __WINE_NTDLL_MISC_H

#include <stdarg.h>
#include <sys/types.h>

#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "unixlib.h"
#include "wine/debug.h"
#include "wine/server.h"
#include "wine/asm.h"

#define DECLARE_CRITICAL_SECTION(cs) \
    static RTL_CRITICAL_SECTION cs; \
    static RTL_CRITICAL_SECTION_DEBUG cs##_debug = \
    { 0, 0, &cs, { &cs##_debug.ProcessLocksList, &cs##_debug.ProcessLocksList }, \
      0, 0, { (DWORD_PTR)(__FILE__ ": " # cs) }}; \
    static RTL_CRITICAL_SECTION cs = { &cs##_debug, -1, 0, 0, 0, 0 };

#define MAX_NT_PATH_LENGTH 277

#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
static const UINT_PTR page_size = 0x1000;
#else
extern UINT_PTR page_size DECLSPEC_HIDDEN;
#endif

/* exceptions */
extern LONG call_vectored_handlers( EXCEPTION_RECORD *rec, CONTEXT *context ) DECLSPEC_HIDDEN;
extern void DECLSPEC_NORETURN raise_status( NTSTATUS status, EXCEPTION_RECORD *rec ) DECLSPEC_HIDDEN;
extern LONG WINAPI call_unhandled_exception_filter( PEXCEPTION_POINTERS eptr ) DECLSPEC_HIDDEN;

#if defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
extern RUNTIME_FUNCTION *lookup_function_info( ULONG_PTR pc, ULONG_PTR *base, LDR_DATA_TABLE_ENTRY **module ) DECLSPEC_HIDDEN;
#endif

/* debug helpers */
extern LPCSTR debugstr_us( const UNICODE_STRING *str ) DECLSPEC_HIDDEN;

/* init routines */
extern void version_init(void) DECLSPEC_HIDDEN;
extern void debug_init(void) DECLSPEC_HIDDEN;
extern void actctx_init(void) DECLSPEC_HIDDEN;
extern void heap_set_debug_flags( HANDLE handle ) DECLSPEC_HIDDEN;
extern void init_unix_codepage(void) DECLSPEC_HIDDEN;
extern void init_locale( HMODULE module ) DECLSPEC_HIDDEN;
extern void init_user_process_params(void) DECLSPEC_HIDDEN;
extern void CDECL DECLSPEC_NORETURN signal_start_thread( CONTEXT *ctx ) DECLSPEC_HIDDEN;

/* server support */
extern BOOL is_wow64 DECLSPEC_HIDDEN;

/* module handling */
extern LIST_ENTRY tls_links DECLSPEC_HIDDEN;
extern FARPROC RELAY_GetProcAddress( HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports,
                                     DWORD exp_size, FARPROC proc, DWORD ordinal, const WCHAR *user ) DECLSPEC_HIDDEN;
extern FARPROC SNOOP_GetProcAddress( HMODULE hmod, const IMAGE_EXPORT_DIRECTORY *exports, DWORD exp_size,
                                     FARPROC origfun, DWORD ordinal, const WCHAR *user ) DECLSPEC_HIDDEN;
extern void RELAY_SetupDLL( HMODULE hmod ) DECLSPEC_HIDDEN;
extern void SNOOP_SetupDLL( HMODULE hmod ) DECLSPEC_HIDDEN;
extern const WCHAR windows_dir[] DECLSPEC_HIDDEN;
extern const WCHAR system_dir[] DECLSPEC_HIDDEN;
extern const WCHAR syswow64_dir[] DECLSPEC_HIDDEN;

extern void (FASTCALL *pBaseThreadInitThunk)(DWORD,LPTHREAD_START_ROUTINE,void *) DECLSPEC_HIDDEN;
extern const struct unix_funcs *unix_funcs DECLSPEC_HIDDEN;

extern void init_directories(void) DECLSPEC_HIDDEN;

extern struct _KUSER_SHARED_DATA *user_shared_data DECLSPEC_HIDDEN;

/* locale */
extern LCID user_lcid, system_lcid;
extern DWORD ntdll_umbstowcs( const char* src, DWORD srclen, WCHAR* dst, DWORD dstlen ) DECLSPEC_HIDDEN;
extern int ntdll_wcstoumbs( const WCHAR* src, DWORD srclen, char* dst, DWORD dstlen, BOOL strict ) DECLSPEC_HIDDEN;

extern int CDECL NTDLL__vsnprintf( char *str, SIZE_T len, const char *format, __ms_va_list args ) DECLSPEC_HIDDEN;
extern int CDECL NTDLL__vsnwprintf( WCHAR *str, SIZE_T len, const WCHAR *format, __ms_va_list args ) DECLSPEC_HIDDEN;

/* inline version of RtlEnterCriticalSection */
static inline void enter_critical_section( RTL_CRITICAL_SECTION *crit )
{
    if (InterlockedIncrement( &crit->LockCount ))
    {
        if (crit->OwningThread == ULongToHandle(GetCurrentThreadId()))
        {
            crit->RecursionCount++;
            return;
        }
        RtlpWaitForCriticalSection( crit );
    }
    crit->OwningThread   = ULongToHandle(GetCurrentThreadId());
    crit->RecursionCount = 1;
}

/* inline version of RtlLeaveCriticalSection */
static inline void leave_critical_section( RTL_CRITICAL_SECTION *crit )
{
    WINE_DECLARE_DEBUG_CHANNEL(ntdll);
    if (--crit->RecursionCount)
    {
        if (crit->RecursionCount > 0) InterlockedDecrement( &crit->LockCount );
        else ERR_(ntdll)( "section %p is not acquired\n", crit );
    }
    else
    {
        crit->OwningThread = 0;
        if (InterlockedDecrement( &crit->LockCount ) >= 0)
            RtlpUnWaitCriticalSection( crit );
    }
}

/* load order */

enum loadorder
{
    LO_INVALID,
    LO_DISABLED,
    LO_NATIVE,
    LO_BUILTIN,
    LO_NATIVE_BUILTIN,  /* native then builtin */
    LO_BUILTIN_NATIVE,  /* builtin then native */
    LO_DEFAULT          /* nothing specified, use default strategy */
};

extern enum loadorder get_load_order( const WCHAR *app_name, const UNICODE_STRING *nt_name ) DECLSPEC_HIDDEN;

#ifndef _WIN64
static inline TEB64 *NtCurrentTeb64(void) { return (TEB64 *)NtCurrentTeb()->GdiBatchCount; }
#endif

#define HASH_STRING_ALGORITHM_DEFAULT  0
#define HASH_STRING_ALGORITHM_X65599   1
#define HASH_STRING_ALGORITHM_INVALID  0xffffffff

NTSTATUS WINAPI RtlHashUnicodeString(PCUNICODE_STRING,BOOLEAN,ULONG,ULONG*);

/* convert from straight ASCII to Unicode without depending on the current codepage */
static inline void ascii_to_unicode( WCHAR *dst, const char *src, size_t len )
{
    while (len--) *dst++ = (unsigned char)*src++;
}

/* FLS data */
extern void init_global_fls_data(void) DECLSPEC_HIDDEN;
extern TEB_FLS_DATA *fls_alloc_data(void) DECLSPEC_HIDDEN;

#endif
