/*
 * Win32 threads
 *
 * Copyright 1996 Alexandre Julliard
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

#include "config.h"

#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>
#ifdef HAVE_SYS_PRCTL_H
# include <sys/prctl.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winternl.h"
#include "winnls.h"
#include "wine/debug.h"

#include "kernel_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(thread);


/***********************************************************************
 *           FreeLibraryAndExitThread (KERNEL32.@)
 */
void WINAPI FreeLibraryAndExitThread(HINSTANCE hLibModule, DWORD dwExitCode)
{
    FreeLibrary(hLibModule);
    ExitThread(dwExitCode);
}


/***********************************************************************
 * Wow64SetThreadContext [KERNEL32.@]
 */
BOOL WINAPI Wow64SetThreadContext( HANDLE handle, const WOW64_CONTEXT *context)
{
#ifdef __i386__
    NTSTATUS status = NtSetContextThread( handle, (const CONTEXT *)context );
#elif defined(__x86_64__)
    NTSTATUS status = RtlWow64SetThreadContext( handle, context );
#else
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
#endif
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}

/***********************************************************************
 * Wow64GetThreadContext [KERNEL32.@]
 */
BOOL WINAPI Wow64GetThreadContext( HANDLE handle, WOW64_CONTEXT *context)
{
#ifdef __i386__
    NTSTATUS status = NtGetContextThread( handle, (CONTEXT *)context );
#elif defined(__x86_64__)
    NTSTATUS status = RtlWow64GetThreadContext( handle, context );
#else
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
#endif
    if (status) SetLastError( RtlNtStatusToDosError(status) );
    return !status;
}


/* ??? MSDN says it should be HRESULT, but we get this */
#define THREADDESC_SUCCESS 0x10000000

/***********************************************************************
* SetThreadDescription [KERNEL32.@]  Sets name of thread.
*
* RETURNS
*    Success: TRUE
*    Failure: FALSE
*/
HRESULT WINAPI SetThreadDescription( HANDLE handle, const WCHAR *descW )
{
TRACE("(%p,%s)\n", handle, wine_dbgstr_w( descW ));

if (handle != GetCurrentThread())
{
    FIXME("Can't set other thread description\n");
    return THREADDESC_SUCCESS;
}

#ifdef HAVE_PRCTL

#ifndef PR_SET_NAME
# define PR_SET_NAME 15
#endif

if (descW)
{
    DWORD length;
    char *descA;

    length = WideCharToMultiByte( CP_UNIXCP, 0, descW, -1, NULL, 0, NULL, NULL );
    if (!(descA = HeapAlloc( GetProcessHeap(), 0, length ))) return E_OUTOFMEMORY;
    WideCharToMultiByte( CP_UNIXCP, 0, descW, -1, descA, length, NULL, NULL );

    prctl( PR_SET_NAME, descA );

    HeapFree( GetProcessHeap(), 0, descA );
}
else
    prctl( PR_SET_NAME, "" );

#endif  /* HAVE_PRCTL */

return THREADDESC_SUCCESS;
}


/***********************************************************************
* GetThreadDescription [KERNEL32.@]  Retrieves name of thread.
*
* RETURNS
*    Success: TRUE
*    Failure: FALSE
*/
HRESULT WINAPI GetThreadDescription( HANDLE handle, WCHAR **descW )
{
#ifdef HAVE_PRCTL
char descA[16];
#endif

*descW = LocalAlloc( 0, 16 * sizeof(WCHAR) );
if(!*descW)
    return E_OUTOFMEMORY;

if (handle != GetCurrentThread())
{
    FIXME("Can't get other thread description\n");
    (*descW)[0] = 0;
    return THREADDESC_SUCCESS;
}

#ifdef HAVE_PRCTL
#ifndef PR_GET_NAME
# define PR_GET_NAME 16
#endif

    if (prctl( PR_GET_NAME, descA ) != 0)
    {
        (*descW)[0] = 0;
        return THREADDESC_SUCCESS;
    }

    MultiByteToWideChar( CP_UNIXCP, 0, descA, -1, *descW, 16 );
#else
    (*descW)[0] = 0;
#endif

    return THREADDESC_SUCCESS;
}


/**********************************************************************
 *           SetThreadAffinityMask   (KERNEL32.@)
 */
DWORD_PTR WINAPI SetThreadAffinityMask( HANDLE hThread, DWORD_PTR dwThreadAffinityMask )
{
    NTSTATUS                    status;
    THREAD_BASIC_INFORMATION    tbi;

    status = NtQueryInformationThread( hThread, ThreadBasicInformation, 
                                       &tbi, sizeof(tbi), NULL );
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return 0;
    }
    status = NtSetInformationThread( hThread, ThreadAffinityMask, 
                                     &dwThreadAffinityMask,
                                     sizeof(dwThreadAffinityMask));
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return 0;
    }
    return tbi.AffinityMask;
}


/***********************************************************************
 *           GetThreadSelectorEntry   (KERNEL32.@)
 */
BOOL WINAPI GetThreadSelectorEntry( HANDLE hthread, DWORD sel, LPLDT_ENTRY ldtent )
{
    THREAD_DESCRIPTOR_INFORMATION tdi;
    NTSTATUS status;

    tdi.Selector = sel;
    status = NtQueryInformationThread( hthread, ThreadDescriptorTableEntry, &tdi, sizeof(tdi), NULL);
    if (status)
    {
        SetLastError( RtlNtStatusToDosError(status) );
        return FALSE;
    }
    *ldtent = tdi.Entry;
    return TRUE;
}


/***********************************************************************
 * GetCurrentThread [KERNEL32.@]  Gets pseudohandle for current thread
 *
 * RETURNS
 *    Pseudohandle for the current thread
 */
HANDLE WINAPI KERNEL32_GetCurrentThread(void)
{
    return (HANDLE)~(ULONG_PTR)1;
}

/***********************************************************************
 *		GetCurrentProcessId (KERNEL32.@)
 *
 * Get the current process identifier.
 *
 * RETURNS
 *  current process identifier
 */
DWORD WINAPI KERNEL32_GetCurrentProcessId(void)
{
    return HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess);
}

/***********************************************************************
 *		GetCurrentThreadId (KERNEL32.@)
 *
 * Get the current thread identifier.
 *
 * RETURNS
 *  current thread identifier
 */
DWORD WINAPI KERNEL32_GetCurrentThreadId(void)
{
    return HandleToULong(NtCurrentTeb()->ClientId.UniqueThread);
}
