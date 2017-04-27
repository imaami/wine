/*
 * Win32 processes
 *
 * Copyright 1996, 1998 Alexandre Julliard
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

#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winternl.h"

#include "kernelbase.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(process);

static DWORD shutdown_flags = 0;
static DWORD shutdown_priority = 0x280;

/***********************************************************************
 * Processes
 ***********************************************************************/


/***********************************************************************
 *           find_exe_file
 */
static BOOL find_exe_file( const WCHAR *name, WCHAR *buffer, DWORD buflen )
{
    WCHAR *load_path;
    BOOL ret;

    if (!set_ntstatus( RtlGetExePath( name, &load_path ))) return FALSE;

    TRACE( "looking for %s in %s\n", debugstr_w(name), debugstr_w(load_path) );

    ret = (SearchPathW( load_path, name, L".exe", buflen, buffer, NULL ) ||
           /* not found, try without extension in case it is a Unix app */
           SearchPathW( load_path, name, NULL, buflen, buffer, NULL ));

    if (ret)  /* make sure it can be opened, SearchPathW also returns directories */
    {
        HANDLE handle = CreateFileW( buffer, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE,
                                     NULL, OPEN_EXISTING, 0, 0 );
        if ((ret = (handle != INVALID_HANDLE_VALUE))) CloseHandle( handle );
    }
    RtlReleasePath( load_path );
    return ret;
}


/*************************************************************************
 *               get_file_name
 *
 * Helper for CreateProcess: retrieve the file name to load from the
 * app name and command line. Store the file name in buffer, and
 * return a possibly modified command line.
 */
static WCHAR *get_file_name( WCHAR *cmdline, WCHAR *buffer, DWORD buflen )
{
    WCHAR *name, *pos, *first_space, *ret = NULL;
    const WCHAR *p;

    /* first check for a quoted file name */

    if (cmdline[0] == '"' && (p = wcschr( cmdline + 1, '"' )))
    {
        int len = p - cmdline - 1;
        /* extract the quoted portion as file name */
        if (!(name = RtlAllocateHeap( GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR) ))) return NULL;
        memcpy( name, cmdline + 1, len * sizeof(WCHAR) );
        name[len] = 0;

        if (!find_exe_file( name, buffer, buflen )) goto done;
        ret = cmdline;  /* no change necessary */
        goto done;
    }

    /* now try the command-line word by word */

    if (!(name = RtlAllocateHeap( GetProcessHeap(), 0, (lstrlenW(cmdline) + 1) * sizeof(WCHAR) )))
        return NULL;
    pos = name;
    p = cmdline;
    first_space = NULL;

    for (;;)
    {
        while (*p && *p != ' ' && *p != '\t') *pos++ = *p++;
        *pos = 0;
        if (find_exe_file( name, buffer, buflen ))
        {
            ret = cmdline;
            break;
        }
        if (!first_space) first_space = pos;
        if (!(*pos++ = *p++)) break;
    }

    if (!ret)
    {
        SetLastError( ERROR_FILE_NOT_FOUND );
    }
    else if (first_space)  /* build a new command-line with quotes */
    {
        if (!(ret = HeapAlloc( GetProcessHeap(), 0, (lstrlenW(cmdline) + 3) * sizeof(WCHAR) )))
            goto done;
        swprintf( ret, lstrlenW(cmdline) + 3, L"\"%s\"%s", name, p );
    }

 done:
    RtlFreeHeap( GetProcessHeap(), 0, name );
    return ret;
}


/***********************************************************************
 *           create_process_params
 */
static RTL_USER_PROCESS_PARAMETERS *create_process_params( const WCHAR *filename, const WCHAR *cmdline,
                                                           const WCHAR *cur_dir, void *env, DWORD flags,
                                                           const STARTUPINFOW *startup )
{
    RTL_USER_PROCESS_PARAMETERS *params;
    UNICODE_STRING imageW, dllpathW, curdirW, cmdlineW, titleW, desktopW, runtimeW, newdirW;
    WCHAR imagepath[MAX_PATH];
    WCHAR *load_path, *dummy, *envW = env;

    if (!GetLongPathNameW( filename, imagepath, MAX_PATH )) lstrcpynW( imagepath, filename, MAX_PATH );
    if (!GetFullPathNameW( imagepath, MAX_PATH, imagepath, NULL )) lstrcpynW( imagepath, filename, MAX_PATH );

    if (env && !(flags & CREATE_UNICODE_ENVIRONMENT))  /* convert environment to unicode */
    {
        char *e = env;
        DWORD lenW;

        while (*e) e += strlen(e) + 1;
        e++;  /* final null */
        lenW = MultiByteToWideChar( CP_ACP, 0, env, e - (char *)env, NULL, 0 );
        if ((envW = RtlAllocateHeap( GetProcessHeap(), 0, lenW * sizeof(WCHAR) )))
            MultiByteToWideChar( CP_ACP, 0, env, e - (char *)env, envW, lenW );
    }

    newdirW.Buffer = NULL;
    if (cur_dir)
    {
        if (RtlDosPathNameToNtPathName_U( cur_dir, &newdirW, NULL, NULL ))
            cur_dir = newdirW.Buffer + 4;  /* skip \??\ prefix */
        else
            cur_dir = NULL;
    }
    LdrGetDllPath( imagepath, LOAD_WITH_ALTERED_SEARCH_PATH, &load_path, &dummy );
    RtlInitUnicodeString( &imageW, imagepath );
    RtlInitUnicodeString( &dllpathW, load_path );
    RtlInitUnicodeString( &curdirW, cur_dir );
    RtlInitUnicodeString( &cmdlineW, cmdline );
    RtlInitUnicodeString( &titleW, startup->lpTitle ? startup->lpTitle : imagepath );
    RtlInitUnicodeString( &desktopW, startup->lpDesktop );
    runtimeW.Buffer = (WCHAR *)startup->lpReserved2;
    runtimeW.Length = runtimeW.MaximumLength = startup->cbReserved2;
    if (RtlCreateProcessParametersEx( &params, &imageW, &dllpathW, cur_dir ? &curdirW : NULL,
                                      &cmdlineW, envW, &titleW, &desktopW,
                                      NULL, &runtimeW, PROCESS_PARAMS_FLAG_NORMALIZED ))
    {
        RtlFreeUnicodeString( &newdirW );
        RtlReleasePath( load_path );
        if (envW != env) RtlFreeHeap( GetProcessHeap(), 0, envW );
        return NULL;
    }
    RtlFreeUnicodeString( &newdirW );
    RtlReleasePath( load_path );

    if (flags & CREATE_NEW_PROCESS_GROUP) params->ConsoleFlags = 1;
    if (flags & CREATE_NEW_CONSOLE) params->ConsoleHandle = (HANDLE)1; /* KERNEL32_CONSOLE_ALLOC */

    if (startup->dwFlags & STARTF_USESTDHANDLES)
    {
        params->hStdInput  = startup->hStdInput;
        params->hStdOutput = startup->hStdOutput;
        params->hStdError  = startup->hStdError;
    }
    else if (flags & DETACHED_PROCESS)
    {
        params->hStdInput  = INVALID_HANDLE_VALUE;
        params->hStdOutput = INVALID_HANDLE_VALUE;
        params->hStdError  = INVALID_HANDLE_VALUE;
    }
    else
    {
        params->hStdInput  = NtCurrentTeb()->Peb->ProcessParameters->hStdInput;
        params->hStdOutput = NtCurrentTeb()->Peb->ProcessParameters->hStdOutput;
        params->hStdError  = NtCurrentTeb()->Peb->ProcessParameters->hStdError;
    }

    if (flags & CREATE_NEW_CONSOLE)
    {
        /* this is temporary (for console handles). We have no way to control that the handle is invalid in child process otherwise */
        if (is_console_handle(params->hStdInput))  params->hStdInput  = INVALID_HANDLE_VALUE;
        if (is_console_handle(params->hStdOutput)) params->hStdOutput = INVALID_HANDLE_VALUE;
        if (is_console_handle(params->hStdError))  params->hStdError  = INVALID_HANDLE_VALUE;
    }
    else
    {
        if (is_console_handle(params->hStdInput))  params->hStdInput  = (HANDLE)((UINT_PTR)params->hStdInput & ~3);
        if (is_console_handle(params->hStdOutput)) params->hStdOutput = (HANDLE)((UINT_PTR)params->hStdOutput & ~3);
        if (is_console_handle(params->hStdError))  params->hStdError  = (HANDLE)((UINT_PTR)params->hStdError & ~3);
    }

    params->dwX             = startup->dwX;
    params->dwY             = startup->dwY;
    params->dwXSize         = startup->dwXSize;
    params->dwYSize         = startup->dwYSize;
    params->dwXCountChars   = startup->dwXCountChars;
    params->dwYCountChars   = startup->dwYCountChars;
    params->dwFillAttribute = startup->dwFillAttribute;
    params->dwFlags         = startup->dwFlags;
    params->wShowWindow     = startup->wShowWindow;

    if (envW != env) RtlFreeHeap( GetProcessHeap(), 0, envW );
    return params;
}


/***********************************************************************
 *           create_nt_process
 */
static NTSTATUS create_nt_process( SECURITY_ATTRIBUTES *psa, SECURITY_ATTRIBUTES *tsa,
                                   BOOL inherit, DWORD flags, RTL_USER_PROCESS_PARAMETERS *params,
                                   RTL_USER_PROCESS_INFORMATION *info, HANDLE parent )
{
    NTSTATUS status;
    UNICODE_STRING nameW;

    if (!params->ImagePathName.Buffer[0]) return STATUS_OBJECT_PATH_NOT_FOUND;
    status = RtlDosPathNameToNtPathName_U_WithStatus( params->ImagePathName.Buffer, &nameW, NULL, NULL );
    if (!status)
    {
        params->DebugFlags = flags;  /* hack, cf. RtlCreateUserProcess implementation */
        status = RtlCreateUserProcess( &nameW, OBJ_CASE_INSENSITIVE, params,
                                       psa ? psa->lpSecurityDescriptor : NULL,
                                       tsa ? tsa->lpSecurityDescriptor : NULL,
                                       parent, inherit, 0, 0, info );
        RtlFreeUnicodeString( &nameW );
    }
    return status;
}


/***********************************************************************
 *           create_vdm_process
 */
static NTSTATUS create_vdm_process( SECURITY_ATTRIBUTES *psa, SECURITY_ATTRIBUTES *tsa,
                                    BOOL inherit, DWORD flags, RTL_USER_PROCESS_PARAMETERS *params,
                                    RTL_USER_PROCESS_INFORMATION *info )
{
    const WCHAR *winevdm = (is_win64 || is_wow64 ?
                            L"C:\\windows\\syswow64\\winevdm.exe" :
                            L"C:\\windows\\system32\\winevdm.exe");
    WCHAR *newcmdline;
    NTSTATUS status;
    UINT len;

    len = (lstrlenW(params->ImagePathName.Buffer) + lstrlenW(params->CommandLine.Buffer) +
           lstrlenW(winevdm) + 16);

    if (!(newcmdline = RtlAllocateHeap( GetProcessHeap(), 0, len * sizeof(WCHAR) )))
        return STATUS_NO_MEMORY;

    swprintf( newcmdline, len, L"%s --app-name \"%s\" %s",
              winevdm, params->ImagePathName.Buffer, params->CommandLine.Buffer );
    RtlInitUnicodeString( &params->ImagePathName, winevdm );
    RtlInitUnicodeString( &params->CommandLine, newcmdline );
    status = create_nt_process( psa, tsa, inherit, flags, params, info, NULL );
    HeapFree( GetProcessHeap(), 0, newcmdline );
    return status;
}


/***********************************************************************
 *           create_cmd_process
 */
static NTSTATUS create_cmd_process( SECURITY_ATTRIBUTES *psa, SECURITY_ATTRIBUTES *tsa,
                                    BOOL inherit, DWORD flags, RTL_USER_PROCESS_PARAMETERS *params,
                                    RTL_USER_PROCESS_INFORMATION *info )
{
    WCHAR comspec[MAX_PATH];
    WCHAR *newcmdline;
    NTSTATUS status;
    UINT len;

    if (!GetEnvironmentVariableW( L"COMSPEC", comspec, ARRAY_SIZE( comspec )))
        lstrcpyW( comspec, L"C:\\windows\\system32\\cmd.exe" );

    len = lstrlenW(comspec) + 7 + lstrlenW(params->CommandLine.Buffer) + 2;
    if (!(newcmdline = RtlAllocateHeap( GetProcessHeap(), 0, len * sizeof(WCHAR) )))
        return STATUS_NO_MEMORY;

    swprintf( newcmdline, len, L"%s /s/c \"%s\"", comspec, params->CommandLine.Buffer );
    RtlInitUnicodeString( &params->ImagePathName, comspec );
    RtlInitUnicodeString( &params->CommandLine, newcmdline );
    status = create_nt_process( psa, tsa, inherit, flags, params, info, NULL );
    RtlFreeHeap( GetProcessHeap(), 0, newcmdline );
    return status;
}


/*********************************************************************
 *           CloseHandle   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH CloseHandle( HANDLE handle )
{
    if (handle == (HANDLE)STD_INPUT_HANDLE)
        handle = InterlockedExchangePointer( &NtCurrentTeb()->Peb->ProcessParameters->hStdInput, 0 );
    else if (handle == (HANDLE)STD_OUTPUT_HANDLE)
        handle = InterlockedExchangePointer( &NtCurrentTeb()->Peb->ProcessParameters->hStdOutput, 0 );
    else if (handle == (HANDLE)STD_ERROR_HANDLE)
        handle = InterlockedExchangePointer( &NtCurrentTeb()->Peb->ProcessParameters->hStdError, 0 );

    if (is_console_handle( handle )) handle = console_handle_map( handle );
    return set_ntstatus( NtClose( handle ));
}


/**********************************************************************
 *           CreateProcessAsUserA   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH CreateProcessAsUserA( HANDLE token, const char *app_name, char *cmd_line,
                                                    SECURITY_ATTRIBUTES *process_attr,
                                                    SECURITY_ATTRIBUTES *thread_attr,
                                                    BOOL inherit, DWORD flags, void *env,
                                                    const char *cur_dir, STARTUPINFOA *startup_info,
                                                    PROCESS_INFORMATION *info )
{
    return CreateProcessInternalA( token, app_name, cmd_line, process_attr, thread_attr,
                                   inherit, flags, env, cur_dir, startup_info, info, NULL );
}


/**********************************************************************
 *           CreateProcessAsUserW   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH CreateProcessAsUserW( HANDLE token, const WCHAR *app_name, WCHAR *cmd_line,
                                                    SECURITY_ATTRIBUTES *process_attr,
                                                    SECURITY_ATTRIBUTES *thread_attr,
                                                    BOOL inherit, DWORD flags, void *env,
                                                    const WCHAR *cur_dir, STARTUPINFOW *startup_info,
                                                    PROCESS_INFORMATION *info )
{
    return CreateProcessInternalW( token, app_name, cmd_line, process_attr, thread_attr,
                                   inherit, flags, env, cur_dir, startup_info, info, NULL );
}

/**********************************************************************
 *           CreateProcessInternalA   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH CreateProcessInternalA( HANDLE token, const char *app_name, char *cmd_line,
                                                      SECURITY_ATTRIBUTES *process_attr,
                                                      SECURITY_ATTRIBUTES *thread_attr,
                                                      BOOL inherit, DWORD flags, void *env,
                                                      const char *cur_dir, STARTUPINFOA *startup_info,
                                                      PROCESS_INFORMATION *info, HANDLE *new_token )
{
    BOOL ret = FALSE;
    WCHAR *app_nameW = NULL, *cmd_lineW = NULL, *cur_dirW = NULL;
    UNICODE_STRING desktopW, titleW;
    STARTUPINFOEXW infoW;

    desktopW.Buffer = NULL;
    titleW.Buffer = NULL;
    if (app_name && !(app_nameW = file_name_AtoW( app_name, TRUE ))) goto done;
    if (cmd_line && !(cmd_lineW = file_name_AtoW( cmd_line, TRUE ))) goto done;
    if (cur_dir && !(cur_dirW = file_name_AtoW( cur_dir, TRUE ))) goto done;

    if (startup_info->lpDesktop) RtlCreateUnicodeStringFromAsciiz( &desktopW, startup_info->lpDesktop );
    if (startup_info->lpTitle) RtlCreateUnicodeStringFromAsciiz( &titleW, startup_info->lpTitle );

    memcpy( &infoW.StartupInfo, startup_info, sizeof(infoW.StartupInfo) );
    infoW.StartupInfo.lpDesktop = desktopW.Buffer;
    infoW.StartupInfo.lpTitle = titleW.Buffer;

    if (flags & EXTENDED_STARTUPINFO_PRESENT)
        infoW.lpAttributeList = ((STARTUPINFOEXW *)startup_info)->lpAttributeList;

    ret = CreateProcessInternalW( token, app_nameW, cmd_lineW, process_attr, thread_attr,
                                  inherit, flags, env, cur_dirW, (STARTUPINFOW *)&infoW, info, new_token );
done:
    RtlFreeHeap( GetProcessHeap(), 0, app_nameW );
    RtlFreeHeap( GetProcessHeap(), 0, cmd_lineW );
    RtlFreeHeap( GetProcessHeap(), 0, cur_dirW );
    RtlFreeUnicodeString( &desktopW );
    RtlFreeUnicodeString( &titleW );
    return ret;
}

struct proc_thread_attr
{
    DWORD_PTR attr;
    SIZE_T size;
    void *value;
};

struct _PROC_THREAD_ATTRIBUTE_LIST
{
    DWORD mask;  /* bitmask of items in list */
    DWORD size;  /* max number of items in list */
    DWORD count; /* number of items in list */
    DWORD pad;
    DWORD_PTR unk;
    struct proc_thread_attr attrs[1];
};

/**********************************************************************
 *           CreateProcessInternalW   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH CreateProcessInternalW( HANDLE token, const WCHAR *app_name, WCHAR *cmd_line,
                                                      SECURITY_ATTRIBUTES *process_attr,
                                                      SECURITY_ATTRIBUTES *thread_attr,
                                                      BOOL inherit, DWORD flags, void *env,
                                                      const WCHAR *cur_dir, STARTUPINFOW *startup_info,
                                                      PROCESS_INFORMATION *info, HANDLE *new_token )
{
    WCHAR name[MAX_PATH];
    WCHAR *p, *tidy_cmdline = cmd_line;
    RTL_USER_PROCESS_PARAMETERS *params = NULL;
    RTL_USER_PROCESS_INFORMATION rtl_info;
    HANDLE parent = NULL;
    NTSTATUS status;

    /* Process the AppName and/or CmdLine to get module name and path */

    TRACE( "app %s cmdline %s\n", debugstr_w(app_name), debugstr_w(cmd_line) );

    if (token) FIXME( "Creating a process with a token is not yet implemented\n" );
    if (new_token) FIXME( "No support for returning created process token\n" );

    if (app_name)
    {
        if (!cmd_line || !cmd_line[0]) /* no command-line, create one */
        {
            if (!(tidy_cmdline = RtlAllocateHeap( GetProcessHeap(), 0, (lstrlenW(app_name)+3) * sizeof(WCHAR) )))
                return FALSE;
            swprintf( tidy_cmdline, lstrlenW(app_name) + 3, L"\"%s\"", app_name );
        }
    }
    else
    {
        if (!(tidy_cmdline = get_file_name( cmd_line, name, ARRAY_SIZE(name) ))) return FALSE;
        app_name = name;
    }

    /* Warn if unsupported features are used */

    if (flags & (IDLE_PRIORITY_CLASS | HIGH_PRIORITY_CLASS | REALTIME_PRIORITY_CLASS |
                 CREATE_DEFAULT_ERROR_MODE | CREATE_NO_WINDOW |
                 PROFILE_USER | PROFILE_KERNEL | PROFILE_SERVER))
        WARN( "(%s,...): ignoring some flags in %x\n", debugstr_w(app_name), flags );

    if (cur_dir)
    {
        DWORD attr = GetFileAttributesW( cur_dir );
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
        {
            status = STATUS_NOT_A_DIRECTORY;
            goto done;
        }
    }

    info->hThread = info->hProcess = 0;
    info->dwProcessId = info->dwThreadId = 0;

    if (!(params = create_process_params( app_name, tidy_cmdline, cur_dir, env, flags, startup_info )))
    {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    if (flags & EXTENDED_STARTUPINFO_PRESENT)
    {
        struct _PROC_THREAD_ATTRIBUTE_LIST *attrs =
                (struct _PROC_THREAD_ATTRIBUTE_LIST *)((STARTUPINFOEXW *)startup_info)->lpAttributeList;
        unsigned int i;

        if (attrs)
        {
            for (i = 0; i < attrs->count; ++i)
            {
                switch(attrs->attrs[i].attr)
                {
                    case PROC_THREAD_ATTRIBUTE_PARENT_PROCESS:
                        parent = *(HANDLE *)attrs->attrs[i].value;
                        TRACE("PROC_THREAD_ATTRIBUTE_PARENT_PROCESS parent %p.\n", parent);
                        if (!parent)
                        {
                            status = STATUS_INVALID_HANDLE;
                            goto done;
                        }
                        break;
                    default:
                        FIXME("Unsupported attribute %#Ix.\n", attrs->attrs[i].attr);
                        break;
                }
            }
        }
    }

    status = create_nt_process( process_attr, thread_attr, inherit, flags, params, &rtl_info, parent );
    switch (status)
    {
    case STATUS_SUCCESS:
        break;
    case STATUS_INVALID_IMAGE_WIN_16:
    case STATUS_INVALID_IMAGE_NE_FORMAT:
    case STATUS_INVALID_IMAGE_PROTECT:
        TRACE( "starting %s as Win16/DOS binary\n", debugstr_w(app_name) );
        status = create_vdm_process( process_attr, thread_attr, inherit, flags, params, &rtl_info );
        break;
    case STATUS_INVALID_IMAGE_NOT_MZ:
        /* check for .com or .bat extension */
        if (!(p = wcsrchr( app_name, '.' ))) break;
        if (!wcsicmp( p, L".com" ) || !wcsicmp( p, L".pif" ))
        {
            TRACE( "starting %s as DOS binary\n", debugstr_w(app_name) );
            status = create_vdm_process( process_attr, thread_attr, inherit, flags, params, &rtl_info );
        }
        else if (!wcsicmp( p, L".bat" ) || !wcsicmp( p, L".cmd" ))
        {
            TRACE( "starting %s as batch binary\n", debugstr_w(app_name) );
            status = create_cmd_process( process_attr, thread_attr, inherit, flags, params, &rtl_info );
        }
        break;
    }

    if (!status)
    {
        info->hProcess    = rtl_info.Process;
        info->hThread     = rtl_info.Thread;
        info->dwProcessId = HandleToUlong( rtl_info.ClientId.UniqueProcess );
        info->dwThreadId  = HandleToUlong( rtl_info.ClientId.UniqueThread );
        if (!(flags & CREATE_SUSPENDED)) NtResumeThread( rtl_info.Thread, NULL );
        TRACE( "started process pid %04x tid %04x\n", info->dwProcessId, info->dwThreadId );
    }

 done:
    RtlDestroyProcessParameters( params );
    if (tidy_cmdline != cmd_line) HeapFree( GetProcessHeap(), 0, tidy_cmdline );
    return set_ntstatus( status );
}


/**********************************************************************
 *           CreateProcessA   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH CreateProcessA( const char *app_name, char *cmd_line,
                                              SECURITY_ATTRIBUTES *process_attr,
                                              SECURITY_ATTRIBUTES *thread_attr, BOOL inherit,
                                              DWORD flags, void *env, const char *cur_dir,
                                              STARTUPINFOA *startup_info, PROCESS_INFORMATION *info )
{
    return CreateProcessInternalA( NULL, app_name, cmd_line, process_attr, thread_attr,
                                   inherit, flags, env, cur_dir, startup_info, info, NULL );
}


/**********************************************************************
 *           CreateProcessW   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH CreateProcessW( const WCHAR *app_name, WCHAR *cmd_line,
                                              SECURITY_ATTRIBUTES *process_attr,
                                              SECURITY_ATTRIBUTES *thread_attr, BOOL inherit, DWORD flags,
                                              void *env, const WCHAR *cur_dir, STARTUPINFOW *startup_info,
                                              PROCESS_INFORMATION *info )
{
    return CreateProcessInternalW( NULL, app_name, cmd_line, process_attr, thread_attr,
                                   inherit, flags, env, cur_dir, startup_info, info, NULL );
}


/*********************************************************************
 *           DuplicateHandle   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH DuplicateHandle( HANDLE source_process, HANDLE source,
                                               HANDLE dest_process, HANDLE *dest,
                                               DWORD access, BOOL inherit, DWORD options )
{
    if (is_console_handle( source ))
    {
        source = console_handle_map( source );
        if (!set_ntstatus( NtDuplicateObject( source_process, source, dest_process, dest,
                                              access, inherit ? OBJ_INHERIT : 0, options )))
            return FALSE;
        *dest = console_handle_map( *dest );
        return TRUE;
    }
    return set_ntstatus( NtDuplicateObject( source_process, source, dest_process, dest,
                                            access, inherit ? OBJ_INHERIT : 0, options ));
}


/****************************************************************************
 *           FlushInstructionCache   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH FlushInstructionCache( HANDLE process, LPCVOID addr, SIZE_T size )
{
    return set_ntstatus( NtFlushInstructionCache( process, addr, size ));
}


/***********************************************************************
 *           GetApplicationRestartSettings   (kernelbase.@)
 */
HRESULT WINAPI /* DECLSPEC_HOTPATCH */ GetApplicationRestartSettings( HANDLE process, WCHAR *cmdline,
                                                                      DWORD *size, DWORD *flags )
{
    FIXME( "%p, %p, %p, %p)\n", process, cmdline, size, flags );
    return E_NOTIMPL;
}


/***********************************************************************
 *           GetCurrentProcess   (kernelbase.@)
 */
HANDLE WINAPI kernelbase_GetCurrentProcess(void)
{
    return (HANDLE)~(ULONG_PTR)0;
}


/***********************************************************************
 *           GetCurrentProcessId   (kernelbase.@)
 */
DWORD WINAPI kernelbase_GetCurrentProcessId(void)
{
    return HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
}


/***********************************************************************
 *           GetErrorMode   (kernelbase.@)
 */
UINT WINAPI DECLSPEC_HOTPATCH GetErrorMode(void)
{
    UINT mode;

    NtQueryInformationProcess( GetCurrentProcess(), ProcessDefaultHardErrorMode,
                               &mode, sizeof(mode), NULL );
    return mode;
}


/***********************************************************************
 *           GetExitCodeProcess   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetExitCodeProcess( HANDLE process, LPDWORD exit_code )
{
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;

    status = NtQueryInformationProcess( process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL );
    if (status && exit_code) *exit_code = pbi.ExitStatus;
    return set_ntstatus( status );
}


/*********************************************************************
 *           GetHandleInformation   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetHandleInformation( HANDLE handle, DWORD *flags )
{
    OBJECT_DATA_INFORMATION info;

    if (!set_ntstatus( NtQueryObject( handle, ObjectDataInformation, &info, sizeof(info), NULL )))
        return FALSE;

    if (flags)
    {
        *flags = 0;
        if (info.InheritHandle) *flags |= HANDLE_FLAG_INHERIT;
        if (info.ProtectFromClose) *flags |= HANDLE_FLAG_PROTECT_FROM_CLOSE;
    }
    return TRUE;
}


/***********************************************************************
 *           GetPriorityClass   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH GetPriorityClass( HANDLE process )
{
    PROCESS_BASIC_INFORMATION pbi;

    if (!set_ntstatus( NtQueryInformationProcess( process, ProcessBasicInformation,
                                                  &pbi, sizeof(pbi), NULL )))
        return 0;

    switch (pbi.BasePriority)
    {
    case PROCESS_PRIOCLASS_IDLE: return IDLE_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_BELOW_NORMAL: return BELOW_NORMAL_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_NORMAL: return NORMAL_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_ABOVE_NORMAL: return ABOVE_NORMAL_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_HIGH: return HIGH_PRIORITY_CLASS;
    case PROCESS_PRIOCLASS_REALTIME: return REALTIME_PRIORITY_CLASS;
    default: return 0;
    }
}


/******************************************************************
 *           GetProcessHandleCount   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetProcessHandleCount( HANDLE process, DWORD *count )
{
    return set_ntstatus( NtQueryInformationProcess( process, ProcessHandleCount,
                                                    count, sizeof(*count), NULL ));
}


/***********************************************************************
 *           GetProcessHeap   (kernelbase.@)
 */
HANDLE WINAPI kernelbase_GetProcessHeap(void)
{
    return NtCurrentTeb()->Peb->ProcessHeap;
}


/*********************************************************************
 *           GetProcessId   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH GetProcessId( HANDLE process )
{
    PROCESS_BASIC_INFORMATION pbi;

    if (!set_ntstatus( NtQueryInformationProcess( process, ProcessBasicInformation,
                                                  &pbi, sizeof(pbi), NULL )))
        return 0;
    return pbi.UniqueProcessId;
}


/**********************************************************************
 *           GetProcessMitigationPolicy   (kernelbase.@)
 */
BOOL WINAPI /* DECLSPEC_HOTPATCH */ GetProcessMitigationPolicy( HANDLE process, PROCESS_MITIGATION_POLICY policy,
                                                          void *buffer, SIZE_T length )
{
    FIXME( "(%p, %u, %p, %lu): stub\n", process, policy, buffer, length );
    return TRUE;
}


/***********************************************************************
 *           GetProcessPriorityBoost   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetProcessPriorityBoost( HANDLE process, PBOOL disable )
{
    FIXME( "(%p,%p): semi-stub\n", process, disable );
    *disable = FALSE;  /* report that no boost is present */
    return TRUE;
}


/***********************************************************************
 *           GetProcessShutdownParameters   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetProcessShutdownParameters( LPDWORD level, LPDWORD flags )
{
    *level = shutdown_priority;
    *flags = shutdown_flags;
    return TRUE;
}


/*********************************************************************
 *           GetProcessTimes   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetProcessTimes( HANDLE process, FILETIME *create, FILETIME *exit,
                                               FILETIME *kernel, FILETIME *user )
{
    KERNEL_USER_TIMES time;

    if (!set_ntstatus( NtQueryInformationProcess( process, ProcessTimes, &time, sizeof(time), NULL )))
        return FALSE;

    create->dwLowDateTime  = time.CreateTime.u.LowPart;
    create->dwHighDateTime = time.CreateTime.u.HighPart;
    exit->dwLowDateTime    = time.ExitTime.u.LowPart;
    exit->dwHighDateTime   = time.ExitTime.u.HighPart;
    kernel->dwLowDateTime  = time.KernelTime.u.LowPart;
    kernel->dwHighDateTime = time.KernelTime.u.HighPart;
    user->dwLowDateTime    = time.UserTime.u.LowPart;
    user->dwHighDateTime   = time.UserTime.u.HighPart;
    return TRUE;
}


/***********************************************************************
 *           GetProcessVersion   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH GetProcessVersion( DWORD pid )
{
    SECTION_IMAGE_INFORMATION info;
    NTSTATUS status;
    HANDLE process;

    if (pid && pid != GetCurrentProcessId())
    {
        if (!(process = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid ))) return 0;
        status = NtQueryInformationProcess( process, ProcessImageInformation, &info, sizeof(info), NULL );
        CloseHandle( process );
    }
    else status = NtQueryInformationProcess( GetCurrentProcess(), ProcessImageInformation,
                                             &info, sizeof(info), NULL );

    if (!set_ntstatus( status )) return 0;
    return MAKELONG( info.SubsystemVersionLow, info.SubsystemVersionHigh );
}


/***********************************************************************
 *           GetProcessWorkingSetSizeEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetProcessWorkingSetSizeEx( HANDLE process, SIZE_T *minset,
                                                          SIZE_T *maxset, DWORD *flags)
{
    FIXME( "(%p,%p,%p,%p): stub\n", process, minset, maxset, flags );
    /* 32 MB working set size */
    if (minset) *minset = 32*1024*1024;
    if (maxset) *maxset = 32*1024*1024;
    if (flags) *flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;
    return TRUE;
}


/******************************************************************************
 *           IsProcessInJob   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH IsProcessInJob( HANDLE process, HANDLE job, BOOL *result )
{
    NTSTATUS status = NtIsProcessInJob( process, job );

    switch (status)
    {
    case STATUS_PROCESS_IN_JOB:
        *result = TRUE;
        return TRUE;
    case STATUS_PROCESS_NOT_IN_JOB:
        *result = FALSE;
        return TRUE;
    default:
        return set_ntstatus( status );
    }
}


/***********************************************************************
 *           IsProcessorFeaturePresent   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH IsProcessorFeaturePresent ( DWORD feature )
{
    return RtlIsProcessorFeaturePresent( feature );
}


/**********************************************************************
 *           IsWow64Process2   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH IsWow64Process2( HANDLE process, USHORT *machine, USHORT *native_machine )
{
    BOOL wow64;
    SYSTEM_INFO si;

    TRACE( "(%p,%p,%p)\n", process, machine, native_machine );

    if (!IsWow64Process( process, &wow64 ))
        return FALSE;

    if (wow64)
    {
        GetNativeSystemInfo( &si );

        if (process != GetCurrentProcess())
        {
#if defined(__i386__) || defined(__x86_64__)
            *machine = IMAGE_FILE_MACHINE_I386;
#else
            FIXME("not implemented for other process\n");
            *machine = IMAGE_FILE_MACHINE_UNKNOWN;
#endif
        }
        else
        {
            IMAGE_NT_HEADERS *nt;
            nt = RtlImageNtHeader( NtCurrentTeb()->Peb->ImageBaseAddress );
            *machine = nt->FileHeader.Machine;
        }
    }
    else
    {
#ifdef _WIN64
        GetSystemInfo( &si );
#else
        GetNativeSystemInfo( &si );
#endif
        *machine = IMAGE_FILE_MACHINE_UNKNOWN;
    }

    switch (si.u.s.wProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_INTEL:
        *native_machine = IMAGE_FILE_MACHINE_I386;
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        *native_machine = IMAGE_FILE_MACHINE_ARM;
        break;
    case PROCESSOR_ARCHITECTURE_AMD64:
        *native_machine = IMAGE_FILE_MACHINE_AMD64;
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        *native_machine = IMAGE_FILE_MACHINE_ARM64;
        break;
    default:
        FIXME("unknown architecture %u\n", si.u.s.wProcessorArchitecture);
        *native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        break;
    }

    return TRUE;
}


/**********************************************************************
 *           IsWow64Process   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH IsWow64Process( HANDLE process, PBOOL wow64 )
{
    ULONG_PTR pbi;
    NTSTATUS status;

    status = NtQueryInformationProcess( process, ProcessWow64Information, &pbi, sizeof(pbi), NULL );
    if (!status) *wow64 = !!pbi;
    return set_ntstatus( status );
}


/*********************************************************************
 *           OpenProcess   (kernelbase.@)
 */
HANDLE WINAPI DECLSPEC_HOTPATCH OpenProcess( DWORD access, BOOL inherit, DWORD id )
{
    HANDLE handle;
    OBJECT_ATTRIBUTES attr;
    CLIENT_ID cid;

    if (GetVersion() & 0x80000000) access = PROCESS_ALL_ACCESS;

    attr.Length = sizeof(OBJECT_ATTRIBUTES);
    attr.RootDirectory = 0;
    attr.Attributes = inherit ? OBJ_INHERIT : 0;
    attr.ObjectName = NULL;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;

    /* PROTON HACK:
     * On Windows, the Steam client puts its process ID into the registry
     * at:
     *
     *   [HKCU\Software\Valve\Steam\ActiveProcess]
     *   PID=dword:00000008
     *
     * Games get that pid from the registry and then query it with
     * OpenProcess to ensure Steam is running. Since we aren't running the
     * Windows Steam in Wine, instead we hack this magic number into the
     * registry and then substitute the game's process itself in its place
     * so it can query a valid process.
     */
    if (id == 0xfffe) id = GetCurrentProcessId();

    cid.UniqueProcess = ULongToHandle(id);
    cid.UniqueThread  = 0;

    if (!set_ntstatus( NtOpenProcess( &handle, access, &attr, &cid ))) return NULL;
    return handle;
}


/***********************************************************************
 *           ProcessIdToSessionId   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH ProcessIdToSessionId( DWORD procid, DWORD *sessionid )
{
    if (procid != GetCurrentProcessId()) FIXME( "Unsupported for other process %x\n", procid );
    *sessionid = NtCurrentTeb()->Peb->SessionId;
    return TRUE;
}


/***********************************************************************
 *           QueryProcessCycleTime   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH QueryProcessCycleTime( HANDLE process, ULONG64 *cycle )
{
    static int once;
    if (!once++) FIXME( "(%p,%p): stub!\n", process, cycle );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}


/***********************************************************************
 *           SetErrorMode   (kernelbase.@)
 */
UINT WINAPI DECLSPEC_HOTPATCH SetErrorMode( UINT mode )
{
    UINT old = GetErrorMode();

    NtSetInformationProcess( GetCurrentProcess(), ProcessDefaultHardErrorMode,
                             &mode, sizeof(mode) );
    return old;
}


/*************************************************************************
 *           SetHandleCount   (kernelbase.@)
 */
UINT WINAPI DECLSPEC_HOTPATCH SetHandleCount( UINT count )
{
    return count;
}


/*********************************************************************
 *           SetHandleInformation   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetHandleInformation( HANDLE handle, DWORD mask, DWORD flags )
{
    OBJECT_DATA_INFORMATION info;

    /* if not setting both fields, retrieve current value first */
    if ((mask & (HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE)) !=
        (HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE))
    {
        if (!set_ntstatus( NtQueryObject( handle, ObjectDataInformation, &info, sizeof(info), NULL )))
            return FALSE;
    }
    if (mask & HANDLE_FLAG_INHERIT)
        info.InheritHandle = (flags & HANDLE_FLAG_INHERIT) != 0;
    if (mask & HANDLE_FLAG_PROTECT_FROM_CLOSE)
        info.ProtectFromClose = (flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0;

    return set_ntstatus( NtSetInformationObject( handle, ObjectDataInformation, &info, sizeof(info) ));
}


/***********************************************************************
 *           SetPriorityClass   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetPriorityClass( HANDLE process, DWORD class )
{
    PROCESS_PRIORITY_CLASS ppc;

    ppc.Foreground = FALSE;
    switch (class)
    {
    case IDLE_PRIORITY_CLASS:         ppc.PriorityClass = PROCESS_PRIOCLASS_IDLE; break;
    case BELOW_NORMAL_PRIORITY_CLASS: ppc.PriorityClass = PROCESS_PRIOCLASS_BELOW_NORMAL; break;
    case NORMAL_PRIORITY_CLASS:       ppc.PriorityClass = PROCESS_PRIOCLASS_NORMAL; break;
    case ABOVE_NORMAL_PRIORITY_CLASS: ppc.PriorityClass = PROCESS_PRIOCLASS_ABOVE_NORMAL; break;
    case HIGH_PRIORITY_CLASS:         ppc.PriorityClass = PROCESS_PRIOCLASS_HIGH; break;
    case REALTIME_PRIORITY_CLASS:     ppc.PriorityClass = PROCESS_PRIOCLASS_REALTIME; break;
    default:
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }
    return set_ntstatus( NtSetInformationProcess( process, ProcessPriorityClass, &ppc, sizeof(ppc) ));
}


/***********************************************************************
 *           SetProcessAffinityUpdateMode   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetProcessAffinityUpdateMode( HANDLE process, DWORD flags )
{
    FIXME( "(%p,0x%08x): stub\n", process, flags );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}


/**********************************************************************
 *           SetProcessMitigationPolicy   (kernelbase.@)
 */
BOOL WINAPI /* DECLSPEC_HOTPATCH */ SetProcessMitigationPolicy( PROCESS_MITIGATION_POLICY policy,
                                                          void *buffer, SIZE_T length )
{
    FIXME( "(%d, %p, %lu): stub\n", policy, buffer, length );
    return TRUE;
}


/***********************************************************************
 *           SetProcessPriorityBoost   (kernelbase.@)
 */
BOOL WINAPI /* DECLSPEC_HOTPATCH */ SetProcessPriorityBoost( HANDLE process, BOOL disable )
{
    FIXME( "(%p,%d): stub\n", process, disable );
    return TRUE;
}


/***********************************************************************
 *           SetProcessShutdownParameters   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetProcessShutdownParameters( DWORD level, DWORD flags )
{
    FIXME( "(%08x, %08x): partial stub.\n", level, flags );
    shutdown_flags = flags;
    shutdown_priority = level;
    return TRUE;
}


/***********************************************************************
 *           SetProcessWorkingSetSizeEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetProcessWorkingSetSizeEx( HANDLE process, SIZE_T minset,
                                                          SIZE_T maxset, DWORD flags )
{
    return TRUE;
}


/******************************************************************************
 *           TerminateProcess   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH TerminateProcess( HANDLE handle, DWORD exit_code )
{
    if (!handle)
    {
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }
    return set_ntstatus( NtTerminateProcess( handle, exit_code ));
}


/***********************************************************************
 * Process startup information
 ***********************************************************************/


static STARTUPINFOW startup_infoW;
static char *command_lineA;
static WCHAR *command_lineW;

/******************************************************************
 *		init_startup_info
 */
void init_startup_info( RTL_USER_PROCESS_PARAMETERS *params )
{
    ANSI_STRING ansi;

    startup_infoW.cb              = sizeof(startup_infoW);
    startup_infoW.lpReserved      = NULL;
    startup_infoW.lpDesktop       = params->Desktop.Buffer;
    startup_infoW.lpTitle         = params->WindowTitle.Buffer;
    startup_infoW.dwX             = params->dwX;
    startup_infoW.dwY             = params->dwY;
    startup_infoW.dwXSize         = params->dwXSize;
    startup_infoW.dwYSize         = params->dwYSize;
    startup_infoW.dwXCountChars   = params->dwXCountChars;
    startup_infoW.dwYCountChars   = params->dwYCountChars;
    startup_infoW.dwFillAttribute = params->dwFillAttribute;
    startup_infoW.dwFlags         = params->dwFlags;
    startup_infoW.wShowWindow     = params->wShowWindow;
    startup_infoW.cbReserved2     = params->RuntimeInfo.MaximumLength;
    startup_infoW.lpReserved2     = params->RuntimeInfo.MaximumLength ? (void *)params->RuntimeInfo.Buffer : NULL;
    startup_infoW.hStdInput       = params->hStdInput ? params->hStdInput : INVALID_HANDLE_VALUE;
    startup_infoW.hStdOutput      = params->hStdOutput ? params->hStdOutput : INVALID_HANDLE_VALUE;
    startup_infoW.hStdError       = params->hStdError ? params->hStdError : INVALID_HANDLE_VALUE;

    command_lineW = params->CommandLine.Buffer;
    if (!RtlUnicodeStringToAnsiString( &ansi, &params->CommandLine, TRUE )) command_lineA = ansi.Buffer;
}


/**********************************************************************
 *           BaseFlushAppcompatCache   (kernelbase.@)
 */
BOOL WINAPI BaseFlushAppcompatCache(void)
{
    FIXME( "stub\n" );
    SetLastError( ERROR_CALL_NOT_IMPLEMENTED );
    return FALSE;
}


/***********************************************************************
 *           GetCommandLineA   (kernelbase.@)
 */
LPSTR WINAPI DECLSPEC_HOTPATCH GetCommandLineA(void)
{
    return command_lineA;
}


/***********************************************************************
 *           GetCommandLineW   (kernelbase.@)
 */
LPWSTR WINAPI DECLSPEC_HOTPATCH GetCommandLineW(void)
{
    return NtCurrentTeb()->Peb->ProcessParameters->CommandLine.Buffer;
}


/***********************************************************************
 *           GetStartupInfoW    (kernelbase.@)
 */
void WINAPI DECLSPEC_HOTPATCH GetStartupInfoW( STARTUPINFOW *info )
{
    *info = startup_infoW;
}


/***********************************************************************
 *           GetStdHandle    (kernelbase.@)
 */
HANDLE WINAPI DECLSPEC_HOTPATCH GetStdHandle( DWORD std_handle )
{
    switch (std_handle)
    {
    case STD_INPUT_HANDLE:  return NtCurrentTeb()->Peb->ProcessParameters->hStdInput;
    case STD_OUTPUT_HANDLE: return NtCurrentTeb()->Peb->ProcessParameters->hStdOutput;
    case STD_ERROR_HANDLE:  return NtCurrentTeb()->Peb->ProcessParameters->hStdError;
    }
    SetLastError( ERROR_INVALID_HANDLE );
    return INVALID_HANDLE_VALUE;
}


/***********************************************************************
 *           SetStdHandle    (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetStdHandle( DWORD std_handle, HANDLE handle )
{
    switch (std_handle)
    {
    case STD_INPUT_HANDLE:  NtCurrentTeb()->Peb->ProcessParameters->hStdInput = handle;  return TRUE;
    case STD_OUTPUT_HANDLE: NtCurrentTeb()->Peb->ProcessParameters->hStdOutput = handle; return TRUE;
    case STD_ERROR_HANDLE:  NtCurrentTeb()->Peb->ProcessParameters->hStdError = handle;  return TRUE;
    }
    SetLastError( ERROR_INVALID_HANDLE );
    return FALSE;
}


/***********************************************************************
 *           SetStdHandleEx    (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetStdHandleEx( DWORD std_handle, HANDLE handle, HANDLE *prev )
{
    HANDLE *ptr;

    switch (std_handle)
    {
    case STD_INPUT_HANDLE:  ptr = &NtCurrentTeb()->Peb->ProcessParameters->hStdInput;  break;
    case STD_OUTPUT_HANDLE: ptr = &NtCurrentTeb()->Peb->ProcessParameters->hStdOutput; break;
    case STD_ERROR_HANDLE:  ptr = &NtCurrentTeb()->Peb->ProcessParameters->hStdError;  break;
    default:
        SetLastError( ERROR_INVALID_HANDLE );
        return FALSE;
    }
    if (prev) *prev = *ptr;
    *ptr = handle;
    return TRUE;
}


/***********************************************************************
 * Process environment
 ***********************************************************************/


static inline SIZE_T get_env_length( const WCHAR *env )
{
    const WCHAR *end = env;
    while (*end) end += lstrlenW(end) + 1;
    return end + 1 - env;
}

/***********************************************************************
 *           ExpandEnvironmentStringsA   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH ExpandEnvironmentStringsA( LPCSTR src, LPSTR dst, DWORD count )
{
    UNICODE_STRING us_src;
    PWSTR dstW = NULL;
    DWORD ret;

    RtlCreateUnicodeStringFromAsciiz( &us_src, src );
    if (count)
    {
        if (!(dstW = HeapAlloc(GetProcessHeap(), 0, count * sizeof(WCHAR)))) return 0;
        ret = ExpandEnvironmentStringsW( us_src.Buffer, dstW, count);
        if (ret) WideCharToMultiByte( CP_ACP, 0, dstW, ret, dst, count, NULL, NULL );
    }
    else ret = ExpandEnvironmentStringsW( us_src.Buffer, NULL, 0 );

    RtlFreeUnicodeString( &us_src );
    HeapFree( GetProcessHeap(), 0, dstW );
    return ret;
}


/***********************************************************************
 *           ExpandEnvironmentStringsW   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH ExpandEnvironmentStringsW( LPCWSTR src, LPWSTR dst, DWORD len )
{
    UNICODE_STRING us_src, us_dst;
    NTSTATUS status;
    DWORD res;

    TRACE( "(%s %p %u)\n", debugstr_w(src), dst, len );

    RtlInitUnicodeString( &us_src, src );

    /* make sure we don't overflow the maximum UNICODE_STRING size */
    len = min( len, UNICODE_STRING_MAX_CHARS );

    us_dst.Length = 0;
    us_dst.MaximumLength = len * sizeof(WCHAR);
    us_dst.Buffer = dst;

    res = 0;
    status = RtlExpandEnvironmentStrings_U( NULL, &us_src, &us_dst, &res );
    res /= sizeof(WCHAR);
    if (!set_ntstatus( status ))
    {
        if (status != STATUS_BUFFER_TOO_SMALL) return 0;
        if (len && dst) dst[len - 1] = 0;
    }
    return res;
}


/***********************************************************************
 *           GetEnvironmentStrings    (kernelbase.@)
 *           GetEnvironmentStringsA   (kernelbase.@)
 */
LPSTR WINAPI DECLSPEC_HOTPATCH GetEnvironmentStringsA(void)
{
    LPWSTR env;
    LPSTR ret;
    SIZE_T lenA, lenW;

    RtlAcquirePebLock();
    env = NtCurrentTeb()->Peb->ProcessParameters->Environment;
    lenW = get_env_length( env );
    lenA = WideCharToMultiByte( CP_ACP, 0, env, lenW, NULL, 0, NULL, NULL );
    if ((ret = HeapAlloc( GetProcessHeap(), 0, lenA )))
        WideCharToMultiByte( CP_ACP, 0, env, lenW, ret, lenA, NULL, NULL );
    RtlReleasePebLock();
    return ret;
}


/***********************************************************************
 *           GetEnvironmentStringsW   (kernelbase.@)
 */
LPWSTR WINAPI DECLSPEC_HOTPATCH GetEnvironmentStringsW(void)
{
    LPWSTR ret;
    SIZE_T len;

    RtlAcquirePebLock();
    len = get_env_length( NtCurrentTeb()->Peb->ProcessParameters->Environment ) * sizeof(WCHAR);
    if ((ret = HeapAlloc( GetProcessHeap(), 0, len )))
        memcpy( ret, NtCurrentTeb()->Peb->ProcessParameters->Environment, len );
    RtlReleasePebLock();
    return ret;
}


/***********************************************************************
 *           SetEnvironmentStringsA   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetEnvironmentStringsA( char *env )
{
    WCHAR *envW;
    const char *p = env;
    DWORD len;
    BOOL ret;

    for (p = env; *p; p += strlen( p ) + 1);

    len = MultiByteToWideChar( CP_ACP, 0, env, p - env, NULL, 0 );
    if (!(envW = HeapAlloc( GetProcessHeap(), 0, len )))
    {
        SetLastError( ERROR_NOT_ENOUGH_MEMORY );
        return FALSE;
    }
    MultiByteToWideChar( CP_ACP, 0, env, p - env, envW, len );
    ret = SetEnvironmentStringsW( envW );
    HeapFree( GetProcessHeap(), 0, envW );
    return ret;
}


/***********************************************************************
 *           SetEnvironmentStringsW   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetEnvironmentStringsW( WCHAR *env )
{
    WCHAR *p;
    WCHAR *new_env;
    NTSTATUS status;

    for (p = env; *p; p += wcslen( p ) + 1)
    {
        const WCHAR *eq = wcschr( p, '=' );
        if (!eq || eq == p)
        {
            SetLastError( ERROR_INVALID_PARAMETER );
            return FALSE;
        }
    }

    if ((status = RtlCreateEnvironment( FALSE, &new_env )))
        return set_ntstatus( status );

    for (p = env; *p; p += wcslen( p ) + 1)
    {
        const WCHAR *eq = wcschr( p, '=' );
        UNICODE_STRING var, value;
        var.Buffer = p;
        var.Length = (eq - p) * sizeof(WCHAR);
        RtlInitUnicodeString( &value, eq + 1 );
        if ((status = RtlSetEnvironmentVariable( &new_env, &var, &value )))
        {
            RtlDestroyEnvironment( new_env );
            return set_ntstatus( status );
        }
    }

    RtlSetCurrentEnvironment( new_env, NULL );
    return TRUE;
}


/***********************************************************************
 *           GetEnvironmentVariableA   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH GetEnvironmentVariableA( LPCSTR name, LPSTR value, DWORD size )
{
    UNICODE_STRING us_name, us_value;
    PWSTR valueW;
    NTSTATUS status;
    DWORD len, ret;

    /* limit the size to sane values */
    size = min( size, 32767 );
    if (!(valueW = HeapAlloc( GetProcessHeap(), 0, size * sizeof(WCHAR) ))) return 0;

    RtlCreateUnicodeStringFromAsciiz( &us_name, name );
    us_value.Length = 0;
    us_value.MaximumLength = (size ? size - 1 : 0) * sizeof(WCHAR);
    us_value.Buffer = valueW;

    status = RtlQueryEnvironmentVariable_U( NULL, &us_name, &us_value );
    len = us_value.Length / sizeof(WCHAR);
    if (status == STATUS_BUFFER_TOO_SMALL) ret = len + 1;
    else if (!set_ntstatus( status )) ret = 0;
    else if (!size) ret = len + 1;
    else
    {
        if (len) WideCharToMultiByte( CP_ACP, 0, valueW, len + 1, value, size, NULL, NULL );
        value[len] = 0;
        ret = len;
    }

    RtlFreeUnicodeString( &us_name );
    HeapFree( GetProcessHeap(), 0, valueW );
    return ret;
}


/***********************************************************************
 *           GetEnvironmentVariableW   (kernelbase.@)
 */
DWORD WINAPI DECLSPEC_HOTPATCH GetEnvironmentVariableW( LPCWSTR name, LPWSTR val, DWORD size )
{
    UNICODE_STRING us_name, us_value;
    NTSTATUS status;
    DWORD len;

    TRACE( "(%s %p %u)\n", debugstr_w(name), val, size );

    RtlInitUnicodeString( &us_name, name );
    us_value.Length = 0;
    us_value.MaximumLength = (size ? size - 1 : 0) * sizeof(WCHAR);
    us_value.Buffer = val;

    status = RtlQueryEnvironmentVariable_U( NULL, &us_name, &us_value );
    len = us_value.Length / sizeof(WCHAR);
    if (status == STATUS_BUFFER_TOO_SMALL) return len + 1;
    if (!set_ntstatus( status )) return 0;
    if (!size) return len + 1;
    val[len] = 0;
    return len;
}


/***********************************************************************
 *           FreeEnvironmentStringsA   (kernelbase.@)
 *           FreeEnvironmentStringsW   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH FreeEnvironmentStringsW( LPWSTR ptr )
{
    return HeapFree( GetProcessHeap(), 0, ptr );
}


/***********************************************************************
 *           SetEnvironmentVariableA   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetEnvironmentVariableA( LPCSTR name, LPCSTR value )
{
    UNICODE_STRING us_name, us_value;
    BOOL ret;

    if (!name)
    {
        SetLastError( ERROR_ENVVAR_NOT_FOUND );
        return FALSE;
    }

    RtlCreateUnicodeStringFromAsciiz( &us_name, name );
    if (value)
    {
        RtlCreateUnicodeStringFromAsciiz( &us_value, value );
        ret = SetEnvironmentVariableW( us_name.Buffer, us_value.Buffer );
        RtlFreeUnicodeString( &us_value );
    }
    else ret = SetEnvironmentVariableW( us_name.Buffer, NULL );
    RtlFreeUnicodeString( &us_name );
    return ret;
}


/***********************************************************************
 *           SetEnvironmentVariableW   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH SetEnvironmentVariableW( LPCWSTR name, LPCWSTR value )
{
    UNICODE_STRING us_name, us_value;
    NTSTATUS status;

    TRACE( "(%s %s)\n", debugstr_w(name), debugstr_w(value) );

    if (!name)
    {
        SetLastError( ERROR_ENVVAR_NOT_FOUND );
        return FALSE;
    }

    RtlInitUnicodeString( &us_name, name );
    if (value)
    {
        RtlInitUnicodeString( &us_value, value );
        status = RtlSetEnvironmentVariable( NULL, &us_name, &us_value );
    }
    else status = RtlSetEnvironmentVariable( NULL, &us_name, NULL );

    return set_ntstatus( status );
}


/***********************************************************************
 * Process/thread attribute lists
 ***********************************************************************/

/***********************************************************************
 *           InitializeProcThreadAttributeList   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH InitializeProcThreadAttributeList( struct _PROC_THREAD_ATTRIBUTE_LIST *list,
                                                                 DWORD count, DWORD flags, SIZE_T *size )
{
    SIZE_T needed;
    BOOL ret = FALSE;

    TRACE( "(%p %d %x %p)\n", list, count, flags, size );

    needed = FIELD_OFFSET( struct _PROC_THREAD_ATTRIBUTE_LIST, attrs[count] );
    if (list && *size >= needed)
    {
        list->mask = 0;
        list->size = count;
        list->count = 0;
        list->unk = 0;
        ret = TRUE;
    }
    else SetLastError( ERROR_INSUFFICIENT_BUFFER );

    *size = needed;
    return ret;
}


/***********************************************************************
 *           UpdateProcThreadAttribute   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH UpdateProcThreadAttribute( struct _PROC_THREAD_ATTRIBUTE_LIST *list,
                                                         DWORD flags, DWORD_PTR attr, void *value,
                                                         SIZE_T size, void *prev_ret, SIZE_T *size_ret )
{
    DWORD mask;
    struct proc_thread_attr *entry;

    TRACE( "(%p %x %08lx %p %ld %p %p)\n", list, flags, attr, value, size, prev_ret, size_ret );

    if (list->count >= list->size)
    {
        SetLastError( ERROR_GEN_FAILURE );
        return FALSE;
    }

    switch (attr)
    {
    case PROC_THREAD_ATTRIBUTE_PARENT_PROCESS:
        if (size != sizeof(HANDLE))
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    case PROC_THREAD_ATTRIBUTE_HANDLE_LIST:
        if ((size / sizeof(HANDLE)) * sizeof(HANDLE) != size)
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    case PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR:
        if (size != sizeof(PROCESSOR_NUMBER))
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    case PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY:
       if (size != sizeof(DWORD) && size != sizeof(DWORD64))
       {
           SetLastError( ERROR_BAD_LENGTH );
           return FALSE;
       }
       break;

    case PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY:
        if (size != sizeof(DWORD) && size != sizeof(DWORD64) && size != sizeof(DWORD64) * 2)
        {
            SetLastError( ERROR_BAD_LENGTH );
            return FALSE;
        }
        break;

    default:
        SetLastError( ERROR_NOT_SUPPORTED );
        FIXME( "Unhandled attribute %lu\n", attr & PROC_THREAD_ATTRIBUTE_NUMBER );
        return FALSE;
    }

    mask = 1 << (attr & PROC_THREAD_ATTRIBUTE_NUMBER);
    if (list->mask & mask)
    {
        SetLastError( ERROR_OBJECT_NAME_EXISTS );
        return FALSE;
    }
    list->mask |= mask;

    entry = list->attrs + list->count;
    entry->attr = attr;
    entry->size = size;
    entry->value = value;
    list->count++;
    return TRUE;
}


/***********************************************************************
 *           DeleteProcThreadAttributeList   (kernelbase.@)
 */
void WINAPI DECLSPEC_HOTPATCH DeleteProcThreadAttributeList( struct _PROC_THREAD_ATTRIBUTE_LIST *list )
{
    return;
}
