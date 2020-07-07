/*
 * Windows and DOS version functions
 *
 * Copyright 1997 Marcus Meissner
 * Copyright 1998 Patrik Stridvall
 * Copyright 1998, 2003 Andreas Mohr
 * Copyright 1997, 2003 Alexandre Julliard
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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "wine/debug.h"
#include "ntdll_misc.h"
#include "ddk/wdm.h"

WINE_DEFAULT_DEBUG_CHANNEL(ver);

typedef enum
{
    WIN20,   /* Windows 2.0 */
    WIN30,   /* Windows 3.0 */
    WIN31,   /* Windows 3.1 */
    WIN95,   /* Windows 95 */
    WIN98,   /* Windows 98 */
    WINME,   /* Windows Me */
    NT351,   /* Windows NT 3.51 */
    NT40,    /* Windows NT 4.0 */
    NT2K,    /* Windows 2000 */
    WINXP,   /* Windows XP */
    WINXP64, /* Windows XP 64-bit */
    WIN2K3,  /* Windows 2003 */
    WINVISTA,/* Windows Vista */
    WIN2K8,  /* Windows 2008 */
    WIN2K8R2,/* Windows 2008 R2 */
    WIN7,    /* Windows 7 */
    WIN8,    /* Windows 8 */
    WIN81,   /* Windows 8.1 */
    WIN10,   /* Windows 10 */
    NB_WINDOWS_VERSIONS
} WINDOWS_VERSION;

/* FIXME: compare values below with original and fix.
 * An *excellent* win9x version page (ALL versions !)
 * can be found at www.mdgx.com/ver.htm */
static const RTL_OSVERSIONINFOEXW VersionData[NB_WINDOWS_VERSIONS] =
{
    /* WIN20 FIXME: verify values */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 2, 0, 0, VER_PLATFORM_WIN32s,
        {'W','i','n','3','2','s',' ','1','.','3',0},
        0, 0, 0, 0, 0
    },
    /* WIN30 FIXME: verify values */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 3, 0, 0, VER_PLATFORM_WIN32s,
        {'W','i','n','3','2','s',' ','1','.','3',0},
        0, 0, 0, 0, 0
    },
    /* WIN31 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 3, 10, 0, VER_PLATFORM_WIN32s,
        {'W','i','n','3','2','s',' ','1','.','3',0},
        0, 0, 0, 0, 0
    },
    /* WIN95 */
    {
        /* Win95:       4, 0, 0x40003B6, ""
         * Win95sp1:    4, 0, 0x40003B6, " A " (according to doc)
         * Win95osr2:   4, 0, 0x4000457, " B " (according to doc)
         * Win95osr2.1: 4, 3, 0x40304BC, " B " (according to doc)
         * Win95osr2.5: 4, 3, 0x40304BE, " C " (according to doc)
         * Win95a/b can be discerned via regkey SubVersionNumber
         */
        sizeof(RTL_OSVERSIONINFOEXW), 4, 0, 0x40003B6, VER_PLATFORM_WIN32_WINDOWS,
        {0},
        0, 0, 0, 0, 0
    },
    /* WIN98 (second edition) */
    {
        /* Win98:   4, 10, 0x40A07CE, " "   4.10.1998
         * Win98SE: 4, 10, 0x40A08AE, " A " 4.10.2222
         */
        sizeof(RTL_OSVERSIONINFOEXW), 4, 10, 0x40A08AE, VER_PLATFORM_WIN32_WINDOWS,
        {' ','A',' ',0},
        0, 0, 0, 0, 0
    },
    /* WINME */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 4, 90, 0x45A0BB8, VER_PLATFORM_WIN32_WINDOWS,
        {' ',0},
        0, 0, 0, 0, 0
    },
    /* NT351 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 3, 51, 0x421, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','5',0},
        5, 0, 0, VER_NT_WORKSTATION, 0
    },
    /* NT40 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 4, 0, 0x565, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','6','a',0},
        6, 0, 0, VER_NT_WORKSTATION, 0
    },
    /* NT2K */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 0, 0x893, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','4',0},
        4, 0, 0, VER_NT_WORKSTATION, 30 /* FIXME: Great, a reserved field with a value! */
    },
    /* WINXP */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 1, 0xA28, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','3',0},
        3, 0, VER_SUITE_SINGLEUSERTS, VER_NT_WORKSTATION, 30 /* FIXME: Great, a reserved field with a value! */
    },
    /* WINXP64 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 2, 0xECE, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','2',0},
        2, 0, VER_SUITE_SINGLEUSERTS, VER_NT_WORKSTATION, 0
    },
    /* WIN2K3 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 5, 2, 0xECE, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','2',0},
        2, 0, VER_SUITE_SINGLEUSERTS, VER_NT_SERVER, 0
    },
    /* WINVISTA */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 0, 0x1772, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','2',0},
        2, 0, VER_SUITE_SINGLEUSERTS, VER_NT_WORKSTATION, 0
    },
    /* WIN2K8 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 0, 0x1772, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','2',0},
        2, 0, VER_SUITE_SINGLEUSERTS, VER_NT_SERVER, 0
    },
    /* WIN7 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 1, 0x1DB1, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','1',0},
        1, 0, VER_SUITE_SINGLEUSERTS, VER_NT_WORKSTATION, 0
    },
    /* WIN2K8R2 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 1, 0x1DB1, VER_PLATFORM_WIN32_NT,
        {'S','e','r','v','i','c','e',' ','P','a','c','k',' ','1',0},
        1, 0, VER_SUITE_SINGLEUSERTS, VER_NT_SERVER, 0
    },
    /* WIN8 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 2, 0x23F0, VER_PLATFORM_WIN32_NT,
        {0}, 0, 0, VER_SUITE_SINGLEUSERTS, VER_NT_WORKSTATION, 0
    },
    /* WIN81 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 6, 3, 0x2580, VER_PLATFORM_WIN32_NT,
        {0}, 0, 0, VER_SUITE_SINGLEUSERTS, VER_NT_WORKSTATION, 0
    },
    /* WIN10 */
    {
        sizeof(RTL_OSVERSIONINFOEXW), 10, 0, 0x4563, VER_PLATFORM_WIN32_NT,
        {0}, 0, 0, VER_SUITE_SINGLEUSERTS, VER_NT_WORKSTATION, 0
    },

};

static const struct { WCHAR name[12]; WINDOWS_VERSION ver; } version_names[] =
{
    { {'w','i','n','2','0',0}, WIN20 },
    { {'w','i','n','3','0',0}, WIN30 },
    { {'w','i','n','3','1',0}, WIN31 },
    { {'w','i','n','9','5',0}, WIN95 },
    { {'w','i','n','9','8',0}, WIN98 },
    { {'w','i','n','m','e',0}, WINME },
    { {'n','t','3','5','1',0}, NT351 },
    { {'n','t','4','0',0}, NT40 },
    { {'w','i','n','2','0','0','0',0}, NT2K },
    { {'w','i','n','2','k',0}, NT2K },
    { {'n','t','2','k',0}, NT2K },
    { {'n','t','2','0','0','0',0}, NT2K },
    { {'w','i','n','x','p',0}, WINXP },
    { {'w','i','n','x','p','6','4',0}, WINXP64 },
    { {'w','i','n','2','0','0','3',0}, WIN2K3 },
    { {'w','i','n','2','k','3',0}, WIN2K3 },
    { {'v','i','s','t','a',0}, WINVISTA },
    { {'w','i','n','v','i','s','t','a',0}, WINVISTA },
    { {'w','i','n','2','0','0','8',0}, WIN2K8 },
    { {'w','i','n','2','k','8',0}, WIN2K8 },
    { {'w','i','n','2','0','0','8','r','2',0}, WIN2K8R2 },
    { {'w','i','n','2','k','8','r','2',0}, WIN2K8R2 },
    { {'w','i','n','7',0}, WIN7 },
    { {'w','i','n','8',0}, WIN8 },
    { {'w','i','n','8','1',0}, WIN81 },
    { {'w','i','n','1','0',0}, WIN10 },
};


/* initialized to null so that we crash if we try to retrieve the version too early at startup */
static const RTL_OSVERSIONINFOEXW *current_version;


/**********************************************************************
 *         get_nt_registry_version
 *
 * Fetch the version information from the NT-style registry keys.
 */
static BOOL get_nt_registry_version( RTL_OSVERSIONINFOEXW *version )
{
    static const WCHAR version_keyW[] = {'M','a','c','h','i','n','e','\\',
                                         'S','o','f','t','w','a','r','e','\\',
                                         'M','i','c','r','o','s','o','f','t','\\',
                                         'W','i','n','d','o','w','s',' ','N','T','\\',
                                         'C','u','r','r','e','n','t','V','e','r','s','i','o','n',0};
    static const WCHAR service_pack_keyW[] = {'M','a','c','h','i','n','e','\\',
                                              'S','y','s','t','e','m','\\',
                                              'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
                                              'C','o','n','t','r','o','l','\\',
                                              'W','i','n','d','o','w','s',0};
    static const WCHAR product_keyW[] = {'M','a','c','h','i','n','e','\\',
                                         'S','y','s','t','e','m','\\',
                                         'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
                                         'C','o','n','t','r','o','l','\\',
                                         'P','r','o','d','u','c','t','O','p','t','i','o','n','s',0};
    static const WCHAR CurrentBuildNumberW[] = {'C','u','r','r','e','n','t','B','u','i','l','d','N','u','m','b','e','r',0};
    static const WCHAR CSDVersionW[] = {'C','S','D','V','e','r','s','i','o','n',0};
    static const WCHAR CurrentVersionW[] = {'C','u','r','r','e','n','t','V','e','r','s','i','o','n',0};
    static const WCHAR ProductTypeW[] = {'P','r','o','d','u','c','t','T','y','p','e',0};
    static const WCHAR WinNTW[]    = {'W','i','n','N','T',0};
    static const WCHAR ServerNTW[] = {'S','e','r','v','e','r','N','T',0};
    static const WCHAR LanmanNTW[] = {'L','a','n','m','a','n','N','T',0};

    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW, valueW;
    HANDLE hkey, hkey2;
    char tmp[64];
    DWORD count;
    BOOL ret = FALSE;
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)tmp;

    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &nameW;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
    RtlInitUnicodeString( &nameW, version_keyW );

    if (NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr )) return FALSE;

    memset( version, 0, sizeof(*version) );

    RtlInitUnicodeString( &valueW, CurrentVersionW );
    if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
    {
        WCHAR *p, *str = (WCHAR *)info->Data;
        str[info->DataLength / sizeof(WCHAR)] = 0;
        p = wcschr( str, '.' );
        if (p)
        {
            *p++ = 0;
            version->dwMinorVersion = wcstoul( p, NULL, 10 );
        }
        version->dwMajorVersion = wcstoul( str, NULL, 10 );
    }

    if (version->dwMajorVersion)   /* we got the main version, now fetch the other fields */
    {
        ret = TRUE;
        version->dwPlatformId = VER_PLATFORM_WIN32_NT;

        /* get build number */

        RtlInitUnicodeString( &valueW, CurrentBuildNumberW );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
        {
            WCHAR *str = (WCHAR *)info->Data;
            str[info->DataLength / sizeof(WCHAR)] = 0;
            version->dwBuildNumber = wcstoul( str, NULL, 10 );
        }

        /* get version description */

        RtlInitUnicodeString( &valueW, CSDVersionW );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
        {
            DWORD len = min( info->DataLength, sizeof(version->szCSDVersion) - sizeof(WCHAR) );
            memcpy( version->szCSDVersion, info->Data, len );
            version->szCSDVersion[len / sizeof(WCHAR)] = 0;
        }

        /* get service pack version */

        RtlInitUnicodeString( &nameW, service_pack_keyW );
        if (!NtOpenKey( &hkey2, KEY_ALL_ACCESS, &attr ))
        {
            RtlInitUnicodeString( &valueW, CSDVersionW );
            if (!NtQueryValueKey( hkey2, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp), &count ))
            {
                if (info->DataLength >= sizeof(DWORD))
                {
                    DWORD dw = *(DWORD *)info->Data;
                    version->wServicePackMajor = LOWORD(dw) >> 8;
                    version->wServicePackMinor = LOWORD(dw) & 0xff;
                }
            }
            NtClose( hkey2 );
        }

        /* get product type */

        RtlInitUnicodeString( &nameW, product_keyW );
        if (!NtOpenKey( &hkey2, KEY_ALL_ACCESS, &attr ))
        {
            RtlInitUnicodeString( &valueW, ProductTypeW );
            if (!NtQueryValueKey( hkey2, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
            {
                WCHAR *str = (WCHAR *)info->Data;
                str[info->DataLength / sizeof(WCHAR)] = 0;
                if (!wcsicmp( str, WinNTW )) version->wProductType = VER_NT_WORKSTATION;
                else if (!wcsicmp( str, LanmanNTW )) version->wProductType = VER_NT_DOMAIN_CONTROLLER;
                else if (!wcsicmp( str, ServerNTW )) version->wProductType = VER_NT_SERVER;
            }
            NtClose( hkey2 );
        }

        /* FIXME: get wSuiteMask */
    }

    NtClose( hkey );
    return ret;
}


/**********************************************************************
 *         get_win9x_registry_version
 *
 * Fetch the version information from the Win9x-style registry keys.
 */
static BOOL get_win9x_registry_version( RTL_OSVERSIONINFOEXW *version )
{
    static const WCHAR version_keyW[] = {'M','a','c','h','i','n','e','\\',
                                         'S','o','f','t','w','a','r','e','\\',
                                         'M','i','c','r','o','s','o','f','t','\\',
                                         'W','i','n','d','o','w','s','\\',
                                         'C','u','r','r','e','n','t','V','e','r','s','i','o','n',0};
    static const WCHAR VersionNumberW[] = {'V','e','r','s','i','o','n','N','u','m','b','e','r',0};
    static const WCHAR SubVersionNumberW[] = {'S','u','b','V','e','r','s','i','o','n','N','u','m','b','e','r',0};

    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW, valueW;
    HANDLE hkey;
    char tmp[64];
    DWORD count;
    BOOL ret = FALSE;
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)tmp;

    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.ObjectName = &nameW;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
    RtlInitUnicodeString( &nameW, version_keyW );

    if (NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr )) return FALSE;

    memset( version, 0, sizeof(*version) );

    RtlInitUnicodeString( &valueW, VersionNumberW );
    if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
    {
        WCHAR *p, *str = (WCHAR *)info->Data;
        str[info->DataLength / sizeof(WCHAR)] = 0;
        p = wcschr( str, '.' );
        if (p) *p++ = 0;
        version->dwMajorVersion = wcstoul( str, NULL, 10 );
        if (p)
        {
            str = p;
            p = wcschr( str, '.' );
            if (p)
            {
                *p++ = 0;
                version->dwBuildNumber = wcstoul( p, NULL, 10 );
            }
            version->dwMinorVersion = wcstoul( str, NULL, 10 );
        }
        /* build number contains version too on Win9x */
        version->dwBuildNumber |= MAKEWORD( version->dwMinorVersion, version->dwMajorVersion ) << 16;
    }

    if (version->dwMajorVersion)   /* we got the main version, now fetch the other fields */
    {
        ret = TRUE;
        version->dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;

        RtlInitUnicodeString( &valueW, SubVersionNumberW );
        if (!NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp)-1, &count ))
        {
            DWORD len = min( info->DataLength, sizeof(version->szCSDVersion) - sizeof(WCHAR) );
            memcpy( version->szCSDVersion, info->Data, len );
            version->szCSDVersion[len / sizeof(WCHAR)] = 0;
        }
    }

    NtClose( hkey );
    return ret;
}


/**********************************************************************
 *         parse_win_version
 *
 * Parse the contents of the Version key.
 */
static BOOL parse_win_version( HANDLE hkey )
{
    static const WCHAR VersionW[] = {'V','e','r','s','i','o','n',0};

    UNICODE_STRING valueW;
    WCHAR *name, tmp[64];
    KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)tmp;
    DWORD i, count;

    RtlInitUnicodeString( &valueW, VersionW );
    if (NtQueryValueKey( hkey, &valueW, KeyValuePartialInformation, tmp, sizeof(tmp) - sizeof(WCHAR), &count ))
        return FALSE;

    name = (WCHAR *)info->Data;
    name[info->DataLength / sizeof(WCHAR)] = 0;

    for (i = 0; i < ARRAY_SIZE(version_names); i++)
    {
        if (wcscmp( version_names[i].name, name )) continue;
        current_version = &VersionData[version_names[i].ver];
        TRACE( "got win version %s\n", debugstr_w(version_names[i].name) );
        return TRUE;
    }

    ERR( "Invalid Windows version value %s specified in config file.\n", debugstr_w(name) );
    return FALSE;
}


/**********************************************************************
 *         version_init
 */
void version_init(void)
{
    static const WCHAR configW[] = {'S','o','f','t','w','a','r','e','\\','W','i','n','e',0};
    static const WCHAR appdefaultsW[] = {'A','p','p','D','e','f','a','u','l','t','s','\\',0};
    OBJECT_ATTRIBUTES attr;
    UNICODE_STRING nameW;
    HANDLE root, hkey, config_key;
    BOOL got_win_ver = FALSE;
    const WCHAR *p, *appname = NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer;
    WCHAR appversion[MAX_PATH+20];

    current_version = &VersionData[WIN10];

    RtlOpenCurrentUser( KEY_ALL_ACCESS, &root );
    attr.Length = sizeof(attr);
    attr.RootDirectory = root;
    attr.ObjectName = &nameW;
    attr.Attributes = 0;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
    RtlInitUnicodeString( &nameW, configW );

    /* @@ Wine registry key: HKCU\Software\Wine */
    if (NtOpenKey( &config_key, KEY_ALL_ACCESS, &attr )) config_key = 0;
    NtClose( root );
    if (!config_key) goto done;

    /* open AppDefaults\\appname key */

    if ((p = wcsrchr( appname, '/' ))) appname = p + 1;
    if ((p = wcsrchr( appname, '\\' ))) appname = p + 1;

    wcscpy( appversion, appdefaultsW );
    wcscat( appversion, appname );
    RtlInitUnicodeString( &nameW, appversion );
    attr.RootDirectory = config_key;

    /* @@ Wine registry key: HKCU\Software\Wine\AppDefaults\app.exe */
    if (!NtOpenKey( &hkey, KEY_ALL_ACCESS, &attr ))
    {
        TRACE( "getting version from %s\n", debugstr_w(appversion) );
        got_win_ver = parse_win_version( hkey );
        NtClose( hkey );
    }

    if (!got_win_ver)
    {
        TRACE( "getting default version\n" );
        got_win_ver = parse_win_version( config_key );
    }
    NtClose( config_key );

done:
    if (!got_win_ver)
    {
        static RTL_OSVERSIONINFOEXW registry_version;

        TRACE( "getting registry version\n" );
        if (get_nt_registry_version( &registry_version ) ||
            get_win9x_registry_version( &registry_version ))
            current_version = &registry_version;
    }


    NtCurrentTeb()->Peb->OSMajorVersion = current_version->dwMajorVersion;
    NtCurrentTeb()->Peb->OSMinorVersion = current_version->dwMinorVersion;
    NtCurrentTeb()->Peb->OSBuildNumber  = current_version->dwBuildNumber;
    NtCurrentTeb()->Peb->OSPlatformId   = current_version->dwPlatformId;

    TRACE( "got %d.%d platform %d build %x name %s service pack %d.%d product %d\n",
           current_version->dwMajorVersion, current_version->dwMinorVersion,
           current_version->dwPlatformId, current_version->dwBuildNumber,
           debugstr_w(current_version->szCSDVersion),
           current_version->wServicePackMajor, current_version->wServicePackMinor,
           current_version->wProductType );
}

/***********************************************************************
 *           RtlGetProductInfo    (NTDLL.@)
 *
 * Gives info about the current Windows product type, in a format compatible
 * with the given Windows version
 *
 * Returns TRUE if the input is valid, FALSE otherwise
 */
BOOLEAN WINAPI RtlGetProductInfo(DWORD dwOSMajorVersion, DWORD dwOSMinorVersion, DWORD dwSpMajorVersion,
                                 DWORD dwSpMinorVersion, PDWORD pdwReturnedProductType)
{
    TRACE("(%d, %d, %d, %d, %p)\n", dwOSMajorVersion, dwOSMinorVersion,
          dwSpMajorVersion, dwSpMinorVersion, pdwReturnedProductType);

    if (!pdwReturnedProductType)
        return FALSE;

    if (dwOSMajorVersion < 6)
    {
        *pdwReturnedProductType = PRODUCT_UNDEFINED;
        return FALSE;
    }

    if (current_version->wProductType == VER_NT_WORKSTATION)
        *pdwReturnedProductType = PRODUCT_ULTIMATE_N;
    else
        *pdwReturnedProductType = PRODUCT_STANDARD_SERVER;

    return TRUE;
}

/***********************************************************************
 *         RtlGetVersion   (NTDLL.@)
 */
NTSTATUS WINAPI RtlGetVersion( RTL_OSVERSIONINFOEXW *info )
{
    info->dwMajorVersion = current_version->dwMajorVersion;
    info->dwMinorVersion = current_version->dwMinorVersion;
    info->dwBuildNumber  = current_version->dwBuildNumber;
    info->dwPlatformId   = current_version->dwPlatformId;
    wcscpy( info->szCSDVersion, current_version->szCSDVersion );
    if(info->dwOSVersionInfoSize == sizeof(RTL_OSVERSIONINFOEXW))
    {
        info->wServicePackMajor = current_version->wServicePackMajor;
        info->wServicePackMinor = current_version->wServicePackMinor;
        info->wSuiteMask        = current_version->wSuiteMask;
        info->wProductType      = current_version->wProductType;
    }
    return STATUS_SUCCESS;
}


/******************************************************************************
 *  RtlGetNtVersionNumbers   (NTDLL.@)
 *
 * Get the version numbers of the run time library.
 *
 * PARAMS
 *  major [O] Destination for the Major version
 *  minor [O] Destination for the Minor version
 *  build [O] Destination for the Build version
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 * Introduced in Windows XP (NT5.1)
 */
void WINAPI RtlGetNtVersionNumbers( LPDWORD major, LPDWORD minor, LPDWORD build )
{
    if (major) *major = current_version->dwMajorVersion;
    if (minor) *minor = current_version->dwMinorVersion;
    /* FIXME: Does anybody know the real formula? */
    if (build) *build = (0xF0000000 | current_version->dwBuildNumber);
}


/******************************************************************************
 *  RtlGetNtProductType   (NTDLL.@)
 */
BOOLEAN WINAPI RtlGetNtProductType( LPDWORD type )
{
    if (type) *type = current_version->wProductType;
    return TRUE;
}

static inline UCHAR version_update_condition(UCHAR *last_condition, UCHAR condition)
{
    switch (*last_condition)
    {
        case 0:
            *last_condition = condition;
            break;
        case VER_EQUAL:
            if (condition >= VER_EQUAL && condition <= VER_LESS_EQUAL)
            {
                *last_condition = condition;
                return condition;
            }
            break;
        case VER_GREATER:
        case VER_GREATER_EQUAL:
            if (condition >= VER_EQUAL && condition <= VER_GREATER_EQUAL)
                return condition;
            break;
        case VER_LESS:
        case VER_LESS_EQUAL:
            if (condition == VER_EQUAL || (condition >= VER_LESS && condition <= VER_LESS_EQUAL))
                return condition;
            break;
    }
    if (!condition) *last_condition |= 0x10;
    return *last_condition & 0xf;
}

static inline NTSTATUS version_compare_values(ULONG left, ULONG right, UCHAR condition)
{
    switch (condition) {
        case VER_EQUAL:
            if (left != right) return STATUS_REVISION_MISMATCH;
            break;
        case VER_GREATER:
            if (left <= right) return STATUS_REVISION_MISMATCH;
            break;
        case VER_GREATER_EQUAL:
            if (left < right) return STATUS_REVISION_MISMATCH;
            break;
        case VER_LESS:
            if (left >= right) return STATUS_REVISION_MISMATCH;
            break;
        case VER_LESS_EQUAL:
            if (left > right) return STATUS_REVISION_MISMATCH;
            break;
        default:
            return STATUS_REVISION_MISMATCH;
    }
    return STATUS_SUCCESS;
}

/******************************************************************************
 *        RtlVerifyVersionInfo   (NTDLL.@)
 */
NTSTATUS WINAPI RtlVerifyVersionInfo( const RTL_OSVERSIONINFOEXW *info,
                                      DWORD dwTypeMask, DWORDLONG dwlConditionMask )
{
    RTL_OSVERSIONINFOEXW ver;
    NTSTATUS status;

    TRACE("(%p,0x%x,0x%s)\n", info, dwTypeMask, wine_dbgstr_longlong(dwlConditionMask));

    ver.dwOSVersionInfoSize = sizeof(ver);
    if ((status = RtlGetVersion( &ver )) != STATUS_SUCCESS) return status;

    if(!(dwTypeMask && dwlConditionMask)) return STATUS_INVALID_PARAMETER;

    if(dwTypeMask & VER_PRODUCT_TYPE)
    {
        status = version_compare_values(ver.wProductType, info->wProductType, dwlConditionMask >> 7*3 & 0x07);
        if (status != STATUS_SUCCESS)
            return status;
    }
    if(dwTypeMask & VER_SUITENAME)
        switch(dwlConditionMask >> 6*3 & 0x07)
        {
            case VER_AND:
                if((info->wSuiteMask & ver.wSuiteMask) != info->wSuiteMask)
                    return STATUS_REVISION_MISMATCH;
                break;
            case VER_OR:
                if(!(info->wSuiteMask & ver.wSuiteMask) && info->wSuiteMask)
                    return STATUS_REVISION_MISMATCH;
                break;
            default:
                return STATUS_INVALID_PARAMETER;
        }
    if(dwTypeMask & VER_PLATFORMID)
    {
        status = version_compare_values(ver.dwPlatformId, info->dwPlatformId, dwlConditionMask >> 3*3 & 0x07);
        if (status != STATUS_SUCCESS)
            return status;
    }
    if(dwTypeMask & VER_BUILDNUMBER)
    {
        status = version_compare_values(ver.dwBuildNumber, info->dwBuildNumber, dwlConditionMask >> 2*3 & 0x07);
        if (status != STATUS_SUCCESS)
            return status;
    }

    if(dwTypeMask & (VER_MAJORVERSION|VER_MINORVERSION|VER_SERVICEPACKMAJOR|VER_SERVICEPACKMINOR))
    {
        unsigned char condition, last_condition = 0;
        BOOLEAN do_next_check = TRUE;

        if(dwTypeMask & VER_MAJORVERSION)
        {
            condition = version_update_condition(&last_condition, dwlConditionMask >> 1*3 & 0x07);
            status = version_compare_values(ver.dwMajorVersion, info->dwMajorVersion, condition);
            do_next_check = (ver.dwMajorVersion == info->dwMajorVersion) &&
                ((condition >= VER_EQUAL) && (condition <= VER_LESS_EQUAL));
        }
        if((dwTypeMask & VER_MINORVERSION) && do_next_check)
        {
            condition = version_update_condition(&last_condition, dwlConditionMask >> 0*3 & 0x07);
            status = version_compare_values(ver.dwMinorVersion, info->dwMinorVersion, condition);
            do_next_check = (ver.dwMinorVersion == info->dwMinorVersion) &&
                ((condition >= VER_EQUAL) && (condition <= VER_LESS_EQUAL));
        }
        if((dwTypeMask & VER_SERVICEPACKMAJOR) && do_next_check)
        {
            condition = version_update_condition(&last_condition, dwlConditionMask >> 5*3 & 0x07);
            status = version_compare_values(ver.wServicePackMajor, info->wServicePackMajor, condition);
            do_next_check = (ver.wServicePackMajor == info->wServicePackMajor) &&
                ((condition >= VER_EQUAL) && (condition <= VER_LESS_EQUAL));
        }
        if((dwTypeMask & VER_SERVICEPACKMINOR) && do_next_check)
        {
            condition = version_update_condition(&last_condition, dwlConditionMask >> 4*3 & 0x07);
            status = version_compare_values(ver.wServicePackMinor, info->wServicePackMinor, condition);
        }

        if (status != STATUS_SUCCESS)
            return status;
    }

    return STATUS_SUCCESS;
}
