/*
 *	shell icon cache (SIC)
 *
 * Copyright 1998, 1999 Juergen Schmied
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
#include "wine/port.h"

#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "wingdi.h"
#include "winuser.h"
#include "winreg.h"
#include "wine/debug.h"

#include "shellapi.h"
#include "objbase.h"
#include "pidl.h"
#include "shell32_main.h"
#include "undocshell.h"
#include "shresdef.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

/********************** THE ICON CACHE ********************************/

#define INVALID_INDEX -1

typedef struct
{
	LPWSTR sSourceFile;	/* file (not path!) containing the icon */
	DWORD dwSourceIndex;	/* index within the file, if it is a resource ID it will be negated */
	DWORD dwListIndex;	/* index within the iconlist */
	DWORD dwFlags;		/* GIL_* flags */
	DWORD dwAccessTime;
} SIC_ENTRY, * LPSIC_ENTRY;

static HDPA sic_hdpa;
static INIT_ONCE sic_init_once = INIT_ONCE_STATIC_INIT;
static HIMAGELIST shell_imagelists[SHIL_LAST+1];

static CRITICAL_SECTION SHELL32_SicCS;
static CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &SHELL32_SicCS,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": SHELL32_SicCS") }
};
static CRITICAL_SECTION SHELL32_SicCS = { &critsect_debug, -1, 0, 0, 0, 0 };


static const WCHAR WindowMetrics[] = {'C','o','n','t','r','o','l',' ','P','a','n','e','l','\\','D','e','s','k','t','o','p','\\',
                                      'W','i','n','d','o','w','M','e','t','r','i','c','s',0};
static const WCHAR ShellIconSize[] = {'S','h','e','l','l',' ','I','c','o','n',' ','S','i','z','e',0};

#define SIC_COMPARE_LISTINDEX 1

/*****************************************************************************
 * SIC_CompareEntries
 *
 * NOTES
 *  Callback for DPA_Search
 */
static INT CALLBACK SIC_CompareEntries( LPVOID p1, LPVOID p2, LPARAM lparam)
{
        LPSIC_ENTRY e1 = p1, e2 = p2;

	TRACE("%p %p %8lx\n", p1, p2, lparam);

	/* Icons in the cache are keyed by the name of the file they are
	 * loaded from, their resource index and the fact if they have a shortcut
	 * icon overlay or not. 
	 */

        if (lparam & SIC_COMPARE_LISTINDEX)
            return e1->dwListIndex != e2->dwListIndex;

	if (e1->dwSourceIndex != e2->dwSourceIndex || /* first the faster one */
	    (e1->dwFlags & GIL_FORSHORTCUT) != (e2->dwFlags & GIL_FORSHORTCUT)) 
	  return 1;

	if (strcmpiW(e1->sSourceFile,e2->sSourceFile))
	  return 1;

	return 0;
}

/**************************************************************************************
 *                      SIC_get_location
 *
 * Returns the source file and resource index of an icon with the given imagelist index
 */
HRESULT SIC_get_location( int list_idx, WCHAR *file, DWORD *size, int *res_idx )
{
    SIC_ENTRY seek, *found;
    DWORD needed;
    HRESULT hr = E_INVALIDARG;
    int dpa_idx;

    seek.dwListIndex = list_idx;

    EnterCriticalSection( &SHELL32_SicCS );

    dpa_idx = DPA_Search( sic_hdpa, &seek, 0, SIC_CompareEntries, SIC_COMPARE_LISTINDEX, 0 );
    if (dpa_idx != -1)
    {
        found = DPA_GetPtr( sic_hdpa, dpa_idx );
        needed = (strlenW( found->sSourceFile ) + 1) * sizeof(WCHAR);
        if (needed <= *size)
        {
            memcpy( file, found->sSourceFile, needed );
            *res_idx = found->dwSourceIndex;
            hr = S_OK;
        }
        else
        {
            *size = needed;
            hr = E_NOT_SUFFICIENT_BUFFER;
        }
    }
    LeaveCriticalSection( &SHELL32_SicCS );

    return hr;
}

/* declare SIC_LoadOverlayIcon() */
static int SIC_LoadOverlayIcon(int icon_idx);

/*****************************************************************************
 * SIC_OverlayShortcutImage			[internal]
 *
 * NOTES
 *  Creates a new icon as a copy of the passed-in icon, overlaid with a
 *  shortcut image. 
 */
static HICON SIC_OverlayShortcutImage(HICON SourceIcon, int type)
{
    ICONINFO SourceIconInfo, ShortcutIconInfo, TargetIconInfo;
	HICON ShortcutIcon, TargetIcon;
	BITMAP SourceBitmapInfo, ShortcutBitmapInfo;
	HDC SourceDC = NULL,
	  ShortcutDC = NULL,
	  TargetDC = NULL,
	  ScreenDC = NULL;
	HBITMAP OldSourceBitmap = NULL,
	  OldShortcutBitmap = NULL,
	  OldTargetBitmap = NULL;

	static int s_imgListIdx = -1;

	/* Get information about the source icon and shortcut overlay */
	if (! GetIconInfo(SourceIcon, &SourceIconInfo)
	    || 0 == GetObjectW(SourceIconInfo.hbmColor, sizeof(BITMAP), &SourceBitmapInfo))
	{
	  return NULL;
	}

	/* search for the shortcut icon only once */
	if (s_imgListIdx == -1)
	    s_imgListIdx = SIC_LoadOverlayIcon(- IDI_SHELL_SHORTCUT);
                           /* FIXME should use icon index 29 instead of the
                              resource id, but not all icons are present yet
                              so we can't use icon indices */

    if (s_imgListIdx != -1)
        ShortcutIcon = ImageList_GetIcon(shell_imagelists[type], s_imgListIdx, ILD_TRANSPARENT);
    else
        ShortcutIcon = NULL;

    if (NULL == ShortcutIcon || ! GetIconInfo(ShortcutIcon, &ShortcutIconInfo)
            || 0 == GetObjectW(ShortcutIconInfo.hbmColor, sizeof(BITMAP), &ShortcutBitmapInfo))
    {
        return NULL;
    }

	TargetIconInfo = SourceIconInfo;
	TargetIconInfo.hbmMask = NULL;
	TargetIconInfo.hbmColor = NULL;

	/* Setup the source, shortcut and target masks */
	SourceDC = CreateCompatibleDC(NULL);
	if (NULL == SourceDC) goto fail;
	OldSourceBitmap = SelectObject(SourceDC, SourceIconInfo.hbmMask);
	if (NULL == OldSourceBitmap) goto fail;

	ShortcutDC = CreateCompatibleDC(NULL);
	if (NULL == ShortcutDC) goto fail;
	OldShortcutBitmap = SelectObject(ShortcutDC, ShortcutIconInfo.hbmMask);
	if (NULL == OldShortcutBitmap) goto fail;

	TargetDC = CreateCompatibleDC(NULL);
	if (NULL == TargetDC) goto fail;
	TargetIconInfo.hbmMask = CreateCompatibleBitmap(TargetDC, SourceBitmapInfo.bmWidth,
	                                                SourceBitmapInfo.bmHeight);
	if (NULL == TargetIconInfo.hbmMask) goto fail;
	ScreenDC = GetDC(NULL);
	if (NULL == ScreenDC) goto fail;
	TargetIconInfo.hbmColor = CreateCompatibleBitmap(ScreenDC, SourceBitmapInfo.bmWidth,
	                                                 SourceBitmapInfo.bmHeight);
	ReleaseDC(NULL, ScreenDC);
	if (NULL == TargetIconInfo.hbmColor) goto fail;
	OldTargetBitmap = SelectObject(TargetDC, TargetIconInfo.hbmMask);
	if (NULL == OldTargetBitmap) goto fail;

	/* Create the target mask by ANDing the source and shortcut masks */
	if (! BitBlt(TargetDC, 0, 0, SourceBitmapInfo.bmWidth, SourceBitmapInfo.bmHeight,
	             SourceDC, 0, 0, SRCCOPY) ||
	    ! BitBlt(TargetDC, 0, SourceBitmapInfo.bmHeight - ShortcutBitmapInfo.bmHeight,
	             ShortcutBitmapInfo.bmWidth, ShortcutBitmapInfo.bmHeight,
	             ShortcutDC, 0, 0, SRCAND))
	{
	  goto fail;
	}

	/* Setup the source and target xor bitmap */
	if (NULL == SelectObject(SourceDC, SourceIconInfo.hbmColor) ||
	    NULL == SelectObject(TargetDC, TargetIconInfo.hbmColor))
	{
	  goto fail;
	}

	/* Copy the source xor bitmap to the target and clear out part of it by using
	   the shortcut mask */
	if (! BitBlt(TargetDC, 0, 0, SourceBitmapInfo.bmWidth, SourceBitmapInfo.bmHeight,
	             SourceDC, 0, 0, SRCCOPY) ||
	    ! BitBlt(TargetDC, 0, SourceBitmapInfo.bmHeight - ShortcutBitmapInfo.bmHeight,
	             ShortcutBitmapInfo.bmWidth, ShortcutBitmapInfo.bmHeight,
	             ShortcutDC, 0, 0, SRCAND))
	{
	  goto fail;
	}

	if (NULL == SelectObject(ShortcutDC, ShortcutIconInfo.hbmColor)) goto fail;

	/* Now put in the shortcut xor mask */
	if (! BitBlt(TargetDC, 0, SourceBitmapInfo.bmHeight - ShortcutBitmapInfo.bmHeight,
	             ShortcutBitmapInfo.bmWidth, ShortcutBitmapInfo.bmHeight,
	             ShortcutDC, 0, 0, SRCINVERT))
	{
	  goto fail;
	}

	/* Clean up, we're not goto'ing to 'fail' after this so we can be lazy and not set
	   handles to NULL */
	SelectObject(TargetDC, OldTargetBitmap);
	DeleteObject(TargetDC);
	SelectObject(ShortcutDC, OldShortcutBitmap);
	DeleteObject(ShortcutDC);
	SelectObject(SourceDC, OldSourceBitmap);
	DeleteObject(SourceDC);

	/* Create the icon using the bitmaps prepared earlier */
	TargetIcon = CreateIconIndirect(&TargetIconInfo);

	/* CreateIconIndirect copies the bitmaps, so we can release our bitmaps now */
	DeleteObject(TargetIconInfo.hbmColor);
	DeleteObject(TargetIconInfo.hbmMask);

	return TargetIcon;

fail:
	/* Clean up scratch resources we created */
	if (NULL != OldTargetBitmap) SelectObject(TargetDC, OldTargetBitmap);
	if (NULL != TargetIconInfo.hbmColor) DeleteObject(TargetIconInfo.hbmColor);
	if (NULL != TargetIconInfo.hbmMask) DeleteObject(TargetIconInfo.hbmMask);
	if (NULL != TargetDC) DeleteObject(TargetDC);
	if (NULL != OldShortcutBitmap) SelectObject(ShortcutDC, OldShortcutBitmap);
	if (NULL != ShortcutDC) DeleteObject(ShortcutDC);
	if (NULL != OldSourceBitmap) SelectObject(SourceDC, OldSourceBitmap);
	if (NULL != SourceDC) DeleteObject(SourceDC);

	return NULL;
}

/*****************************************************************************
 * SIC_IconAppend			[internal]
 */
static INT SIC_IconAppend (const WCHAR *sourcefile, INT src_index, HICON *hicons, DWORD flags)
{
    INT ret, index, index1;
    WCHAR path[MAX_PATH];
    SIC_ENTRY *entry;
    unsigned int i;

    TRACE("%s %i %p %#x\n", debugstr_w(sourcefile), src_index, hicons, flags);

    entry = SHAlloc(sizeof(*entry));

    GetFullPathNameW(sourcefile, MAX_PATH, path, NULL);
    entry->sSourceFile = heap_alloc( (strlenW(path)+1)*sizeof(WCHAR) );
    strcpyW( entry->sSourceFile, path );

    entry->dwSourceIndex = src_index;
    entry->dwFlags = flags;

    EnterCriticalSection(&SHELL32_SicCS);

    index = DPA_InsertPtr(sic_hdpa, 0x7fff, entry);
    if ( INVALID_INDEX == index )
    {
        heap_free(entry->sSourceFile);
        SHFree(entry);
        ret = INVALID_INDEX;
    }
    else
    {
        index = -1;
        for (i = 0; i < ARRAY_SIZE(shell_imagelists); i++)
        {
            index1 = ImageList_AddIcon(shell_imagelists[i], hicons[i]);
            if (index != -1 && index1 != index)
                WARN("Imagelists out of sync, list %d.\n", i);
            index = index1;
        }

        entry->dwListIndex = index;
        ret = entry->dwListIndex;
    }

    LeaveCriticalSection(&SHELL32_SicCS);
    return ret;
}

/****************************************************************************
 * SIC_LoadIcon				[internal]
 *
 * NOTES
 *  gets icons by index from the file
 */
static INT SIC_LoadIcon (const WCHAR *sourcefile, INT index, DWORD flags)
{
    HICON hicons[ARRAY_SIZE(shell_imagelists)] = { 0 };
    HICON hshortcuts[ARRAY_SIZE(hicons)] = { 0 };
    SIZE size[ARRAY_SIZE(shell_imagelists)];
    unsigned int i;
    INT ret = -1;

    /* Keep track of the sizes in case any icon fails to get extracted */
    for (i = 0; i < ARRAY_SIZE(hicons); i++)
    {
        ImageList_GetIconSize(shell_imagelists[i], &size[i].cx, &size[i].cy);
        PrivateExtractIconsW(sourcefile, index, size[i].cx, size[i].cy, &hicons[i], 0, 1, 0);
    }

    /* Fill any icon handles that failed to get extracted, by resizing
       another icon handle that succeeded and creating the icon from it.
       Use a dumb O(n^2) algorithm since ARRAY_SIZE(hicons) is small */
    for (i = 0; i < ARRAY_SIZE(hicons); i++)
    {
        unsigned int k, ix, iy;
        BOOL failed = TRUE;
        if (hicons[i]) continue;

        for (k = 0; k < ARRAY_SIZE(hicons); k++)
        {
            if (hicons[k])
            {
                ix = iy = k;
                failed = FALSE;
                break;
            }
        }
        if (failed) goto fail;

        for (k++; k < ARRAY_SIZE(hicons); k++)
        {
            if (!hicons[k]) continue;

            /* Find closest-sized icon, but favor larger icons to resize from */
            if (size[k].cx >= size[i].cx)
                ix = (size[ix].cx < size[i].cx || size[ix].cx > size[k].cx) ? k : ix;
            else
                ix = (size[ix].cx < size[i].cx && size[ix].cx < size[k].cx) ? k : ix;

            if (size[k].cy >= size[i].cy)
                iy = (size[iy].cy < size[i].cy || size[iy].cy > size[k].cy) ? k : iy;
            else
                iy = (size[iy].cy < size[i].cy && size[iy].cy < size[k].cy) ? k : iy;
        }

        /* Use the closest icon in aspect ratio if ix and iy differ */
        if (ix != iy)
        {
            float i_ratio, ix_ratio, iy_ratio;
            i_ratio  = (float)size[i].cx  / (float)size[i].cy;
            ix_ratio = (float)size[ix].cx / (float)size[ix].cy;
            iy_ratio = (float)size[iy].cx / (float)size[iy].cy;
            if (fabsf(ix_ratio - i_ratio) > fabsf(iy_ratio - i_ratio))
                ix = iy;
        }

        /* If this fails, we have to abort to prevent the image lists from
           becoming out of sync and completely screwing the icons up */
        hicons[i] = CopyImage(hicons[ix], IMAGE_ICON, size[i].cx, size[i].cy, 0);
        if (!hicons[i]) goto fail;
    }

    if (flags & GIL_FORSHORTCUT)
    {
        BOOL failed = FALSE;

        for (i = 0; i < ARRAY_SIZE(hshortcuts); i++)
        {
            if (!(hshortcuts[i] = SIC_OverlayShortcutImage(hicons[i], i)))
            {
                WARN("Failed to create shortcut overlaid icons.\n");
                failed = TRUE;
            }
        }

        if (failed)
        {
            for (i = 0; i < ARRAY_SIZE(hshortcuts); i++)
                DestroyIcon(hshortcuts[i]);
            flags &= ~GIL_FORSHORTCUT;
        }
        else
        {
            for (i = 0; i < ARRAY_SIZE(hicons); i++)
            {
                DestroyIcon(hicons[i]);
                hicons[i] = hshortcuts[i];
            }
        }
    }

    ret = SIC_IconAppend( sourcefile, index, hicons, flags );

fail:
    for (i = 0; i < ARRAY_SIZE(hicons); i++)
        DestroyIcon(hicons[i]);
    return ret;
}

static int get_shell_icon_size(void)
{
    WCHAR buf[32];
    DWORD value = 32, size = sizeof(buf), type;
    HKEY key;

    if (!RegOpenKeyW( HKEY_CURRENT_USER, WindowMetrics, &key ))
    {
        if (!RegQueryValueExW( key, ShellIconSize, NULL, &type, (BYTE *)buf, &size ) && type == REG_SZ)
        {
            if (size == sizeof(buf)) buf[size / sizeof(WCHAR) - 1] = 0;
            value = atoiW( buf );
        }
        RegCloseKey( key );
    }
    return value;
}

/*****************************************************************************
 * SIC_Initialize			[internal]
 */
static BOOL WINAPI SIC_Initialize( INIT_ONCE *once, void *param, void **context )
{
    HICON hicons[ARRAY_SIZE(shell_imagelists)];
    SIZE sizes[ARRAY_SIZE(shell_imagelists)];
    BOOL failed = FALSE;
    unsigned int i;

    if (!IsProcessDPIAware())
    {
        sizes[SHIL_LARGE].cx = sizes[SHIL_LARGE].cy = get_shell_icon_size();
        sizes[SHIL_SMALL].cx = GetSystemMetrics( SM_CXSMICON );
        sizes[SHIL_SMALL].cy = GetSystemMetrics( SM_CYSMICON );
    }
    else
    {
        sizes[SHIL_LARGE].cx = GetSystemMetrics( SM_CXICON );
        sizes[SHIL_LARGE].cy = GetSystemMetrics( SM_CYICON );
        sizes[SHIL_SMALL].cx = sizes[SHIL_LARGE].cx / 2;
        sizes[SHIL_SMALL].cy = sizes[SHIL_LARGE].cy / 2;
    }

    sizes[SHIL_EXTRALARGE].cx = (GetSystemMetrics( SM_CXICON ) * 3) / 2;
    sizes[SHIL_EXTRALARGE].cy = (GetSystemMetrics( SM_CYICON ) * 3) / 2;
    sizes[SHIL_SYSSMALL].cx = GetSystemMetrics( SM_CXSMICON );
    sizes[SHIL_SYSSMALL].cy = GetSystemMetrics( SM_CYSMICON );
    sizes[SHIL_JUMBO].cx = sizes[SHIL_JUMBO].cy = 256;

    TRACE("large %dx%d small %dx%d\n", sizes[SHIL_LARGE].cx, sizes[SHIL_LARGE].cy, sizes[SHIL_SMALL].cx, sizes[SHIL_SMALL].cy);

    sic_hdpa = DPA_Create(16);
    if (!sic_hdpa)
        return(FALSE);

    for (i = 0; i < ARRAY_SIZE(shell_imagelists); i++)
    {
        shell_imagelists[i] = ImageList_Create(sizes[i].cx, sizes[i].cy, ILC_COLOR32 | ILC_MASK, 0, 0x20);
        ImageList_SetBkColor(shell_imagelists[i], CLR_NONE);

        /* Load the generic file icon, which is used as the default if an icon isn't found. */
        if (!(hicons[i] = LoadImageA(shell32_hInstance, MAKEINTRESOURCEA(IDI_SHELL_FILE),
            IMAGE_ICON, sizes[i].cx, sizes[i].cy, LR_SHARED)))
        {
            failed = TRUE;
        }
    }

    if (failed)
    {
        FIXME("Failed to load IDI_SHELL_FILE icon!\n");
        return FALSE;
    }

    SIC_IconAppend(swShell32Name, IDI_SHELL_FILE - 1, hicons, 0);
    SIC_IconAppend(swShell32Name, -IDI_SHELL_FILE, hicons, 0);

    TRACE("small list=%p, large list=%p\n", shell_imagelists[SHIL_SMALL], shell_imagelists[SHIL_LARGE]);

    return TRUE;
}

/*************************************************************************
 * SIC_Destroy
 *
 * frees the cache
 */
static INT CALLBACK sic_free( LPVOID ptr, LPVOID lparam )
{
	heap_free(((LPSIC_ENTRY)ptr)->sSourceFile);
	SHFree(ptr);
	return TRUE;
}

void SIC_Destroy(void)
{
    unsigned int i;

    TRACE("\n");

    EnterCriticalSection(&SHELL32_SicCS);

    if (sic_hdpa) DPA_DestroyCallback(sic_hdpa, sic_free, NULL );

    for (i = 0; i < ARRAY_SIZE(shell_imagelists); i++)
    {
        if (shell_imagelists[i])
            ImageList_Destroy(shell_imagelists[i]);
    }

    LeaveCriticalSection(&SHELL32_SicCS);
    DeleteCriticalSection(&SHELL32_SicCS);
}

/*****************************************************************************
 * SIC_GetIconIndex			[internal]
 *
 * Parameters
 *	sSourceFile	[IN]	filename of file containing the icon
 *	index		[IN]	index/resID (negated) in this file
 *
 * NOTES
 *  look in the cache for a proper icon. if not available the icon is taken
 *  from the file and cached
 */
INT SIC_GetIconIndex (LPCWSTR sSourceFile, INT dwSourceIndex, DWORD dwFlags )
{
	SIC_ENTRY sice;
	INT ret, index = INVALID_INDEX;
	WCHAR path[MAX_PATH];

	TRACE("%s %i\n", debugstr_w(sSourceFile), dwSourceIndex);

	GetFullPathNameW(sSourceFile, MAX_PATH, path, NULL);
	sice.sSourceFile = path;
	sice.dwSourceIndex = dwSourceIndex;
	sice.dwFlags = dwFlags;

        InitOnceExecuteOnce( &sic_init_once, SIC_Initialize, NULL, NULL );

	EnterCriticalSection(&SHELL32_SicCS);

	if (NULL != DPA_GetPtr (sic_hdpa, 0))
	{
	  /* search linear from position 0*/
	  index = DPA_Search (sic_hdpa, &sice, 0, SIC_CompareEntries, 0, 0);
	}

	if ( INVALID_INDEX == index )
	{
          ret = SIC_LoadIcon (sSourceFile, dwSourceIndex, dwFlags);
	}
	else
	{
	  TRACE("-- found\n");
	  ret = ((LPSIC_ENTRY)DPA_GetPtr(sic_hdpa, index))->dwListIndex;
	}

	LeaveCriticalSection(&SHELL32_SicCS);
	return ret;
}

/*****************************************************************************
 * SIC_LoadOverlayIcon			[internal]
 *
 * Load a shell overlay icon and return its icon cache index.
 */
static int SIC_LoadOverlayIcon(int icon_idx)
{
	WCHAR buffer[1024], wszIdx[8];
	HKEY hKeyShellIcons;
	LPCWSTR iconPath;
	int iconIdx;

	static const WCHAR wszShellIcons[] = {
	    'S','o','f','t','w','a','r','e','\\','M','i','c','r','o','s','o','f','t','\\',
	    'W','i','n','d','o','w','s','\\','C','u','r','r','e','n','t','V','e','r','s','i','o','n','\\',
	    'E','x','p','l','o','r','e','r','\\','S','h','e','l','l',' ','I','c','o','n','s',0
	}; 
	static const WCHAR wszNumFmt[] = {'%','d',0};

	iconPath = swShell32Name;	/* default: load icon from shell32.dll */
	iconIdx = icon_idx;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wszShellIcons, 0, KEY_READ, &hKeyShellIcons) == ERROR_SUCCESS)
	{
	    DWORD count = sizeof(buffer);

	    sprintfW(wszIdx, wszNumFmt, icon_idx);

	    /* read icon path and index */
	    if (RegQueryValueExW(hKeyShellIcons, wszIdx, NULL, NULL, (LPBYTE)buffer, &count) == ERROR_SUCCESS)
	    {
		LPWSTR p = strchrW(buffer, ',');

		if (!p)
		{
		    ERR("Icon index in %s/%s corrupted, no comma.\n", debugstr_w(wszShellIcons),debugstr_w(wszIdx));
		    RegCloseKey(hKeyShellIcons);
		    return -1;
		}
		*p++ = 0;
		iconPath = buffer;
		iconIdx = atoiW(p);
	    }

	    RegCloseKey(hKeyShellIcons);
	}

        InitOnceExecuteOnce( &sic_init_once, SIC_Initialize, NULL, NULL );

	return SIC_LoadIcon(iconPath, iconIdx, 0);
}

/*************************************************************************
 * Shell_GetImageLists			[SHELL32.71]
 *
 * PARAMETERS
 *  imglist[1|2] [OUT] pointer which receives imagelist handles
 *
 */
BOOL WINAPI Shell_GetImageLists(HIMAGELIST *large_list, HIMAGELIST *small_list)
{
    TRACE("(%p, %p)\n", large_list, small_list);

    InitOnceExecuteOnce( &sic_init_once, SIC_Initialize, NULL, NULL );
    if (large_list) *large_list = shell_imagelists[SHIL_LARGE];
    if (small_list) *small_list = shell_imagelists[SHIL_SMALL];
    return TRUE;
}

/*************************************************************************
 * PidlToSicIndex			[INTERNAL]
 *
 * PARAMETERS
 *	sh	[IN]	IShellFolder
 *	pidl	[IN]
 *	bBigIcon [IN]
 *	uFlags	[IN]	GIL_*
 *	pIndex	[OUT]	index within the SIC
 *
 */
BOOL PidlToSicIndex (
	IShellFolder * sh,
	LPCITEMIDLIST pidl,
	BOOL bBigIcon,
	UINT uFlags,
	int * pIndex)
{
	IExtractIconW	*ei;
	WCHAR		szIconFile[MAX_PATH];	/* file containing the icon */
	INT		iSourceIndex;		/* index or resID(negated) in this file */
	BOOL		ret = FALSE;
	UINT		dwFlags = 0;
	int		iShortcutDefaultIndex = INVALID_INDEX;

	TRACE("sf=%p pidl=%p %s\n", sh, pidl, bBigIcon?"Big":"Small");

        InitOnceExecuteOnce( &sic_init_once, SIC_Initialize, NULL, NULL );

	if (SUCCEEDED (IShellFolder_GetUIObjectOf(sh, 0, 1, &pidl, &IID_IExtractIconW, 0, (void **)&ei)))
	{
	  if (SUCCEEDED(IExtractIconW_GetIconLocation(ei, uFlags, szIconFile, MAX_PATH, &iSourceIndex, &dwFlags)))
	  {
	    *pIndex = SIC_GetIconIndex(szIconFile, iSourceIndex, uFlags);
	    ret = TRUE;
	  }
	  IExtractIconW_Release(ei);
	}

	if (INVALID_INDEX == *pIndex)	/* default icon when failed */
	{
	  if (0 == (uFlags & GIL_FORSHORTCUT))
	  {
	    *pIndex = 0;
	  }
	  else
	  {
	    if (INVALID_INDEX == iShortcutDefaultIndex)
	    {
	      iShortcutDefaultIndex = SIC_LoadIcon(swShell32Name, 0, GIL_FORSHORTCUT);
	    }
	    *pIndex = (INVALID_INDEX != iShortcutDefaultIndex ? iShortcutDefaultIndex : 0);
	  }
	}

	return ret;

}

/*************************************************************************
 * SHMapPIDLToSystemImageListIndex	[SHELL32.77]
 *
 * PARAMETERS
 *	sh	[IN]		pointer to an instance of IShellFolder
 *	pidl	[IN]
 *	pIndex	[OUT][OPTIONAL]	SIC index for big icon
 *
 */
int WINAPI SHMapPIDLToSystemImageListIndex(
	IShellFolder *sh,
	LPCITEMIDLIST pidl,
	int *pIndex)
{
	int Index;
	UINT uGilFlags = 0;

	TRACE("(SF=%p,pidl=%p,%p)\n",sh,pidl,pIndex);
	pdump(pidl);

	if (SHELL_IsShortcut(pidl))
	    uGilFlags |= GIL_FORSHORTCUT;

	if (pIndex)
	    if (!PidlToSicIndex ( sh, pidl, 1, uGilFlags, pIndex))
	        *pIndex = -1;

	if (!PidlToSicIndex ( sh, pidl, 0, uGilFlags, &Index))
	    return -1;

	return Index;
}

/*************************************************************************
 * SHMapIDListToImageListIndexAsync  [SHELL32.148]
 */
HRESULT WINAPI SHMapIDListToImageListIndexAsync(IUnknown *pts, IShellFolder *psf,
                                                LPCITEMIDLIST pidl, UINT flags,
                                                void *pfn, void *pvData, void *pvHint,
                                                int *piIndex, int *piIndexSel)
{
    FIXME("(%p, %p, %p, 0x%08x, %p, %p, %p, %p, %p)\n",
            pts, psf, pidl, flags, pfn, pvData, pvHint, piIndex, piIndexSel);
    return E_FAIL;
}

/*************************************************************************
 * Shell_GetCachedImageIndex		[SHELL32.72]
 *
 */
static INT Shell_GetCachedImageIndexA(LPCSTR szPath, INT nIndex, BOOL bSimulateDoc)
{
	INT ret, len;
	LPWSTR szTemp;

	WARN("(%s,%08x,%08x) semi-stub.\n",debugstr_a(szPath), nIndex, bSimulateDoc);

	len = MultiByteToWideChar( CP_ACP, 0, szPath, -1, NULL, 0 );
	szTemp = heap_alloc( len * sizeof(WCHAR) );
	MultiByteToWideChar( CP_ACP, 0, szPath, -1, szTemp, len );

	ret = SIC_GetIconIndex( szTemp, nIndex, 0 );

	heap_free( szTemp );

	return ret;
}

static INT Shell_GetCachedImageIndexW(LPCWSTR szPath, INT nIndex, BOOL bSimulateDoc)
{
	WARN("(%s,%08x,%08x) semi-stub.\n",debugstr_w(szPath), nIndex, bSimulateDoc);

	return SIC_GetIconIndex(szPath, nIndex, 0);
}

INT WINAPI Shell_GetCachedImageIndexAW(LPCVOID szPath, INT nIndex, BOOL bSimulateDoc)
{	if( SHELL_OsIsUnicode())
	  return Shell_GetCachedImageIndexW(szPath, nIndex, bSimulateDoc);
	return Shell_GetCachedImageIndexA(szPath, nIndex, bSimulateDoc);
}

/*************************************************************************
 * ExtractIconExW			[SHELL32.@]
 * RETURNS
 *  0 no icon found
 *  -1 file is not valid
 *  or number of icons extracted
 */
UINT WINAPI ExtractIconExW(LPCWSTR lpszFile, INT nIconIndex, HICON * phiconLarge, HICON * phiconSmall, UINT nIcons)
{
	TRACE("%s %i %p %p %i\n", debugstr_w(lpszFile), nIconIndex, phiconLarge, phiconSmall, nIcons);

	return PrivateExtractIconExW(lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
}

/*************************************************************************
 * ExtractIconExA			[SHELL32.@]
 */
UINT WINAPI ExtractIconExA(LPCSTR lpszFile, INT nIconIndex, HICON * phiconLarge, HICON * phiconSmall, UINT nIcons)
{
    UINT ret = 0;
    INT len = MultiByteToWideChar(CP_ACP, 0, lpszFile, -1, NULL, 0);
    LPWSTR lpwstrFile = heap_alloc( len * sizeof(WCHAR));

    TRACE("%s %i %p %p %i\n", lpszFile, nIconIndex, phiconLarge, phiconSmall, nIcons);

    if (lpwstrFile)
    {
        MultiByteToWideChar(CP_ACP, 0, lpszFile, -1, lpwstrFile, len);
        ret = ExtractIconExW(lpwstrFile, nIconIndex, phiconLarge, phiconSmall, nIcons);
        heap_free(lpwstrFile);
    }
    return ret;
}

/*************************************************************************
 *				ExtractAssociatedIconA (SHELL32.@)
 *
 * Return icon for given file (either from file itself or from associated
 * executable) and patch parameters if needed.
 */
HICON WINAPI ExtractAssociatedIconA(HINSTANCE hInst, LPSTR lpIconPath, LPWORD lpiIcon)
{	
    HICON hIcon = NULL;
    INT len = MultiByteToWideChar(CP_ACP, 0, lpIconPath, -1, NULL, 0);
    /* Note that we need to allocate MAX_PATH, since we are supposed to fill
     * the correct executable if there is no icon in lpIconPath directly.
     * lpIconPath itself is supposed to be large enough, so make sure lpIconPathW
     * is large enough too. Yes, I am puking too.
     */
    LPWSTR lpIconPathW = heap_alloc(MAX_PATH * sizeof(WCHAR));

    TRACE("%p %s %p\n", hInst, debugstr_a(lpIconPath), lpiIcon);

    if (lpIconPathW)
    {
        MultiByteToWideChar(CP_ACP, 0, lpIconPath, -1, lpIconPathW, len);
        hIcon = ExtractAssociatedIconW(hInst, lpIconPathW, lpiIcon);
        WideCharToMultiByte(CP_ACP, 0, lpIconPathW, -1, lpIconPath, MAX_PATH , NULL, NULL);
        heap_free(lpIconPathW);
    }
    return hIcon;
}

/*************************************************************************
 *				ExtractAssociatedIconW (SHELL32.@)
 *
 * Return icon for given file (either from file itself or from associated
 * executable) and patch parameters if needed.
 */
HICON WINAPI ExtractAssociatedIconW(HINSTANCE hInst, LPWSTR lpIconPath, LPWORD lpiIcon)
{
    HICON hIcon = NULL;
    WORD wDummyIcon = 0;

    TRACE("%p %s %p\n", hInst, debugstr_w(lpIconPath), lpiIcon);

    if(lpiIcon == NULL)
        lpiIcon = &wDummyIcon;

    hIcon = ExtractIconW(hInst, lpIconPath, *lpiIcon);

    if( hIcon < (HICON)2 )
    { if( hIcon == (HICON)1 ) /* no icons found in given file */
      { WCHAR tempPath[MAX_PATH];
        HINSTANCE uRet = FindExecutableW(lpIconPath,NULL,tempPath);

        if( uRet > (HINSTANCE)32 && tempPath[0] )
        { lstrcpyW(lpIconPath,tempPath);
          hIcon = ExtractIconW(hInst, lpIconPath, *lpiIcon);
          if( hIcon > (HICON)2 )
            return hIcon;
        }
      }

      if( hIcon == (HICON)1 )
        *lpiIcon = 2;   /* MS-DOS icon - we found .exe but no icons in it */
      else
        *lpiIcon = 6;   /* generic icon - found nothing */

      if (GetModuleFileNameW(hInst, lpIconPath, MAX_PATH))
        hIcon = LoadIconW(hInst, MAKEINTRESOURCEW(*lpiIcon));
    }
    return hIcon;
}

/*************************************************************************
 *				ExtractAssociatedIconExW (SHELL32.@)
 *
 * Return icon for given file (either from file itself or from associated
 * executable) and patch parameters if needed.
 */
HICON WINAPI ExtractAssociatedIconExW(HINSTANCE hInst, LPWSTR lpIconPath, LPWORD lpiIconIdx, LPWORD lpiIconId)
{
  FIXME("%p %s %p %p): stub\n", hInst, debugstr_w(lpIconPath), lpiIconIdx, lpiIconId);
  return 0;
}

/*************************************************************************
 *				ExtractAssociatedIconExA (SHELL32.@)
 *
 * Return icon for given file (either from file itself or from associated
 * executable) and patch parameters if needed.
 */
HICON WINAPI ExtractAssociatedIconExA(HINSTANCE hInst, LPSTR lpIconPath, LPWORD lpiIconIdx, LPWORD lpiIconId)
{
  HICON ret;
  INT len = MultiByteToWideChar( CP_ACP, 0, lpIconPath, -1, NULL, 0 );
  LPWSTR lpwstrFile = heap_alloc( len * sizeof(WCHAR) );

  TRACE("%p %s %p %p)\n", hInst, lpIconPath, lpiIconIdx, lpiIconId);

  MultiByteToWideChar( CP_ACP, 0, lpIconPath, -1, lpwstrFile, len );
  ret = ExtractAssociatedIconExW(hInst, lpwstrFile, lpiIconIdx, lpiIconId);
  heap_free(lpwstrFile);
  return ret;
}


/****************************************************************************
 * SHDefExtractIconW		[SHELL32.@]
 */
HRESULT WINAPI SHDefExtractIconW(LPCWSTR pszIconFile, int iIndex, UINT uFlags,
                                 HICON* phiconLarge, HICON* phiconSmall, UINT nIconSize)
{
	UINT ret;
	HICON hIcons[2];
	WARN("%s %d 0x%08x %p %p %d, semi-stub\n", debugstr_w(pszIconFile), iIndex, uFlags, phiconLarge, phiconSmall, nIconSize);

	ret = PrivateExtractIconsW(pszIconFile, iIndex, nIconSize, nIconSize, hIcons, NULL, 2, LR_DEFAULTCOLOR);
	/* FIXME: deal with uFlags parameter which contains GIL_ flags */
	if (ret == 0xFFFFFFFF)
	  return E_FAIL;
	if (ret > 0) {
	  if (phiconLarge)
	    *phiconLarge = hIcons[0];
	  else
	    DestroyIcon(hIcons[0]);
	  if (phiconSmall)
	    *phiconSmall = hIcons[1];
	  else
	    DestroyIcon(hIcons[1]);
	  return S_OK;
	}
	return S_FALSE;
}

/****************************************************************************
 * SHDefExtractIconA		[SHELL32.@]
 */
HRESULT WINAPI SHDefExtractIconA(LPCSTR pszIconFile, int iIndex, UINT uFlags,
                                 HICON* phiconLarge, HICON* phiconSmall, UINT nIconSize)
{
  HRESULT ret;
  INT len = MultiByteToWideChar(CP_ACP, 0, pszIconFile, -1, NULL, 0);
  LPWSTR lpwstrFile = heap_alloc(len * sizeof(WCHAR));

  TRACE("%s %d 0x%08x %p %p %d\n", pszIconFile, iIndex, uFlags, phiconLarge, phiconSmall, nIconSize);

  MultiByteToWideChar(CP_ACP, 0, pszIconFile, -1, lpwstrFile, len);
  ret = SHDefExtractIconW(lpwstrFile, iIndex, uFlags, phiconLarge, phiconSmall, nIconSize);
  heap_free(lpwstrFile);
  return ret;
}


/****************************************************************************
 * SHGetIconOverlayIndexA    [SHELL32.@]
 *
 * Returns the index of the overlay icon in the system image list.
 */
INT WINAPI SHGetIconOverlayIndexA(LPCSTR pszIconPath, INT iIconIndex)
{
  FIXME("%s, %d\n", debugstr_a(pszIconPath), iIconIndex);

  return -1;
}

/****************************************************************************
 * SHGetIconOverlayIndexW    [SHELL32.@]
 *
 * Returns the index of the overlay icon in the system image list.
 */
INT WINAPI SHGetIconOverlayIndexW(LPCWSTR pszIconPath, INT iIconIndex)
{
  FIXME("%s, %d\n", debugstr_w(pszIconPath), iIconIndex);

  return -1;
}

/****************************************************************************
 * For SHGetStockIconInfo
 */
typedef struct {
    SHSTOCKICONID id;
    DWORD iconid;
} SI_ENTRY;

static const SI_ENTRY si_table[] =
{
    [0]   = { SIID_DOCNOASSOC, IDI_SHELL_FILE},
    [1]   = { SIID_DOCASSOC, IDI_SHELL_DOCUMENT},
    [2]   = { SIID_APPLICATION, IDI_SHELL_WINDOW},
    [3]   = { SIID_FOLDER, IDI_SHELL_FOLDER},
    [4]   = { SIID_FOLDEROPEN, IDI_SHELL_FOLDER_OPEN},
    [5]   = { SIID_DRIVE525, 0},
    [6]   = { SIID_DRIVE35, 0},
    [7]   = { SIID_DRIVERREMOVE, 0},
    [8]   = { SIID_DRIVERFIXED, IDI_SHELL_DRIVE},
    [9]   = { SIID_DRIVERNET, IDI_SHELL_NETDRIVE},
    [10]  = { SIID_DRIVERNETDISABLE, IDI_SHELL_NETDRIVE2},
    [11]  = { SIID_DRIVERCD, IDI_SHELL_OPTICAL_DRIVE},
    [12]  = { SIID_DRIVERRAM, IDI_SHELL_RAMDISK},
    [13]  = { SIID_WORLD, 0},
    /* Missing: 14 */
    [15]  = { SIID_SERVER, 0},
    [16]  = { SIID_PRINTER, IDI_SHELL_PRINT},
    [17]  = { SIID_MYNETWORK, 0},
    /* Missing: 18 - 21 */
    [22]  = { SIID_FIND, 0},
    [23]  = { SIID_HELP, IDI_SHELL_HELP},
    /* Missing: 24 - 27 */
    [28]  = {SIID_SHARE, 0},
    [29]  = {SIID_LINK, 0},
    [30]  = {SIID_SLOWFILE, 0},
    [31]  = {SIID_RECYCLER, IDI_SHELL_TRASH_FOLDER},
    [32]  = {SIID_RECYCLERFULL, IDI_SHELL_FULL_RECYCLE_BIN},
    /* Missing: 33 - 39 */
    [40]  = {SIID_MEDIACDAUDIO, 0},
    /* Missing: 41 - 46 */
    [47]  = {SIID_LOCK, IDI_SHELL_PASSWORDS},
    /* Missing: 48 */
    [49]  = {SIID_AUTOLIST, 0},
    [50]  = {SIID_PRINTERNET, 0},
    [51]  = {SIID_SERVERSHARE, 0},
    [52]  = {SIID_PRINTERFAX, 0},
    [53]  = {SIID_PRINTERFAXNET, 0},
    [54]  = {SIID_PRINTERFILE, 0},
    [55]  = {SIID_STACK, 0},
    [56]  = {SIID_MEDIASVCD, 0},
    [57]  = {SIID_STUFFEDFOLDER, 0},
    [58]  = {SIID_DRIVEUNKNOWN, 0},
    [59]  = {SIID_DRIVEDVD, 0},
    [60]  = {SIID_MEDIADVD, 0},
    [61]  = {SIID_MEDIADVDRAM, 0},
    [62]  = {SIID_MEDIADVDRW, 0},
    [63]  = {SIID_MEDIADVDR, 0},
    [64]  = {SIID_MEDIADVDROM, 0},
    [65]  = {SIID_MEDIACDAUDIOPLUS, 0},
    [66]  = {SIID_MEDIACDRW, 0},
    [67]  = {SIID_MEDIACDR, 0},
    [68]  = {SIID_MEDIACDBURN, 0},
    [69]  = {SIID_MEDIABLANKCD, 0},
    [70]  = {SIID_MEDIACDROM, 0},
    [71]  = {SIID_AUDIOFILES, IDI_SHELL_AUDIO_FILE},
    [72]  = {SIID_IMAGEFILES, IDI_SHELL_IMAGE_FILE},
    [73]  = {SIID_VIDEOFILES, IDI_SHELL_VIDEO_FILE},
    [74]  = {SIID_MIXEDFILES, 0},
    [75]  = {SIID_FOLDERBACK, 0},
    [76]  = {SIID_FOLDERFRONT, 0},
    [77]  = {SIID_SHIELD, 0},
    [78]  = {SIID_WARNING, 0},
    [79]  = {SIID_INFO, 0},
    [80]  = {SIID_ERROR, 0},
    [81]  = {SIID_KEY, 0},
    [82]  = {SIID_SOFTWARE, 0},
    [83]  = {SIID_RENAME, IDI_SHELL_RENAME},
    [84]  = {SIID_DELETE, IDI_SHELL_CONFIRM_DELETE},
    [85]  = {SIID_MEDIAAUDIODVD, 0},
    [86]  = {SIID_MEDIAMOVIEDVD, 0},
    [87]  = {SIID_MEDIAENHANCEDCD, 0},
    [88]  = {SIID_MEDIAENHANCEDDVD, 0},
    [89]  = {SIID_MEDIAHDDVD, 0},
    [90]  = {SIID_MEDIABLUERAY, 0},
    [91]  = {SIID_MEDIAVCD, 0},
    [92]  = {SIID_MEDIADVDPLUSR, 0},
    [93]  = {SIID_MEDIADVDPLUSRW, 0},
    [94]  = {SIID_DESKTOPPC, IDI_SHELL_MY_COMPUTER},
    [95]  = {SIID_MOBILEPC, 0},
    [96]  = {SIID_USERS, IDI_SHELL_USERS},
    [97]  = {SIID_MEDIASMARTMEDIA, 0},
    [98]  = {SIID_MEDIACOMPACTFLASH, 0},
    [99]  = {SIID_DEVICECELLPHONE, 0},
    [100] = {SIID_DEVICECAMERA, 0},
    [101] = {SIID_DEVICEVIDEOCAMERA, 0},
    [102] = {SIID_DEVICEAUDIOPLAYER, 0},
    [103] = {SIID_NETWORKCONNECT, 0},
    [104] = {SIID_INTERNET, IDI_SHELL_WEB_BROWSER},
    [105] = {SIID_ZIPFILE, 0},
    [106] = {SIID_SETTINGS, IDI_SHELL_SETTINGS},
    /* Missing: 107 - 131 */
    [132] = {SIID_DRIVEHDDVD, 0},
    [133] = {SIID_DRIVEBD, 0},
    [134] = {SIID_MEDIAHDDVDROM, 0},
    [135] = {SIID_MEDIAHDDVDR, 0},
    [136] = {SIID_MEDIAHDDVDRAM, 0},
    [137] = {SIID_MEDIABDROM, 0},
    [138] = {SIID_MEDIABDR, 0},
    [139] = {SIID_MEDIABDRE, 0},
    [140] = {SIID_CLUSTEREDDRIVE, 0}
    /* Missing: 141 - 180  and  SIID_MAX_ICONS = 181*/
 };

/****************************************************************************
 * SHGetStockIconInfo [SHELL32.@]
 *
 * Receive information for builtin icons
 *
 * PARAMS
 *  id      [I]  selected icon-id to get information for
 *  flags   [I]  selects the information to receive
 *  sii     [IO] SHSTOCKICONINFO structure to fill
 *
 * RETURNS
 *  Success: S_OK
 *  Failure: A HRESULT failure code
 *
 */
HRESULT WINAPI SHGetStockIconInfo(SHSTOCKICONID id, UINT flags, SHSTOCKICONINFO *sii)
{
    static const WCHAR shell32dllW[] = {'s','h','e','l','l','3','2','.','d','l','l',0};
    static const WCHAR slashW[] = {'\\',0};
    HMODULE hmod;

    TRACE("(%d, 0x%x, %p)\n", id, flags, sii);
    if ((id < 0) || (id >= SIID_MAX_ICONS) || !sii || (sii->cbSize != sizeof(SHSTOCKICONINFO))) {
        return E_INVALIDARG;
    }

    GetSystemDirectoryW(sii->szPath, MAX_PATH);
    lstrcatW(sii->szPath, slashW);
    lstrcatW(sii->szPath, shell32dllW);

    sii->hIcon = NULL;
    sii->iSysImageIndex = -1;

    /* this is not how windows does it, on windows picked mostly from imageres.dll !*/
    if (si_table[id].iconid)
        sii->iIcon = sii->iSysImageIndex - si_table[id].id;
    else
    {
        FIXME("Couldn`t find SIID %d, returning default values (IDI_SHELL_FILE)\n", id);
        sii->iIcon = sii->iSysImageIndex - IDI_SHELL_FILE;
    }

    if (flags & SHGSI_ICON)
    {
        flags &= ~SHGSI_ICON;

        hmod = GetModuleHandleW(shell32dllW);
        if (hmod)
        {
            if (si_table[id].iconid)
                sii->hIcon = LoadIconW(hmod, MAKEINTRESOURCEW(si_table[id].iconid));
            else
                sii->hIcon = LoadIconW(hmod, MAKEINTRESOURCEW(IDI_SHELL_FILE));
        }

        if (!sii->hIcon)
        {
            ERR("failed to get an icon handle\n");
            return E_INVALIDARG;
        }
    }

    if (flags)
        FIXME("flags 0x%x not implemented\n", flags);

    TRACE("%3d: returning %s (%d)\n", id, debugstr_w(sii->szPath), sii->iIcon);

    return S_OK;
}

/*************************************************************************
 *              SHGetImageList (SHELL32.727)
 *
 * Returns a copy of a shell image list.
 *
 * NOTES
 *   Windows XP features 4 sizes of image list, and Vista 5. Wine currently
 *   only supports the traditional small and large image lists, so requests
 *   for the others will currently fail.
 */
HRESULT WINAPI SHGetImageList(int iImageList, REFIID riid, void **ppv)
{
    TRACE("(%d, %s, %p)\n", iImageList, debugstr_guid(riid), ppv);

    if (iImageList < 0 || iImageList > SHIL_LAST)
        return E_FAIL;

    InitOnceExecuteOnce( &sic_init_once, SIC_Initialize, NULL, NULL );
    return HIMAGELIST_QueryInterface(shell_imagelists[iImageList], riid, ppv);
}
