/*
 * Copyright 2015 Michael Müller
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

#define COBJMACROS
#define NONAMELESSUNION

#include <stdarg.h>

#include "winerror.h"
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winreg.h"

#include "winuser.h"
#include "wingdi.h"
#include "shlobj.h"
#include "undocshell.h"

#include "pidl.h"
#include "shell32_main.h"
#include "shlguid.h"
#include "shlwapi.h"
#include "shresdef.h"
#include "shellfolder.h"

#include "wine/heap.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(shell);

typedef struct
{
    IShellExtInit   IShellExtInit_iface;
    IContextMenu3   IContextMenu3_iface;
    IObjectWithSite IObjectWithSite_iface;

    LONG ref;
    IUnknown *site;
    LPITEMIDLIST pidl;
    HICON icon_folder;

    UINT folder_cmd;
} NewMenuImpl;

static inline NewMenuImpl *impl_from_IShellExtInit(IShellExtInit *iface)
{
    return CONTAINING_RECORD(iface, NewMenuImpl, IShellExtInit_iface);
}

static inline NewMenuImpl *impl_from_IContextMenu3(IContextMenu3 *iface)
{
    return CONTAINING_RECORD(iface, NewMenuImpl, IContextMenu3_iface);
}

static inline NewMenuImpl *impl_from_IObjectWithSite(IObjectWithSite *iface)
{
    return CONTAINING_RECORD(iface, NewMenuImpl, IObjectWithSite_iface);
}

static HRESULT WINAPI
NewMenu_ExtInit_QueryInterface(IShellExtInit *iface, REFIID riid, void **ppv)
{
    NewMenuImpl *This = impl_from_IShellExtInit(iface);
    TRACE("(%p)->(%s)\n", This, debugstr_guid(riid));

    *ppv = NULL;

    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IShellExtInit))
    {
        *ppv = &This->IShellExtInit_iface;
    }
    else if (IsEqualIID(riid, &IID_IObjectWithSite))
    {
        *ppv = &This->IObjectWithSite_iface;
    }
    else if (IsEqualIID(riid, &IID_IContextMenu)  ||
             IsEqualIID(riid, &IID_IContextMenu2) ||
             IsEqualIID(riid, &IID_IContextMenu3))
    {
        *ppv = &This->IContextMenu3_iface;
    }

    if (*ppv)
    {
        IUnknown_AddRef((IUnknown *)*ppv);
        TRACE("-- Interface: (%p)->(%p)\n", ppv, *ppv);
        return S_OK;
    }

    ERR("-- Interface: E_NOINTERFACE for %s\n", debugstr_guid(riid));
    return E_NOINTERFACE;
}

static ULONG WINAPI
NewMenu_ExtInit_AddRef(IShellExtInit *iface)
{
    NewMenuImpl *This = impl_from_IShellExtInit(iface);
    ULONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p), refcount=%i\n", iface, ref);

    return ref;
}

static ULONG WINAPI
NewMenu_ExtInit_Release(IShellExtInit *iface)
{
    NewMenuImpl *This = impl_from_IShellExtInit(iface);
    ULONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p), refcount=%i\n", iface, ref);

    if (!ref)
    {
        if (This->site) IUnknown_Release(This->site);
        if (This->pidl) ILFree(This->pidl);
        heap_free(This);
    }

    return ref;
}

static HRESULT WINAPI
NewMenu_ExtInit_Initialize(IShellExtInit *iface, LPCITEMIDLIST pidl, IDataObject *obj, HKEY key)
{
    NewMenuImpl *This = impl_from_IShellExtInit(iface);

    TRACE("(%p)->(%p, %p, %p)\n", This, pidl, obj, key );

    if (!pidl)
        return E_FAIL;

    if (This->pidl) ILFree(This->pidl);
    This->pidl = ILClone(pidl);
    This->icon_folder = LoadImageW(shell32_hInstance, (LPCWSTR)MAKEINTRESOURCE(IDI_SHELL_FOLDER), IMAGE_ICON,
                                   GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED);

    return S_OK;
}

static const IShellExtInitVtbl eivt =
{
    NewMenu_ExtInit_QueryInterface,
    NewMenu_ExtInit_AddRef,
    NewMenu_ExtInit_Release,
    NewMenu_ExtInit_Initialize
};


static HRESULT WINAPI
NewMenu_ObjectWithSite_QueryInterface(IObjectWithSite *iface, REFIID riid, void **ppv)
{
    NewMenuImpl *This = impl_from_IObjectWithSite(iface);
    return NewMenu_ExtInit_QueryInterface(&This->IShellExtInit_iface, riid, ppv);
}

static ULONG WINAPI
NewMenu_ObjectWithSite_AddRef(IObjectWithSite *iface)
{
    NewMenuImpl *This = impl_from_IObjectWithSite(iface);
    return NewMenu_ExtInit_AddRef(&This->IShellExtInit_iface);
}

static ULONG WINAPI
NewMenu_ObjectWithSite_Release(IObjectWithSite *iface)
{
    NewMenuImpl *This = impl_from_IObjectWithSite(iface);
    return NewMenu_ExtInit_Release(&This->IShellExtInit_iface);
}

static HRESULT WINAPI
NewMenu_ObjectWithSite_GetSite(IObjectWithSite *iface, REFIID iid, void **ppv)
{
    NewMenuImpl *This = impl_from_IObjectWithSite(iface);

    TRACE("(%p)->(%s, %p)\n", This, debugstr_guid(iid), ppv);

    if (!This->site)
        return E_FAIL;

    return IUnknown_QueryInterface(This->site, iid, ppv);
}

static HRESULT WINAPI
NewMenu_ObjectWithSite_SetSite(IObjectWithSite *iface, IUnknown *punk)
{
    NewMenuImpl *This = impl_from_IObjectWithSite(iface);

    TRACE("(%p)->(%p)\n", This, punk);

    if (punk)
        IUnknown_AddRef(punk);

    if (This->site)
        IUnknown_Release(This->site);

    This->site = punk;
    return S_OK;
}

static const IObjectWithSiteVtbl owsvt =
{
    NewMenu_ObjectWithSite_QueryInterface,
    NewMenu_ObjectWithSite_AddRef,
    NewMenu_ObjectWithSite_Release,
    NewMenu_ObjectWithSite_SetSite,
    NewMenu_ObjectWithSite_GetSite,
};


static HRESULT WINAPI
NewMenu_ContextMenu3_QueryInterface(IContextMenu3 *iface, REFIID riid, void **ppv)
{
    NewMenuImpl *This = impl_from_IContextMenu3(iface);
    return NewMenu_ExtInit_QueryInterface(&This->IShellExtInit_iface, riid, ppv);
}

static ULONG WINAPI
NewMenu_ContextMenu3_AddRef(IContextMenu3 *iface)
{
    NewMenuImpl *This = impl_from_IContextMenu3(iface);
    return NewMenu_ExtInit_AddRef(&This->IShellExtInit_iface);
}

static ULONG WINAPI
NewMenu_ContextMenu3_Release(IContextMenu3 *iface)
{
    NewMenuImpl *This = impl_from_IContextMenu3(iface);
    return NewMenu_ExtInit_Release(&This->IShellExtInit_iface);
}

static HRESULT WINAPI
NewMenu_ContextMenu3_GetCommandString(IContextMenu3 *iface, UINT_PTR cmd, UINT type,
                                     UINT *reserved, LPSTR name, UINT max_len)
{
    NewMenuImpl *This = impl_from_IContextMenu3(iface);

    FIXME("(%p)->(%lu %u %p %p %u): stub\n", This, cmd, type, reserved, name, max_len);

    return E_NOTIMPL;
}

static HRESULT create_folder(NewMenuImpl *This, IShellView *view)
{
    IFolderView *folder_view = NULL;
    IShellFolder *desktop = NULL;
    IShellFolder *parent = NULL;
    ISFHelper *helper = NULL;
    LPITEMIDLIST pidl = NULL;
    WCHAR nameW[MAX_PATH];
    HRESULT hr;

    if (view)
    {
        hr = IShellView_QueryInterface(view, &IID_IFolderView, (void **)&folder_view);
        if (FAILED(hr)) return hr;

        hr = IFolderView_GetFolder(folder_view, &IID_IShellFolder, (void **)&parent);
        if (FAILED(hr)) goto out;
    }
    else
    {
        hr = SHGetDesktopFolder(&desktop);
        if (FAILED(hr)) goto out;

        hr = IShellFolder_BindToObject(desktop, This->pidl, NULL, &IID_IShellFolder, (void **)&parent);
        if (FAILED(hr)) goto out;
    }

    IShellFolder_QueryInterface(parent, &IID_ISFHelper, (void **)&helper);
    if (FAILED(hr)) goto out;

    hr = ISFHelper_GetUniqueName(helper, nameW, MAX_PATH);
    if (FAILED(hr)) goto out;

    hr = ISFHelper_AddFolder(helper, 0, nameW, &pidl);
    if (FAILED(hr)) goto out;

    if (view)
    {
        IShellView_SelectItem(view, pidl, SVSI_DESELECTOTHERS | SVSI_EDIT |
                              SVSI_ENSUREVISIBLE | SVSI_FOCUSED | SVSI_SELECT);
    }

out:
    if (pidl) SHFree(pidl);
    if (helper) ISFHelper_Release(helper);
    if (parent) IShellFolder_Release(parent);
    if (desktop) IShellFolder_Release(desktop);
    if (folder_view) IFolderView_Release(folder_view);
    return hr;
}

static HRESULT WINAPI
NewMenu_ContextMenu3_InvokeCommand(IContextMenu3 *iface, LPCMINVOKECOMMANDINFO info)
{
    NewMenuImpl *This = impl_from_IContextMenu3(iface);
    IShellBrowser *browser;
    IShellView *view = NULL;
    HRESULT hr = E_FAIL;

    TRACE("(%p)->(%p)\n", This, info);

    /* New Folder */
    if (info->lpVerb == 0)
    {
        if ((browser = (IShellBrowser *)SendMessageA(info->hwnd, CWM_GETISHELLBROWSER, 0, 0)))
        {
            if (FAILED(IShellBrowser_QueryActiveShellView(browser, &view)))
                view = NULL;
        }
        hr = create_folder(This, view);
        if (view) IShellView_Release(view);
    }

    return hr;
}

static UINT insert_new_menu_items(NewMenuImpl *This, HMENU menu, UINT pos, UINT cmd_first, UINT cmd_last)
{
    MENUITEMINFOW item;
    WCHAR buffer[256];

    memset(&item, 0, sizeof(item));
    item.cbSize = sizeof(item);

    if (cmd_first > cmd_last)
        return cmd_first;

    /* FIXME: on windows it is only 'Folder' not 'New Folder' */
    if (!LoadStringW(shell32_hInstance, IDS_NEWFOLDER, buffer, sizeof(buffer) / sizeof(WCHAR)))
        buffer[0] = 0;

    item.fMask      = MIIM_ID | MIIM_BITMAP | MIIM_STRING;
    item.dwTypeData = buffer;
    item.cch        = strlenW(buffer);
    item.wID        = cmd_first;
    item.hbmpItem   = HBMMENU_CALLBACK;
    if (InsertMenuItemW(menu, pos, TRUE, &item))
    {
        This->folder_cmd = cmd_first++;
        pos++;
    }

    return cmd_first;
}

static HRESULT WINAPI
NewMenu_ContextMenu3_QueryContextMenu(IContextMenu3 *iface, HMENU menu, UINT index,
                                      UINT cmd_first, UINT cmd_last, UINT flags)
{
    static WCHAR newW[] = {'N','e','w',0};
    NewMenuImpl *This = impl_from_IContextMenu3(iface);
    MENUITEMINFOW item;
    HMENU submenu;
    UINT id;

    TRACE("(%p)->(%p, %u, %u, %u, %u)\n", This,
          menu, index, cmd_first, cmd_last, flags );

    if (!This->pidl)
        return E_FAIL;

    submenu = CreateMenu();
    if (!submenu) return E_FAIL;

    id = insert_new_menu_items(This, submenu, 0, cmd_first, cmd_last);

    memset(&item, 0, sizeof(item));
    item.cbSize     = sizeof(item);
    item.fMask      = MIIM_TYPE | MIIM_ID | MIIM_STATE | MIIM_SUBMENU;
    item.fType      = MFT_STRING;
    item.wID        = -1;
    item.dwTypeData = newW; /* FIXME: load from resource file */
    item.cch        = strlenW(newW);
    item.fState     = MFS_ENABLED;
    item.hSubMenu   = submenu;

    if (!InsertMenuItemW(menu, index, TRUE, &item))
        return E_FAIL;

    return MAKE_HRESULT(SEVERITY_SUCCESS, 0, id);
}

static HRESULT WINAPI
NewMenu_ContextMenu3_HandleMenuMsg2(IContextMenu3 *iface, UINT uMsg, WPARAM wParam, LPARAM lParam, LRESULT *result)
{
    NewMenuImpl *This = impl_from_IContextMenu3(iface);

    TRACE("(%p)->(%u, %lx, %lx, %p)\n", This, uMsg, wParam, lParam, result);

    switch (uMsg)
    {
        case WM_MEASUREITEM:
        {
            MEASUREITEMSTRUCT *mis = (MEASUREITEMSTRUCT *)lParam;
            if (!mis || mis->CtlType != ODT_MENU)
                break;

            if (This->folder_cmd == mis->itemID)
            {
                mis->itemWidth = GetSystemMetrics(SM_CXSMICON);
                mis->itemHeight = GetSystemMetrics(SM_CYSMICON);
            }

            if (result) *result = TRUE;
            break;
        }

        case WM_DRAWITEM:
        {
            DRAWITEMSTRUCT *dis = (DRAWITEMSTRUCT *)lParam;
            HICON icon = 0;
            UINT x, y;

            if (!dis || dis->CtlType != ODT_MENU)
                break;

            if (This->folder_cmd == dis->itemID)
                icon = This->icon_folder;

            if (!icon)
                break;

            x = (dis->rcItem.right - dis->rcItem.left - GetSystemMetrics(SM_CXSMICON)) / 2;
            y = (dis->rcItem.bottom - dis->rcItem.top - GetSystemMetrics(SM_CYSMICON)) / 2;
            DrawStateW(dis->hDC, NULL, NULL, (LPARAM)icon, 0, x, y, 0, 0, DST_ICON | DSS_NORMAL);

            if (result) *result = TRUE;
            break;
        }
    }

    return S_OK;
}

static HRESULT WINAPI
NewMenu_ContextMenu3_HandleMenuMsg(IContextMenu3 *iface, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return NewMenu_ContextMenu3_HandleMenuMsg2(iface, uMsg, wParam, lParam, NULL);
}

static const IContextMenu3Vtbl cmvt3 =
{
    NewMenu_ContextMenu3_QueryInterface,
    NewMenu_ContextMenu3_AddRef,
    NewMenu_ContextMenu3_Release,
    NewMenu_ContextMenu3_QueryContextMenu,
    NewMenu_ContextMenu3_InvokeCommand,
    NewMenu_ContextMenu3_GetCommandString,
    NewMenu_ContextMenu3_HandleMenuMsg,
    NewMenu_ContextMenu3_HandleMenuMsg2
};

HRESULT WINAPI NewMenu_Constructor(IUnknown *outer, REFIID riid, void **obj)
{
    NewMenuImpl *menu;
    HRESULT hr;

    TRACE("outer=%p riid=%s\n", outer, debugstr_guid(riid));

    *obj = NULL;

    if (outer)
        return CLASS_E_NOAGGREGATION;

    menu = heap_alloc_zero(sizeof(NewMenuImpl));
    if (!menu) return E_OUTOFMEMORY;

    menu->ref = 1;
    menu->IShellExtInit_iface.lpVtbl    = &eivt;
    menu->IContextMenu3_iface.lpVtbl    = &cmvt3;
    menu->IObjectWithSite_iface.lpVtbl  = &owsvt;

    TRACE("(%p)\n", menu);

    hr = IShellExtInit_QueryInterface(&menu->IShellExtInit_iface, riid, obj);
    IShellExtInit_Release(&menu->IShellExtInit_iface);
    return hr;
}
