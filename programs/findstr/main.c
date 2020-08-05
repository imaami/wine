/*
 * Copyright 2012 Qian Hong
 * Copyright 2018 Fabian Maurer
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

#include <windows.h>
#include <stdlib.h>
#include <shlwapi.h>

#include "wine/heap.h"
#include "wine/debug.h"
#include "resources.h"

WINE_DEFAULT_DEBUG_CHANNEL(findstr);

static BOOL read_char_from_handle(HANDLE handle, char *char_out)
{
    static char buffer[4096];
    static UINT buffer_max = 0;
    static UINT buffer_pos = 0;

    /* Read next content into buffer */
    if (buffer_pos >= buffer_max)
    {
        BOOL success = ReadFile(handle, buffer, 4096, &buffer_max, NULL);
        if (!success || !buffer_max)
            return FALSE;
        buffer_pos = 0;
    }

    *char_out = buffer[buffer_pos++];
    return TRUE;
}

/* Read a line from a handle, returns NULL if the end is reached */
static WCHAR* read_line_from_handle(HANDLE handle)
{
    int line_max = 4096;
    int length = 0;
    WCHAR *line_converted;
    int line_converted_length;
    BOOL success;
    char *line = heap_alloc(line_max);

    for (;;)
    {
        char c;
        success = read_char_from_handle(handle, &c);

        /* Check for EOF */
        if (!success)
        {
            if (length == 0)
                return NULL;
            else
                break;
        }

        if (c == '\n')
            break;

        /* Make sure buffer is large enough */
        if (length + 1 >= line_max)
        {
            line_max *= 2;
            line = heap_realloc(line, line_max);
        }

        line[length++] = c;
    }

    line[length] = 0;
    if (length - 1 >= 0 && line[length - 1] == '\r') /* Strip \r of windows line endings */
        line[length - 1] = 0;

    line_converted_length = MultiByteToWideChar(CP_ACP, 0, line, -1, 0, 0);
    line_converted = heap_alloc(line_converted_length * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, line, -1, line_converted, line_converted_length);

    heap_free(line);

    return line_converted;
}

static void write_to_stdout(const WCHAR *str)
{
    char *str_converted;
    UINT str_converted_length;
    DWORD bytes_written;
    UINT str_length = lstrlenW(str);
    int codepage = CP_ACP;

    str_converted_length = WideCharToMultiByte(codepage, 0, str, str_length, NULL, 0, NULL, NULL);
    str_converted = heap_alloc(str_converted_length);
    WideCharToMultiByte(codepage, 0, str, str_length, str_converted, str_converted_length, NULL, NULL);

    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), str_converted, str_converted_length, &bytes_written, NULL);
    if (bytes_written < str_converted_length)
        ERR("Failed to write output\n");

    heap_free(str_converted);
}

static BOOL run_find_for_line(const WCHAR *line, const WCHAR *tofind)
{
    WCHAR *found;
    WCHAR lineending[] = {'\r', '\n', 0};

    if (lstrlenW(line) == 0 || lstrlenW(tofind) == 0)
        return FALSE;

    found = wcsstr(line, tofind);

    if (found)
    {
        write_to_stdout(line);
        write_to_stdout(lineending);
        return TRUE;
    }

    return FALSE;
}

static void output_resource_message(int id)
{
    WCHAR buffer[64];
    LoadStringW(GetModuleHandleW(NULL), id, buffer, ARRAY_SIZE(buffer));
    write_to_stdout(buffer);
}

int __cdecl wmain(int argc, WCHAR *argv[])
{
    WCHAR *line;
    WCHAR *pattern = NULL; WCHAR *tofind = NULL;
    int i;
    int exitcode;
    int file_paths_len = 0;
    int file_paths_max = 0;
    WCHAR** file_paths = NULL;
    BOOL exact_match = FALSE;

    TRACE("running find:");
    for (i = 0; i < argc; i++)
    {
        FIXME(" %s", wine_dbgstr_w(argv[i]));
    }
    TRACE("\n");

    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '/')
        {
            switch(argv[i][1])
            {
            case '?':
                output_resource_message(IDS_USAGE);
                return 0;
            case 'C':
            case 'c':
                 if (argv[i][2] == ':')
                 {
                     pattern = argv[i] + 3;
                     exact_match = TRUE;
                 }
                 break;
            default:
                ;
            }
        }
        else if (pattern == NULL)
        {
            pattern = argv[i];
        }
        else
        {
            if (file_paths_len >= file_paths_max)
            {
                file_paths_max = file_paths_max ? file_paths_max * 2 : 2;
                file_paths = heap_realloc(file_paths, sizeof(WCHAR*) * file_paths_max);
            }
            file_paths[file_paths_len++] = argv[i];
        }
    }

    if (pattern == NULL)
    {
        output_resource_message(IDS_INVALID_PARAMETER);
        return 2;
    }

    exitcode = 1;

    if (file_paths_len > 0)
    {
        for (i = 0; i < file_paths_len; i++)
        {
            HANDLE input;
            WCHAR file_path_upper[MAX_PATH];

            wcscpy(file_path_upper, file_paths[i]);
            wcsupr(file_path_upper);

            input = CreateFileW(file_paths[i], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

            if (input == INVALID_HANDLE_VALUE)
            {
                WCHAR buffer_message[64];
                WCHAR message[300];

                LoadStringW(GetModuleHandleW(NULL), IDS_FILE_NOT_FOUND, buffer_message, ARRAY_SIZE(buffer_message));

                wsprintfW(message, buffer_message, file_path_upper);
                write_to_stdout(message);
                continue;
            }
            while ((line = read_line_from_handle(input)) != NULL)
            {
                tofind = _wcstok (pattern, exact_match ? L"" : L" |" ); /* break up (if necessary) search pattern like "foo bar" or "foo | bar" into "foo" and "bar" */
                    while (tofind != NULL)
                    {
                        if (run_find_for_line(line, tofind))
                        {
                            exitcode = 0;
                            break;
                        }
                        tofind = _wcstok (NULL, L" |");
                     }
            heap_free(line);
            }
            CloseHandle(input);
        }
    }
    else
    {
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        while ((line = read_line_from_handle(input)) != NULL)
        {
            tofind = _wcstok (pattern, exact_match ? L"" : L" |" ); /* break up (if necessary) search pattern like "foo bar" or "foo | bar" into "foo" and "bar" */
            while (tofind != NULL)
            {
                if (run_find_for_line(line, tofind))
                {
                    exitcode = 0;
                    break;
                }
                tofind = _wcstok (NULL, L" |");
             }
        heap_free(line);
        }
    }

    heap_free(file_paths);
    return exitcode;
}
