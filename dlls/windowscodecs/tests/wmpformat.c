/*
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

#define COBJMACROS

#include "objbase.h"
#include "wincodec.h"
#include "wine/test.h"

/* generated with JxrEncApp -i image.bmp -o image.jxr -q 1 -c 22 */
unsigned char wmp_imagedata[] = {
    0x49, 0x49, 0xbc, 0x01, 0x20, 0x00, 0x00, 0x00, 0x24, 0xc3, 0xdd, 0x6f,
    0x03, 0x4e, 0xfe, 0x4b, 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0xbc,
    0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0xbc,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xbc,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x81, 0xbc,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x82, 0xbc,
    0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x42, 0x83, 0xbc,
    0x0b, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x42, 0xc0, 0xbc,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x00, 0xc1, 0xbc,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0xaf, 0x00, 0x00, 0x00, 0xc2, 0xbc,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x4e, 0x01, 0x00, 0x00, 0xc3, 0xbc,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb3, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x57, 0x4d, 0x50, 0x48, 0x4f, 0x54, 0x4f, 0x00, 0x11, 0x45,
    0xc0, 0x71, 0x00, 0x00, 0x00, 0x04, 0x60, 0x00, 0xc0, 0x00, 0x00, 0x0c,
    0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x26, 0xff, 0xff, 0x00, 0x00, 0x01, 0x01, 0x51, 0x40, 0xc2,
    0x51, 0x88, 0x00, 0x00, 0x01, 0x02, 0x02, 0x10, 0x08, 0x62, 0x18, 0x84,
    0x21, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x18, 0x00, 0x00, 0x80, 0x40, 0x30, 0x00, 0x00, 0x00, 0x01, 0x03, 0x19,
    0x0d, 0x34, 0xd2, 0x77, 0x06, 0x62, 0xe8, 0x89, 0x8b, 0xa2, 0x26, 0x2f,
    0x11, 0xba, 0xbc, 0x46, 0xea, 0xa3, 0x6e, 0xdd, 0x72, 0x23, 0x75, 0x86,
    0xcd, 0x48, 0x73, 0xae, 0x43, 0xb9, 0x67, 0x8d, 0xfd, 0x98, 0xb0, 0xd5,
    0x52, 0x1d, 0xcb, 0x0d, 0x81, 0x06, 0xb4, 0x7d, 0xb8, 0x92, 0x5f, 0xf3,
    0x75, 0xc0, 0x3b, 0xd5, 0x07, 0xcb, 0xd0, 0xec, 0xde, 0x54, 0x1f, 0x7a,
    0x9a, 0x21, 0x8e, 0xcd, 0xe5, 0x4c, 0xdc, 0xce, 0xb8, 0x3e, 0xfa, 0x1d,
    0x8d, 0xca, 0x32, 0x94, 0xd2, 0x93, 0x2c, 0x76, 0x37, 0x2a, 0x63, 0x77,
    0x72, 0xd4, 0xd7, 0x66, 0x5a, 0xdb, 0x66, 0xed, 0x60, 0x00, 0x57, 0x4d,
    0x50, 0x48, 0x4f, 0x54, 0x4f, 0x00, 0x11, 0x45, 0xc0, 0x01, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x80, 0x20, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x13, 0xff, 0xff, 0x00, 0x00, 0x01, 0x01, 0x91, 0xe2, 0x00,
    0x00, 0x01, 0x02, 0x00, 0x86, 0x00, 0x00, 0x20, 0x10, 0x0c, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x03, 0xad, 0xcf, 0xf4, 0x6b, 0x64, 0x45, 0xe1, 0x91,
    0x17, 0x8e, 0x9a, 0x51, 0x32, 0x1f, 0xe2, 0x02, 0xfa, 0x69, 0x44, 0x3b,
    0xfc, 0x7b, 0xab, 0x20, 0xfe, 0x9d, 0x35, 0xd4, 0xda, 0xb7, 0xcb, 0x77,
    0x5f, 0x4d, 0xe5, 0x0e, 0xee, 0x39, 0x97, 0x6f, 0xb9, 0x99, 0x6b, 0x6d,
    0xcc, 0xb9, 0x60};

static void test_decode(void)
{
    IWICBitmapDecoder *decoder;
    IWICBitmapFrameDecode *framedecode;
    IWICImagingFactory *factory;
    IWICPalette *palette;
    HRESULT hr;
    HGLOBAL hwmpdata;
    char *wmpdata;
    IStream *wmpstream;
    GUID format;
    UINT count = 0, width = 0, height = 0;
    BYTE imagedata[5 * 4] = {1};
    UINT i;

    const BYTE expected_imagedata[5 * 4] = {
        0x6d, 0xb0, 0xfc, 0x00, 0x6d, 0xb0, 0xfc, 0x00, 0x6d, 0xb0,
        0xfc, 0x00, 0x6d, 0xb0, 0xfc, 0x00, 0x6d, 0xb0, 0xfc, 0x00,
    };

    hr = CoCreateInstance(&CLSID_WICWmpDecoder, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWICBitmapDecoder, (void **)&decoder);
    ok(SUCCEEDED(hr), "CoCreateInstance failed, hr=%x\n", hr);
    if (FAILED(hr)) return;

    hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IWICImagingFactory, (void **)&factory);
    ok(SUCCEEDED(hr), "CoCreateInstance failed, hr=%x\n", hr);

    hwmpdata = GlobalAlloc(GMEM_MOVEABLE, sizeof(wmp_imagedata));
    ok(hwmpdata != 0, "GlobalAlloc failed\n");

    wmpdata = GlobalLock(hwmpdata);
    memcpy(wmpdata, wmp_imagedata, sizeof(wmp_imagedata));
    GlobalUnlock(hwmpdata);

    hr = CreateStreamOnHGlobal(hwmpdata, FALSE, &wmpstream);
    ok(SUCCEEDED(hr), "CreateStreamOnHGlobal failed, hr=%x\n", hr);

    hr = IWICBitmapDecoder_Initialize(decoder, wmpstream, WICDecodeMetadataCacheOnLoad);
    ok(hr == S_OK, "Initialize failed, hr=%x\n", hr);

    hr = IWICBitmapDecoder_GetContainerFormat(decoder, &format);
    ok(SUCCEEDED(hr), "GetContainerFormat failed, hr=%x\n", hr);
    ok(IsEqualGUID(&format, &GUID_ContainerFormatWmp),
       "unexpected container format\n");

    hr = IWICBitmapDecoder_GetFrameCount(decoder, &count);
    ok(SUCCEEDED(hr), "GetFrameCount failed, hr=%x\n", hr);
    ok(count == 1, "unexpected count %u\n", count);

    hr = IWICBitmapDecoder_GetFrame(decoder, 0, &framedecode);
    ok(SUCCEEDED(hr), "GetFrame failed, hr=%x\n", hr);

    hr = IWICBitmapFrameDecode_GetSize(framedecode, &width, &height);
    ok(SUCCEEDED(hr), "GetSize failed, hr=%x\n", hr);
    ok(width == 1, "expected width=1, got %u\n", width);
    ok(height == 5, "expected height=5, got %u\n", height);

    hr = IWICBitmapFrameDecode_GetPixelFormat(framedecode, &format);
    ok(SUCCEEDED(hr), "GetPixelFormat failed, hr=%x\n", hr);
    ok(IsEqualGUID(&format, &GUID_WICPixelFormat32bppBGRA),
       "unexpected pixel format: %s\n", wine_dbgstr_guid(&format));

    for (i = 2; i > 0; --i)
    {
        hr = IWICBitmapFrameDecode_CopyPixels(
            framedecode, NULL, 4, sizeof(imagedata), imagedata);
        ok(SUCCEEDED(hr), "CopyPixels failed, hr=%x\n", hr);
        ok(!memcmp(imagedata, expected_imagedata, sizeof(imagedata)),
           "unexpected image data\n");
    }

    hr = IWICImagingFactory_CreatePalette(factory, &palette);
    ok(SUCCEEDED(hr), "CreatePalette failed, hr=%x\n", hr);

    hr = IWICBitmapDecoder_CopyPalette(decoder, palette);
    ok(hr == WINCODEC_ERR_PALETTEUNAVAILABLE, "Unexpected hr %#x.\n", hr);

    hr = IWICBitmapFrameDecode_CopyPalette(framedecode, palette);
    ok(hr == WINCODEC_ERR_PALETTEUNAVAILABLE, "Unexpected hr %#x.\n", hr);

    IWICPalette_Release(palette);

    IWICBitmapFrameDecode_Release(framedecode);
    IStream_Release(wmpstream);
    GlobalFree(hwmpdata);

    IWICBitmapDecoder_Release(decoder);
    IWICImagingFactory_Release(factory);
}

START_TEST(wmpformat)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    test_decode();

    CoUninitialize();
}
