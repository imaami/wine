/*
 * Copyright 2002 Lionel Ulmer
 * Copyright 2002-2005 Jason Edmeades
 * Copyright 2003-2004 Raphael Junqueira
 * Copyright 2004 Christian Costa
 * Copyright 2005 Oliver Stieber
 * Copyright 2006-2008 Stefan Dösinger for CodeWeavers
 * Copyright 2006-2008 Henri Verbeet
 * Copyright 2007 Andrew Riedi
 * Copyright 2009-2011 Henri Verbeet for CodeWeavers
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

#ifdef HAVE_FLOAT_H
# include <float.h>
#endif

#include "wined3d_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3d);
WINE_DECLARE_DEBUG_CHANNEL(winediag);

struct wined3d_matrix_3x3
{
    float _11, _12, _13;
    float _21, _22, _23;
    float _31, _32, _33;
};

struct light_transformed
{
    struct wined3d_color diffuse, specular, ambient;
    struct wined3d_vec4 position;
    struct wined3d_vec3 direction;
    float range, falloff, c_att, l_att, q_att, cos_htheta, cos_hphi;
};

struct lights_settings
{
    struct light_transformed lights[WINED3D_MAX_SOFTWARE_ACTIVE_LIGHTS];
    struct wined3d_color ambient_light;
    struct wined3d_matrix modelview_matrix;
    struct wined3d_matrix_3x3 normal_matrix;
    struct wined3d_vec4 position_transformed;

    float fog_start, fog_end, fog_density;

    uint32_t point_light_count          : 8;
    uint32_t spot_light_count           : 8;
    uint32_t directional_light_count    : 8;
    uint32_t parallel_point_light_count : 8;
    uint32_t lighting                   : 1;
    uint32_t legacy_lighting            : 1;
    uint32_t normalise                  : 1;
    uint32_t localviewer                : 1;
    uint32_t fog_coord_mode             : 2;
    uint32_t fog_mode                   : 2;
    uint32_t padding                    : 24;
};

/* Define the default light parameters as specified by MSDN. */
const struct wined3d_light WINED3D_default_light =
{
    WINED3D_LIGHT_DIRECTIONAL,  /* Type */
    { 1.0f, 1.0f, 1.0f, 0.0f }, /* Diffuse r,g,b,a */
    { 0.0f, 0.0f, 0.0f, 0.0f }, /* Specular r,g,b,a */
    { 0.0f, 0.0f, 0.0f, 0.0f }, /* Ambient r,g,b,a, */
    { 0.0f, 0.0f, 0.0f },       /* Position x,y,z */
    { 0.0f, 0.0f, 1.0f },       /* Direction x,y,z */
    0.0f,                       /* Range */
    0.0f,                       /* Falloff */
    0.0f, 0.0f, 0.0f,           /* Attenuation 0,1,2 */
    0.0f,                       /* Theta */
    0.0f                        /* Phi */
};

BOOL device_context_add(struct wined3d_device *device, struct wined3d_context *context)
{
    struct wined3d_context **new_array;

    TRACE("Adding context %p.\n", context);

    if (!device->shader_backend->shader_allocate_context_data(context))
    {
        ERR("Failed to allocate shader backend context data.\n");
        return FALSE;
    }
    device->shader_backend->shader_init_context_state(context);

    if (!device->adapter->fragment_pipe->allocate_context_data(context))
    {
        ERR("Failed to allocate fragment pipeline context data.\n");
        device->shader_backend->shader_free_context_data(context);
        return FALSE;
    }

    if (!(new_array = heap_realloc(device->contexts, sizeof(*new_array) * (device->context_count + 1))))
    {
        ERR("Failed to grow the context array.\n");
        device->adapter->fragment_pipe->free_context_data(context);
        device->shader_backend->shader_free_context_data(context);
        return FALSE;
    }

    new_array[device->context_count++] = context;
    device->contexts = new_array;

    return TRUE;
}

void device_context_remove(struct wined3d_device *device, struct wined3d_context *context)
{
    struct wined3d_context **new_array;
    BOOL found = FALSE;
    UINT i;

    TRACE("Removing context %p.\n", context);

    device->adapter->fragment_pipe->free_context_data(context);
    device->shader_backend->shader_free_context_data(context);

    for (i = 0; i < device->context_count; ++i)
    {
        if (device->contexts[i] == context)
        {
            found = TRUE;
            break;
        }
    }

    if (!found)
    {
        ERR("Context %p doesn't exist in context array.\n", context);
        return;
    }

    if (!--device->context_count)
    {
        heap_free(device->contexts);
        device->contexts = NULL;
        return;
    }

    memmove(&device->contexts[i], &device->contexts[i + 1], (device->context_count - i) * sizeof(*device->contexts));
    if (!(new_array = heap_realloc(device->contexts, device->context_count * sizeof(*device->contexts))))
    {
        ERR("Failed to shrink context array. Oh well.\n");
        return;
    }

    device->contexts = new_array;
}

ULONG CDECL wined3d_device_incref(struct wined3d_device *device)
{
    ULONG refcount = InterlockedIncrement(&device->ref);

    TRACE("%p increasing refcount to %u.\n", device, refcount);

    return refcount;
}

static void device_free_so_desc(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_so_desc_entry *s = WINE_RB_ENTRY_VALUE(entry, struct wined3d_so_desc_entry, entry);

    heap_free(s);
}

static void device_leftover_sampler(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_sampler *sampler = WINE_RB_ENTRY_VALUE(entry, struct wined3d_sampler, entry);

    ERR("Leftover sampler %p.\n", sampler);
}

static void device_leftover_rasterizer_state(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_rasterizer_state *state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_rasterizer_state, entry);

    ERR("Leftover rasterizer state %p.\n", state);
}

static void device_leftover_blend_state(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_blend_state *blend_state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_blend_state, entry);

    ERR("Leftover blend state %p.\n", blend_state);
}

static void device_leftover_depth_stencil_state(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_depth_stencil_state *state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_depth_stencil_state, entry);

    ERR("Leftover depth/stencil state %p.\n", state);
}

void wined3d_device_cleanup(struct wined3d_device *device)
{
    unsigned int i;

    if (device->swapchain_count)
        wined3d_device_uninit_3d(device);

    wined3d_cs_destroy(device->cs);

    for (i = 0; i < ARRAY_SIZE(device->multistate_funcs); ++i)
    {
        heap_free(device->multistate_funcs[i]);
        device->multistate_funcs[i] = NULL;
    }

    if (!list_empty(&device->resources))
    {
        struct wined3d_resource *resource;

        ERR("Device released with resources still bound.\n");

        LIST_FOR_EACH_ENTRY(resource, &device->resources, struct wined3d_resource, resource_list_entry)
        {
            ERR("Leftover resource %p with type %s (%#x).\n",
                    resource, debug_d3dresourcetype(resource->type), resource->type);
        }
    }

    if (device->contexts)
        ERR("Context array not freed!\n");
    if (device->hardwareCursor)
        DestroyCursor(device->hardwareCursor);
    device->hardwareCursor = 0;

    wine_rb_destroy(&device->samplers, device_leftover_sampler, NULL);
    wine_rb_destroy(&device->rasterizer_states, device_leftover_rasterizer_state, NULL);
    wine_rb_destroy(&device->blend_states, device_leftover_blend_state, NULL);
    wine_rb_destroy(&device->depth_stencil_states, device_leftover_depth_stencil_state, NULL);
    wine_rb_destroy(&device->so_descs, device_free_so_desc, NULL);

    wined3d_decref(device->wined3d);
    device->wined3d = NULL;
}

ULONG CDECL wined3d_device_decref(struct wined3d_device *device)
{
    ULONG refcount = InterlockedDecrement(&device->ref);

    TRACE("%p decreasing refcount to %u.\n", device, refcount);

    if (!refcount)
    {
        device->adapter->adapter_ops->adapter_destroy_device(device);
        TRACE("Destroyed device %p.\n", device);
    }

    return refcount;
}

UINT CDECL wined3d_device_get_swapchain_count(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->swapchain_count;
}

struct wined3d_swapchain * CDECL wined3d_device_get_swapchain(const struct wined3d_device *device, UINT swapchain_idx)
{
    TRACE("device %p, swapchain_idx %u.\n", device, swapchain_idx);

    if (swapchain_idx >= device->swapchain_count)
    {
        WARN("swapchain_idx %u >= swapchain_count %u.\n",
                swapchain_idx, device->swapchain_count);
        return NULL;
    }

    return device->swapchains[swapchain_idx];
}

static void device_load_logo(struct wined3d_device *device, const char *filename)
{
    struct wined3d_color_key color_key;
    struct wined3d_resource_desc desc;
    HBITMAP hbm;
    BITMAP bm;
    HRESULT hr;
    HDC dcb = NULL, dcs = NULL;

    if (!(hbm = LoadImageA(NULL, filename, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION)))
    {
        ERR_(winediag)("Failed to load logo %s.\n", wine_dbgstr_a(filename));
        return;
    }
    GetObjectA(hbm, sizeof(BITMAP), &bm);

    if (!(dcb = CreateCompatibleDC(NULL)))
        goto out;
    SelectObject(dcb, hbm);

    desc.resource_type = WINED3D_RTYPE_TEXTURE_2D;
    desc.format = WINED3DFMT_B5G6R5_UNORM;
    desc.multisample_type = WINED3D_MULTISAMPLE_NONE;
    desc.multisample_quality = 0;
    desc.usage = WINED3DUSAGE_DYNAMIC;
    desc.bind_flags = 0;
    desc.access = WINED3D_RESOURCE_ACCESS_GPU;
    desc.width = bm.bmWidth;
    desc.height = bm.bmHeight;
    desc.depth = 1;
    desc.size = 0;
    if (FAILED(hr = wined3d_texture_create(device, &desc, 1, 1, WINED3D_TEXTURE_CREATE_GET_DC,
            NULL, NULL, &wined3d_null_parent_ops, &device->logo_texture)))
    {
        ERR("Wine logo requested, but failed to create texture, hr %#x.\n", hr);
        goto out;
    }

    if (FAILED(hr = wined3d_texture_get_dc(device->logo_texture, 0, &dcs)))
    {
        wined3d_texture_decref(device->logo_texture);
        device->logo_texture = NULL;
        goto out;
    }
    BitBlt(dcs, 0, 0, bm.bmWidth, bm.bmHeight, dcb, 0, 0, SRCCOPY);
    wined3d_texture_release_dc(device->logo_texture, 0, dcs);

    color_key.color_space_low_value = 0;
    color_key.color_space_high_value = 0;
    wined3d_texture_set_color_key(device->logo_texture, WINED3D_CKEY_SRC_BLT, &color_key);

out:
    if (dcb) DeleteDC(dcb);
    if (hbm) DeleteObject(hbm);
}

/* Context activation is done by the caller. */
static void wined3d_device_gl_create_dummy_textures(struct wined3d_device_gl *device_gl,
        struct wined3d_context_gl *context_gl)
{
    struct wined3d_dummy_textures *textures = &device_gl->dummy_textures;
    const struct wined3d_d3d_info *d3d_info = context_gl->c.d3d_info;
    const struct wined3d_gl_info *gl_info = context_gl->gl_info;
    unsigned int i;
    DWORD color;

    if (d3d_info->wined3d_creation_flags & WINED3D_LEGACY_UNBOUND_RESOURCE_COLOR)
        color = 0x000000ff;
    else
        color = 0x00000000;

    /* Under DirectX you can sample even if no texture is bound, whereas
     * OpenGL will only allow that when a valid texture is bound.
     * We emulate this by creating dummy textures and binding them
     * to each texture stage when the currently set D3D texture is NULL. */
    wined3d_context_gl_active_texture(context_gl, gl_info, 0);

    gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_1d);
    TRACE("Dummy 1D texture given name %u.\n", textures->tex_1d);
    gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_1D, textures->tex_1d);
    gl_info->gl_ops.gl.p_glTexImage1D(GL_TEXTURE_1D, 0, GL_RGBA8, 1, 0,
            GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color);

    gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_2d);
    TRACE("Dummy 2D texture given name %u.\n", textures->tex_2d);
    gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_2D, textures->tex_2d);
    gl_info->gl_ops.gl.p_glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, 1, 1, 0,
            GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color);

    if (gl_info->supported[ARB_TEXTURE_RECTANGLE])
    {
        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_rect);
        TRACE("Dummy rectangle texture given name %u.\n", textures->tex_rect);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_RECTANGLE_ARB, textures->tex_rect);
        gl_info->gl_ops.gl.p_glTexImage2D(GL_TEXTURE_RECTANGLE_ARB, 0, GL_RGBA8, 1, 1, 0,
                GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color);
    }

    if (gl_info->supported[EXT_TEXTURE3D])
    {
        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_3d);
        TRACE("Dummy 3D texture given name %u.\n", textures->tex_3d);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_3D, textures->tex_3d);
        GL_EXTCALL(glTexImage3D(GL_TEXTURE_3D, 0, GL_RGBA8, 1, 1, 1, 0,
                    GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color));
    }

    if (gl_info->supported[ARB_TEXTURE_CUBE_MAP])
    {
        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_cube);
        TRACE("Dummy cube texture given name %u.\n", textures->tex_cube);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_CUBE_MAP, textures->tex_cube);
        for (i = GL_TEXTURE_CUBE_MAP_POSITIVE_X; i <= GL_TEXTURE_CUBE_MAP_NEGATIVE_Z; ++i)
        {
            gl_info->gl_ops.gl.p_glTexImage2D(i, 0, GL_RGBA8, 1, 1, 0,
                    GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color);
        }
    }

    if (gl_info->supported[ARB_TEXTURE_CUBE_MAP_ARRAY])
    {
        DWORD cube_array_data[6];

        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_cube_array);
        TRACE("Dummy cube array texture given name %u.\n", textures->tex_cube_array);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_CUBE_MAP_ARRAY, textures->tex_cube_array);
        for (i = 0; i < ARRAY_SIZE(cube_array_data); ++i)
            cube_array_data[i] = color;
        GL_EXTCALL(glTexImage3D(GL_TEXTURE_CUBE_MAP_ARRAY, 0, GL_RGBA8, 1, 1, 6, 0,
                    GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, cube_array_data));
    }

    if (gl_info->supported[EXT_TEXTURE_ARRAY])
    {
        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_1d_array);
        TRACE("Dummy 1D array texture given name %u.\n", textures->tex_1d_array);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_1D_ARRAY, textures->tex_1d_array);
        gl_info->gl_ops.gl.p_glTexImage2D(GL_TEXTURE_1D_ARRAY, 0, GL_RGBA8, 1, 1, 0,
                    GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color);

        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_2d_array);
        TRACE("Dummy 2D array texture given name %u.\n", textures->tex_2d_array);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_2D_ARRAY, textures->tex_2d_array);
        GL_EXTCALL(glTexImage3D(GL_TEXTURE_2D_ARRAY, 0, GL_RGBA8, 1, 1, 1, 0,
                    GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color));
    }

    if (gl_info->supported[ARB_TEXTURE_BUFFER_OBJECT])
    {
        GLuint buffer;

        GL_EXTCALL(glGenBuffers(1, &buffer));
        GL_EXTCALL(glBindBuffer(GL_TEXTURE_BUFFER, buffer));
        GL_EXTCALL(glBufferData(GL_TEXTURE_BUFFER, sizeof(color), &color, GL_STATIC_DRAW));
        GL_EXTCALL(glBindBuffer(GL_TEXTURE_BUFFER, 0));

        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_buffer);
        TRACE("Dummy buffer texture given name %u.\n", textures->tex_buffer);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_BUFFER, textures->tex_buffer);
        GL_EXTCALL(glTexBuffer(GL_TEXTURE_BUFFER, GL_RGBA8, buffer));
        GL_EXTCALL(glDeleteBuffers(1, &buffer));
    }

    if (gl_info->supported[ARB_TEXTURE_MULTISAMPLE])
    {
        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_2d_ms);
        TRACE("Dummy multisample texture given name %u.\n", textures->tex_2d_ms);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_2D_MULTISAMPLE, textures->tex_2d_ms);
        GL_EXTCALL(glTexImage2DMultisample(GL_TEXTURE_2D_MULTISAMPLE, 1, GL_RGBA8, 1, 1, GL_TRUE));

        gl_info->gl_ops.gl.p_glGenTextures(1, &textures->tex_2d_ms_array);
        TRACE("Dummy multisample array texture given name %u.\n", textures->tex_2d_ms_array);
        gl_info->gl_ops.gl.p_glBindTexture(GL_TEXTURE_2D_MULTISAMPLE_ARRAY, textures->tex_2d_ms_array);
        GL_EXTCALL(glTexImage3DMultisample(GL_TEXTURE_2D_MULTISAMPLE_ARRAY, 1, GL_RGBA8, 1, 1, 1, GL_TRUE));

        if (gl_info->supported[ARB_CLEAR_TEXTURE])
        {
            GL_EXTCALL(glClearTexImage(textures->tex_2d_ms, 0, GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color));
            GL_EXTCALL(glClearTexImage(textures->tex_2d_ms_array, 0, GL_RGBA, GL_UNSIGNED_INT_8_8_8_8, &color));
        }
        else
        {
            WARN("ARB_clear_texture is currently required to clear dummy multisample textures.\n");
        }
    }

    checkGLcall("create dummy textures");

    wined3d_context_gl_bind_dummy_textures(context_gl);
}

/* Context activation is done by the caller. */
static void wined3d_device_gl_destroy_dummy_textures(struct wined3d_device_gl *device_gl,
        struct wined3d_context_gl *context_gl)
{
    struct wined3d_dummy_textures *dummy_textures = &device_gl->dummy_textures;
    const struct wined3d_gl_info *gl_info = context_gl->gl_info;

    if (gl_info->supported[ARB_TEXTURE_MULTISAMPLE])
    {
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_2d_ms);
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_2d_ms_array);
    }

    if (gl_info->supported[ARB_TEXTURE_BUFFER_OBJECT])
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_buffer);

    if (gl_info->supported[EXT_TEXTURE_ARRAY])
    {
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_2d_array);
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_1d_array);
    }

    if (gl_info->supported[ARB_TEXTURE_CUBE_MAP_ARRAY])
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_cube_array);

    if (gl_info->supported[ARB_TEXTURE_CUBE_MAP])
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_cube);

    if (gl_info->supported[EXT_TEXTURE3D])
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_3d);

    if (gl_info->supported[ARB_TEXTURE_RECTANGLE])
        gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_rect);

    gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_2d);
    gl_info->gl_ops.gl.p_glDeleteTextures(1, &dummy_textures->tex_1d);

    checkGLcall("delete dummy textures");

    memset(dummy_textures, 0, sizeof(*dummy_textures));
}

/* Context activation is done by the caller. */
void wined3d_device_create_default_samplers(struct wined3d_device *device, struct wined3d_context *context)
{
    struct wined3d_sampler_desc desc;
    HRESULT hr;

    desc.address_u = WINED3D_TADDRESS_WRAP;
    desc.address_v = WINED3D_TADDRESS_WRAP;
    desc.address_w = WINED3D_TADDRESS_WRAP;
    memset(desc.border_color, 0, sizeof(desc.border_color));
    desc.mag_filter = WINED3D_TEXF_POINT;
    desc.min_filter = WINED3D_TEXF_POINT;
    desc.mip_filter = WINED3D_TEXF_NONE;
    desc.lod_bias = 0.0f;
    desc.min_lod = -1000.0f;
    desc.max_lod =  1000.0f;
    desc.mip_base_level = 0;
    desc.max_anisotropy = 1;
    desc.compare = FALSE;
    desc.comparison_func = WINED3D_CMP_NEVER;
    desc.srgb_decode = TRUE;

    /* In SM4+ shaders there is a separation between resources and samplers. Some shader
     * instructions allow access to resources without using samplers.
     * In GLSL, resources are always accessed through sampler or image variables. The default
     * sampler object is used to emulate the direct resource access when there is no sampler state
     * to use.
     */
    if (FAILED(hr = wined3d_sampler_create(device, &desc, NULL, &wined3d_null_parent_ops, &device->default_sampler)))
    {
        ERR("Failed to create default sampler, hr %#x.\n", hr);
        device->default_sampler = NULL;
    }

    /* In D3D10+, a NULL sampler maps to the default sampler state. */
    desc.address_u = WINED3D_TADDRESS_CLAMP;
    desc.address_v = WINED3D_TADDRESS_CLAMP;
    desc.address_w = WINED3D_TADDRESS_CLAMP;
    desc.mag_filter = WINED3D_TEXF_LINEAR;
    desc.min_filter = WINED3D_TEXF_LINEAR;
    desc.mip_filter = WINED3D_TEXF_LINEAR;
    if (FAILED(hr = wined3d_sampler_create(device, &desc, NULL, &wined3d_null_parent_ops, &device->null_sampler)))
    {
        ERR("Failed to create null sampler, hr %#x.\n", hr);
        device->null_sampler = NULL;
    }
}

/* Context activation is done by the caller. */
void wined3d_device_destroy_default_samplers(struct wined3d_device *device, struct wined3d_context *context)
{
    wined3d_sampler_decref(device->default_sampler);
    device->default_sampler = NULL;
    wined3d_sampler_decref(device->null_sampler);
    device->null_sampler = NULL;
}

static bool wined3d_null_image_vk_init(struct wined3d_image_vk *image, struct wined3d_context_vk *context_vk,
        VkCommandBuffer vk_command_buffer, VkImageType type, unsigned int layer_count, unsigned int sample_count)
{
    const struct wined3d_vk_info *vk_info = context_vk->vk_info;
    VkImageSubresourceRange range;
    uint32_t flags = 0;

    static const VkClearColorValue colour = {{0}};

    TRACE("image %p, context_vk %p, vk_command_buffer %p, type %#x, layer_count %u, sample_count %u.\n",
            image, context_vk, vk_command_buffer, type, layer_count, sample_count);

    if (type == VK_IMAGE_TYPE_2D && layer_count >= 6)
        flags |= VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT;

    if (!wined3d_context_vk_create_image(context_vk, type,
            VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT, VK_FORMAT_R8G8B8A8_UNORM,
            1, 1, 1, sample_count, 1, layer_count, flags, image))
    {
        return false;
    }

    wined3d_context_vk_reference_image(context_vk, image);

    range.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    range.baseMipLevel = 0;
    range.levelCount = 1;
    range.baseArrayLayer = 0;
    range.layerCount = layer_count;

    wined3d_context_vk_image_barrier(context_vk, vk_command_buffer,
            VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, VK_ACCESS_TRANSFER_WRITE_BIT,
            VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, image->vk_image, &range);

    VK_CALL(vkCmdClearColorImage(vk_command_buffer, image->vk_image,
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &colour, 1, &range));

    wined3d_context_vk_image_barrier(context_vk, vk_command_buffer,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, VK_ACCESS_TRANSFER_WRITE_BIT, 0,
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL, image->vk_image, &range);

    TRACE("Created NULL image 0x%s, memory 0x%s.\n",
            wine_dbgstr_longlong(image->vk_image), wine_dbgstr_longlong(image->vk_memory));

    return true;
}

bool wined3d_device_vk_create_null_resources(struct wined3d_device_vk *device_vk,
        struct wined3d_context_vk *context_vk)
{
    struct wined3d_null_resources_vk *r = &device_vk->null_resources_vk;
    const struct wined3d_vk_info *vk_info;
    const struct wined3d_format *format;
    VkMemoryPropertyFlags memory_type;
    VkCommandBuffer vk_command_buffer;
    unsigned int sample_count = 2;
    VkBufferUsageFlags usage;

    format = wined3d_get_format(device_vk->d.adapter, WINED3DFMT_R8G8B8A8_UNORM, WINED3D_BIND_SHADER_RESOURCE);
    while (sample_count && !(sample_count & format->multisample_types))
        sample_count <<= 1;

    if (!(vk_command_buffer = wined3d_context_vk_get_command_buffer(context_vk)))
    {
        ERR("Failed to get command buffer.\n");
        return false;
    }

    vk_info = context_vk->vk_info;

    usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_UNIFORM_TEXEL_BUFFER_BIT
            | VK_BUFFER_USAGE_UNIFORM_BUFFER_BIT | VK_BUFFER_USAGE_VERTEX_BUFFER_BIT;
    memory_type = VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT;
    if (!wined3d_context_vk_create_bo(context_vk, 16, usage, memory_type, &r->bo))
        return false;
    VK_CALL(vkCmdFillBuffer(vk_command_buffer, r->bo.vk_buffer, r->bo.buffer_offset, r->bo.size, 0x00000000u));
    r->buffer_info.buffer = r->bo.vk_buffer;
    r->buffer_info.offset = r->bo.buffer_offset;
    r->buffer_info.range = r->bo.size;

    if (!wined3d_null_image_vk_init(&r->image_1d, context_vk, vk_command_buffer, VK_IMAGE_TYPE_1D, 1, 1))
    {
        ERR("Failed to create 1D image.\n");
        goto fail;
    }

    if (!wined3d_null_image_vk_init(&r->image_2d, context_vk, vk_command_buffer, VK_IMAGE_TYPE_2D, 6, 1))
    {
        ERR("Failed to create 2D image.\n");
        goto fail;
    }

    if (!wined3d_null_image_vk_init(&r->image_2dms, context_vk, vk_command_buffer, VK_IMAGE_TYPE_2D, 1, sample_count))
    {
        ERR("Failed to create 2D MSAA image.\n");
        goto fail;
    }

    if (!wined3d_null_image_vk_init(&r->image_3d, context_vk, vk_command_buffer, VK_IMAGE_TYPE_3D, 1, 1))
    {
        ERR("Failed to create 3D image.\n");
        goto fail;
    }

    return true;

fail:
    if (r->image_2dms.vk_image)
        wined3d_context_vk_destroy_image(context_vk, &r->image_2dms);
    if (r->image_2d.vk_image)
        wined3d_context_vk_destroy_image(context_vk, &r->image_2d);
    if (r->image_1d.vk_image)
        wined3d_context_vk_destroy_image(context_vk, &r->image_1d);
    wined3d_context_vk_reference_bo(context_vk, &r->bo);
    wined3d_context_vk_destroy_bo(context_vk, &r->bo);
    return false;
}

void wined3d_device_vk_destroy_null_resources(struct wined3d_device_vk *device_vk,
        struct wined3d_context_vk *context_vk)
{
    struct wined3d_null_resources_vk *r = &device_vk->null_resources_vk;

    /* We don't track command buffer references to NULL resources. We easily
     * could, but it doesn't seem worth it. */
    wined3d_context_vk_reference_image(context_vk, &r->image_3d);
    wined3d_context_vk_destroy_image(context_vk, &r->image_3d);
    wined3d_context_vk_reference_image(context_vk, &r->image_2dms);
    wined3d_context_vk_destroy_image(context_vk, &r->image_2dms);
    wined3d_context_vk_reference_image(context_vk, &r->image_2d);
    wined3d_context_vk_destroy_image(context_vk, &r->image_2d);
    wined3d_context_vk_reference_image(context_vk, &r->image_1d);
    wined3d_context_vk_destroy_image(context_vk, &r->image_1d);
    wined3d_context_vk_reference_bo(context_vk, &r->bo);
    wined3d_context_vk_destroy_bo(context_vk, &r->bo);
}

bool wined3d_device_vk_create_null_views(struct wined3d_device_vk *device_vk, struct wined3d_context_vk *context_vk)
{
    struct wined3d_null_resources_vk *r = &device_vk->null_resources_vk;
    struct wined3d_null_views_vk *v = &device_vk->null_views_vk;
    VkBufferViewCreateInfo buffer_create_info;
    const struct wined3d_vk_info *vk_info;
    VkImageViewCreateInfo view_desc;
    VkResult vr;

    vk_info = context_vk->vk_info;

    buffer_create_info.sType = VK_STRUCTURE_TYPE_BUFFER_VIEW_CREATE_INFO;
    buffer_create_info.pNext = NULL;
    buffer_create_info.flags = 0;
    buffer_create_info.buffer = r->bo.vk_buffer;
    buffer_create_info.format = VK_FORMAT_R32_UINT;
    buffer_create_info.offset = r->bo.buffer_offset;
    buffer_create_info.range = r->bo.size;

    if ((vr = VK_CALL(vkCreateBufferView(device_vk->vk_device,
            &buffer_create_info, NULL, &v->vk_view_buffer_uint))) < 0)
    {
        ERR("Failed to create buffer view, vr %s.\n", wined3d_debug_vkresult(vr));
        return false;
    }
    TRACE("Created buffer view 0x%s.\n", wine_dbgstr_longlong(v->vk_view_buffer_uint));

    buffer_create_info.format = VK_FORMAT_R32G32B32A32_SFLOAT;
    if ((vr = VK_CALL(vkCreateBufferView(device_vk->vk_device,
            &buffer_create_info, NULL, &v->vk_view_buffer_float))) < 0)
    {
        ERR("Failed to create buffer view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    TRACE("Created buffer view 0x%s.\n", wine_dbgstr_longlong(v->vk_view_buffer_float));

    view_desc.sType = VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO;
    view_desc.pNext = NULL;
    view_desc.flags = 0;
    view_desc.image = r->image_1d.vk_image;
    view_desc.viewType = VK_IMAGE_VIEW_TYPE_1D;
    view_desc.format = VK_FORMAT_R8G8B8A8_UNORM;
    view_desc.components.r = VK_COMPONENT_SWIZZLE_ZERO;
    view_desc.components.g = VK_COMPONENT_SWIZZLE_ZERO;
    view_desc.components.b = VK_COMPONENT_SWIZZLE_ZERO;
    view_desc.components.a = VK_COMPONENT_SWIZZLE_ZERO;
    view_desc.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    view_desc.subresourceRange.baseMipLevel = 0;
    view_desc.subresourceRange.levelCount = 1;
    view_desc.subresourceRange.baseArrayLayer = 0;
    view_desc.subresourceRange.layerCount = 1;
    if ((vr = VK_CALL(vkCreateImageView(device_vk->vk_device, &view_desc, NULL, &v->vk_info_1d.imageView))) < 0)
    {
        ERR("Failed to create 1D image view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    v->vk_info_1d.sampler = VK_NULL_HANDLE;
    v->vk_info_1d.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    TRACE("Created 1D image view 0x%s.\n", wine_dbgstr_longlong(v->vk_info_1d.imageView));

    view_desc.image = r->image_2d.vk_image;
    view_desc.viewType = VK_IMAGE_VIEW_TYPE_2D;
    if ((vr = VK_CALL(vkCreateImageView(device_vk->vk_device, &view_desc, NULL, &v->vk_info_2d.imageView))) < 0)
    {
        ERR("Failed to create 2D image view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    v->vk_info_2d.sampler = VK_NULL_HANDLE;
    v->vk_info_2d.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    TRACE("Created 2D image view 0x%s.\n", wine_dbgstr_longlong(v->vk_info_2d.imageView));

    view_desc.image = r->image_2dms.vk_image;
    view_desc.viewType = VK_IMAGE_VIEW_TYPE_2D;
    if ((vr = VK_CALL(vkCreateImageView(device_vk->vk_device, &view_desc, NULL, &v->vk_info_2dms.imageView))) < 0)
    {
        ERR("Failed to create 2D MSAA image view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    v->vk_info_2dms.sampler = VK_NULL_HANDLE;
    v->vk_info_2dms.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    TRACE("Created 2D MSAA image view 0x%s.\n", wine_dbgstr_longlong(v->vk_info_2dms.imageView));

    view_desc.image = r->image_3d.vk_image;
    view_desc.viewType = VK_IMAGE_VIEW_TYPE_3D;
    if ((vr = VK_CALL(vkCreateImageView(device_vk->vk_device, &view_desc, NULL, &v->vk_info_3d.imageView))) < 0)
    {
        ERR("Failed to create 3D image view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    v->vk_info_3d.sampler = VK_NULL_HANDLE;
    v->vk_info_3d.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    TRACE("Created 3D image view 0x%s.\n", wine_dbgstr_longlong(v->vk_info_3d.imageView));

    view_desc.image = r->image_2d.vk_image;
    view_desc.subresourceRange.layerCount = 6;
    view_desc.viewType = VK_IMAGE_VIEW_TYPE_CUBE;
    if ((vr = VK_CALL(vkCreateImageView(device_vk->vk_device, &view_desc, NULL, &v->vk_info_cube.imageView))) < 0)
    {
        ERR("Failed to create cube image view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    v->vk_info_cube.sampler = VK_NULL_HANDLE;
    v->vk_info_cube.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    TRACE("Created cube image view 0x%s.\n", wine_dbgstr_longlong(v->vk_info_cube.imageView));

    view_desc.subresourceRange.layerCount = 1;
    view_desc.viewType = VK_IMAGE_VIEW_TYPE_2D_ARRAY;
    if ((vr = VK_CALL(vkCreateImageView(device_vk->vk_device, &view_desc, NULL, &v->vk_info_2d_array.imageView))) < 0)
    {
        ERR("Failed to create 2D array image view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    v->vk_info_2d_array.sampler = VK_NULL_HANDLE;
    v->vk_info_2d_array.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    TRACE("Created 2D array image view 0x%s.\n", wine_dbgstr_longlong(v->vk_info_2d_array.imageView));

    view_desc.image = r->image_2dms.vk_image;
    view_desc.viewType = VK_IMAGE_VIEW_TYPE_2D_ARRAY;
    if ((vr = VK_CALL(vkCreateImageView(device_vk->vk_device, &view_desc, NULL, &v->vk_info_2dms_array.imageView))) < 0)
    {
        ERR("Failed to create 2D MSAA array image view, vr %s.\n", wined3d_debug_vkresult(vr));
        goto fail;
    }
    v->vk_info_2dms_array.sampler = VK_NULL_HANDLE;
    v->vk_info_2dms_array.imageLayout = VK_IMAGE_LAYOUT_SHADER_READ_ONLY_OPTIMAL;
    TRACE("Created 2D MSAA array image view 0x%s.\n", wine_dbgstr_longlong(v->vk_info_2dms_array.imageView));

    return true;

fail:
    if (v->vk_info_2d_array.imageView)
        VK_CALL(vkDestroyImageView(device_vk->vk_device, v->vk_info_2d_array.imageView, NULL));
    if (v->vk_info_cube.imageView)
        VK_CALL(vkDestroyImageView(device_vk->vk_device, v->vk_info_cube.imageView, NULL));
    if (v->vk_info_3d.imageView)
        VK_CALL(vkDestroyImageView(device_vk->vk_device, v->vk_info_3d.imageView, NULL));
    if (v->vk_info_2dms.imageView)
        VK_CALL(vkDestroyImageView(device_vk->vk_device, v->vk_info_2dms.imageView, NULL));
    if (v->vk_info_2d.imageView)
        VK_CALL(vkDestroyImageView(device_vk->vk_device, v->vk_info_2d.imageView, NULL));
    if (v->vk_info_1d.imageView)
        VK_CALL(vkDestroyImageView(device_vk->vk_device, v->vk_info_1d.imageView, NULL));
    if (v->vk_view_buffer_float)
        VK_CALL(vkDestroyBufferView(device_vk->vk_device, v->vk_view_buffer_float, NULL));
    VK_CALL(vkDestroyBufferView(device_vk->vk_device, v->vk_view_buffer_uint, NULL));
    return false;
}

void wined3d_device_vk_destroy_null_views(struct wined3d_device_vk *device_vk, struct wined3d_context_vk *context_vk)
{
    struct wined3d_null_views_vk *v = &device_vk->null_views_vk;
    uint64_t id = context_vk->current_command_buffer.id;

    wined3d_context_vk_destroy_vk_image_view(context_vk, v->vk_info_2dms_array.imageView, id);
    wined3d_context_vk_destroy_vk_image_view(context_vk, v->vk_info_2d_array.imageView, id);
    wined3d_context_vk_destroy_vk_image_view(context_vk, v->vk_info_cube.imageView, id);
    wined3d_context_vk_destroy_vk_image_view(context_vk, v->vk_info_3d.imageView, id);
    wined3d_context_vk_destroy_vk_image_view(context_vk, v->vk_info_2dms.imageView, id);
    wined3d_context_vk_destroy_vk_image_view(context_vk, v->vk_info_2d.imageView, id);
    wined3d_context_vk_destroy_vk_image_view(context_vk, v->vk_info_1d.imageView, id);

    wined3d_context_vk_destroy_vk_buffer_view(context_vk, v->vk_view_buffer_float, id);
    wined3d_context_vk_destroy_vk_buffer_view(context_vk, v->vk_view_buffer_uint, id);
}

HRESULT CDECL wined3d_device_acquire_focus_window(struct wined3d_device *device, HWND window)
{
    unsigned int screensaver_active;

    TRACE("device %p, window %p.\n", device, window);

    if (!wined3d_register_window(NULL, window, device, 0))
    {
        ERR("Failed to register window %p.\n", window);
        return E_FAIL;
    }

    InterlockedExchangePointer((void **)&device->focus_window, window);
    SetWindowPos(window, 0, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
    SystemParametersInfoW(SPI_GETSCREENSAVEACTIVE, 0, &screensaver_active, 0);
    if ((device->restore_screensaver = !!screensaver_active))
        SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, FALSE, NULL, 0);

    return WINED3D_OK;
}

void CDECL wined3d_device_release_focus_window(struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    if (device->focus_window) wined3d_unregister_window(device->focus_window);
    InterlockedExchangePointer((void **)&device->focus_window, NULL);
    if (device->restore_screensaver)
    {
        SystemParametersInfoW(SPI_SETSCREENSAVEACTIVE, TRUE, NULL, 0);
        device->restore_screensaver = FALSE;
    }
}

static void device_init_swapchain_state(struct wined3d_device *device, struct wined3d_swapchain *swapchain)
{
    BOOL ds_enable = swapchain->state.desc.enable_auto_depth_stencil;
    unsigned int i;

    for (i = 0; i < device->adapter->d3d_info.limits.max_rt_count; ++i)
    {
        wined3d_device_set_rendertarget_view(device, i, NULL, FALSE);
    }
    if (device->back_buffer_view)
        wined3d_device_set_rendertarget_view(device, 0, device->back_buffer_view, TRUE);

    wined3d_device_set_depth_stencil_view(device, ds_enable ? device->auto_depth_stencil_view : NULL);
}

void wined3d_device_delete_opengl_contexts_cs(void *object)
{
    struct wined3d_swapchain_gl *swapchain_gl;
    struct wined3d_device *device = object;
    struct wined3d_context_gl *context_gl;
    struct wined3d_device_gl *device_gl;
    struct wined3d_context *context;
    struct wined3d_shader *shader;

    TRACE("device %p.\n", device);

    device_gl = wined3d_device_gl(device);

    LIST_FOR_EACH_ENTRY(shader, &device->shaders, struct wined3d_shader, shader_list_entry)
    {
        device->shader_backend->shader_destroy(shader);
    }

    context = context_acquire(device, NULL, 0);
    context_gl = wined3d_context_gl(context);
    device->blitter->ops->blitter_destroy(device->blitter, context);
    device->shader_backend->shader_free_private(device, context);
    wined3d_device_gl_destroy_dummy_textures(device_gl, context_gl);
    wined3d_device_destroy_default_samplers(device, context);
    context_release(context);

    while (device->context_count)
    {
        if ((swapchain_gl = wined3d_swapchain_gl(device->contexts[0]->swapchain)))
            wined3d_swapchain_gl_destroy_contexts(swapchain_gl);
        else
            wined3d_context_gl_destroy(wined3d_context_gl(device->contexts[0]));
    }
}

void wined3d_device_create_primary_opengl_context_cs(void *object)
{
    struct wined3d_device *device = object;
    struct wined3d_context_gl *context_gl;
    struct wined3d_swapchain *swapchain;
    struct wined3d_context *context;
    struct wined3d_texture *target;
    HRESULT hr;

    TRACE("device %p.\n", device);

    swapchain = device->swapchains[0];
    target = swapchain->back_buffers ? swapchain->back_buffers[0] : swapchain->front_buffer;
    if (!(context = context_acquire(device, target, 0)))
    {
        WARN("Failed to acquire context.\n");
        return;
    }

    if (FAILED(hr = device->shader_backend->shader_alloc_private(device,
            device->adapter->vertex_pipe, device->adapter->fragment_pipe)))
    {
        ERR("Failed to allocate shader private data, hr %#x.\n", hr);
        context_release(context);
        return;
    }

    if (!(device->blitter = wined3d_cpu_blitter_create()))
    {
        ERR("Failed to create CPU blitter.\n");
        device->shader_backend->shader_free_private(device, NULL);
        context_release(context);
        return;
    }

    context_gl = wined3d_context_gl(context);

    wined3d_ffp_blitter_create(&device->blitter, context_gl->gl_info);
    if (!wined3d_glsl_blitter_create(&device->blitter, device))
        wined3d_arbfp_blitter_create(&device->blitter, device);
    wined3d_fbo_blitter_create(&device->blitter, context_gl->gl_info);
    wined3d_raw_blitter_create(&device->blitter, context_gl->gl_info);

    wined3d_device_gl_create_dummy_textures(wined3d_device_gl(device), context_gl);
    wined3d_device_create_default_samplers(device, context);
    context_release(context);
}

HRESULT wined3d_device_set_implicit_swapchain(struct wined3d_device *device, struct wined3d_swapchain *swapchain)
{
    static const struct wined3d_color black = {0.0f, 0.0f, 0.0f, 0.0f};
    const struct wined3d_swapchain_desc *swapchain_desc;
    struct wined3d_fb_state *fb = &device->cs->c.state->fb;
    DWORD clear_flags = 0;
    unsigned int i;
    HRESULT hr;

    TRACE("device %p, swapchain %p.\n", device, swapchain);

    if (device->d3d_initialized)
        return WINED3DERR_INVALIDCALL;

    device->swapchain_count = 1;
    if (!(device->swapchains = heap_calloc(device->swapchain_count, sizeof(*device->swapchains))))
    {
        ERR("Failed to allocate swapchain array.\n");
        hr = E_OUTOFMEMORY;
        goto err_out;
    }
    device->swapchains[0] = swapchain;

    for (i = 0; i < ARRAY_SIZE(fb->render_targets); ++i)
    {
        if (fb->render_targets[i])
            wined3d_rtv_bind_count_dec(fb->render_targets[i]);
    }
    memset(fb->render_targets, 0, sizeof(fb->render_targets));

    if (FAILED(hr = device->adapter->adapter_ops->adapter_init_3d(device)))
        goto err_out;
    device->d3d_initialized = TRUE;

    swapchain_desc = &swapchain->state.desc;
    if (swapchain_desc->backbuffer_count && swapchain_desc->backbuffer_bind_flags & WINED3D_BIND_RENDER_TARGET)
    {
        struct wined3d_resource *back_buffer = &swapchain->back_buffers[0]->resource;
        struct wined3d_view_desc view_desc;

        view_desc.format_id = back_buffer->format->id;
        view_desc.flags = 0;
        view_desc.u.texture.level_idx = 0;
        view_desc.u.texture.level_count = 1;
        view_desc.u.texture.layer_idx = 0;
        view_desc.u.texture.layer_count = 1;
        if (FAILED(hr = wined3d_rendertarget_view_create(&view_desc, back_buffer,
                NULL, &wined3d_null_parent_ops, &device->back_buffer_view)))
        {
            ERR("Failed to create rendertarget view, hr %#x.\n", hr);
            device->adapter->adapter_ops->adapter_uninit_3d(device);
            device->d3d_initialized = FALSE;
            goto err_out;
        }
    }

    device_init_swapchain_state(device, swapchain);

    TRACE("All defaults now set up.\n");

    /* Clear the screen. */
    if (device->back_buffer_view)
        clear_flags |= WINED3DCLEAR_TARGET;
    if (swapchain_desc->enable_auto_depth_stencil)
        clear_flags |= WINED3DCLEAR_ZBUFFER | WINED3DCLEAR_STENCIL;
    if (clear_flags)
        wined3d_device_clear(device, 0, NULL, clear_flags, &black, 1.0f, 0);

    if (wined3d_settings.logo)
        device_load_logo(device, wined3d_settings.logo);

    return WINED3D_OK;

err_out:
    heap_free(device->swapchains);
    device->swapchains = NULL;
    device->swapchain_count = 0;

    return hr;
}

static void device_free_sampler(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_sampler *sampler = WINE_RB_ENTRY_VALUE(entry, struct wined3d_sampler, entry);

    wined3d_sampler_decref(sampler);
}

static void device_free_rasterizer_state(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_rasterizer_state *state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_rasterizer_state, entry);

    wined3d_rasterizer_state_decref(state);
}

static void device_free_blend_state(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_blend_state *blend_state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_blend_state, entry);

    wined3d_blend_state_decref(blend_state);
}

static void device_free_depth_stencil_state(struct wine_rb_entry *entry, void *context)
{
    struct wined3d_depth_stencil_state *state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_depth_stencil_state, entry);

    wined3d_depth_stencil_state_decref(state);
}

void wined3d_device_uninit_3d(struct wined3d_device *device)
{
    struct wined3d_state *state = device->cs->c.state;
    struct wined3d_resource *resource, *cursor;
    struct wined3d_rendertarget_view *view;
    struct wined3d_texture *texture;

    TRACE("device %p.\n", device);

    if (!device->d3d_initialized)
    {
        ERR("Called while 3D support was not initialised.\n");
        return;
    }

    wined3d_cs_finish(device->cs, WINED3D_CS_QUEUE_DEFAULT);

    device->swapchain_count = 0;

    if ((texture = device->logo_texture))
    {
        device->logo_texture = NULL;
        wined3d_texture_decref(texture);
    }

    if ((texture = device->cursor_texture))
    {
        device->cursor_texture = NULL;
        wined3d_texture_decref(texture);
    }

    wined3d_cs_emit_reset_state(device->cs);
    state_cleanup(state);

    wine_rb_clear(&device->samplers, device_free_sampler, NULL);
    wine_rb_clear(&device->rasterizer_states, device_free_rasterizer_state, NULL);
    wine_rb_clear(&device->blend_states, device_free_blend_state, NULL);
    wine_rb_clear(&device->depth_stencil_states, device_free_depth_stencil_state, NULL);

    LIST_FOR_EACH_ENTRY_SAFE(resource, cursor, &device->resources, struct wined3d_resource, resource_list_entry)
    {
        TRACE("Unloading resource %p.\n", resource);
        wined3d_cs_emit_unload_resource(device->cs, resource);
    }

    device->adapter->adapter_ops->adapter_uninit_3d(device);
    device->d3d_initialized = FALSE;

    if ((view = device->auto_depth_stencil_view))
    {
        device->auto_depth_stencil_view = NULL;
        if (wined3d_rendertarget_view_decref(view))
            ERR("Something's still holding the auto depth/stencil view (%p).\n", view);
    }

    if ((view = device->back_buffer_view))
    {
        device->back_buffer_view = NULL;
        wined3d_rendertarget_view_decref(view);
    }

    heap_free(device->swapchains);
    device->swapchains = NULL;

    wined3d_state_reset(state, &device->adapter->d3d_info);
}

/* Enables thread safety in the wined3d device and its resources. Called by DirectDraw
 * from SetCooperativeLevel if DDSCL_MULTITHREADED is specified, and by d3d8/9 from
 * CreateDevice if D3DCREATE_MULTITHREADED is passed.
 *
 * There is no way to deactivate thread safety once it is enabled.
 */
void CDECL wined3d_device_set_multithreaded(struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    /* For now just store the flag (needed in case of ddraw). */
    device->create_parms.flags |= WINED3DCREATE_MULTITHREADED;
}

UINT CDECL wined3d_device_get_available_texture_mem(const struct wined3d_device *device)
{
    const struct wined3d_driver_info *driver_info;

    TRACE("device %p.\n", device);

    driver_info = &device->adapter->driver_info;

    /* We can not acquire the context unless there is a swapchain. */
    /*
    if (device->swapchains && gl_info->supported[NVX_GPU_MEMORY_INFO] &&
            !wined3d_settings.emulated_textureram)
    {
        GLint vram_free_kb;
        UINT64 vram_free;

        struct wined3d_context *context = context_acquire(device, NULL, 0);
        gl_info->gl_ops.gl.p_glGetIntegerv(GL_GPU_MEMORY_INFO_CURRENT_AVAILABLE_VIDMEM_NVX, &vram_free_kb);
        vram_free = (UINT64)vram_free_kb * 1024;
        context_release(context);

        TRACE("Total 0x%s bytes. emulation 0x%s left, driver 0x%s left.\n",
                wine_dbgstr_longlong(device->adapter->vram_bytes),
                wine_dbgstr_longlong(device->adapter->vram_bytes - device->adapter->vram_bytes_used),
                wine_dbgstr_longlong(vram_free));

        vram_free = min(vram_free, device->adapter->vram_bytes - device->adapter->vram_bytes_used);
        return min(UINT_MAX, vram_free);
    }
    */

    TRACE("Emulating 0x%s bytes. 0x%s used, returning 0x%s left.\n",
            wine_dbgstr_longlong(driver_info->vram_bytes),
            wine_dbgstr_longlong(device->adapter->vram_bytes_used),
            wine_dbgstr_longlong(driver_info->vram_bytes - device->adapter->vram_bytes_used));

    return min(UINT_MAX, driver_info->vram_bytes - device->adapter->vram_bytes_used);
}

void CDECL wined3d_device_set_stream_output(struct wined3d_device *device, UINT idx,
        struct wined3d_buffer *buffer, UINT offset)
{
    TRACE("device %p, idx %u, buffer %p, offset %u.\n", device, idx, buffer, offset);

    wined3d_device_context_set_stream_output(&device->cs->c, idx, buffer, offset);
}

struct wined3d_buffer * CDECL wined3d_device_context_get_stream_output(struct wined3d_device_context *context,
        unsigned int idx, unsigned int *offset)
{
    TRACE("context %p, idx %u, offset %p.\n", context, idx, offset);

    if (idx >= WINED3D_MAX_STREAM_OUTPUT_BUFFERS)
    {
        WARN("Invalid stream output %u.\n", idx);
        return NULL;
    }

    if (offset)
        *offset = context->state->stream_output[idx].offset;
    return context->state->stream_output[idx].buffer;
}

HRESULT CDECL wined3d_device_set_stream_source(struct wined3d_device *device, UINT stream_idx,
        struct wined3d_buffer *buffer, UINT offset, UINT stride)
{
    TRACE("device %p, stream_idx %u, buffer %p, offset %u, stride %u.\n",
            device, stream_idx, buffer, offset, stride);

    return wined3d_device_context_set_stream_source(&device->cs->c, stream_idx, buffer, offset, stride);
}

HRESULT CDECL wined3d_device_context_get_stream_source(const struct wined3d_device_context *context,
        unsigned int stream_idx, struct wined3d_buffer **buffer, unsigned int *offset, unsigned int *stride)
{
    const struct wined3d_stream_state *stream;

    TRACE("context %p, stream_idx %u, buffer %p, offset %p, stride %p.\n",
            context, stream_idx, buffer, offset, stride);

    if (stream_idx >= WINED3D_MAX_STREAMS)
    {
        WARN("Stream index %u out of range.\n", stream_idx);
        return WINED3DERR_INVALIDCALL;
    }

    stream = &context->state->streams[stream_idx];
    *buffer = stream->buffer;
    if (offset)
        *offset = stream->offset;
    *stride = stream->stride;

    return WINED3D_OK;
}

static void wined3d_device_set_stream_source_freq(struct wined3d_device *device, UINT stream_idx, UINT divider)
{
    struct wined3d_stream_state *stream;
    UINT old_flags, old_freq;

    TRACE("device %p, stream_idx %u, divider %#x.\n", device, stream_idx, divider);

    stream = &device->cs->c.state->streams[stream_idx];
    old_flags = stream->flags;
    old_freq = stream->frequency;

    stream->flags = divider & (WINED3DSTREAMSOURCE_INSTANCEDATA | WINED3DSTREAMSOURCE_INDEXEDDATA);
    stream->frequency = divider & 0x7fffff;
    if (stream->frequency != old_freq || stream->flags != old_flags)
        wined3d_cs_emit_set_stream_source_freq(device->cs, stream_idx, stream->frequency, stream->flags);
}

static void wined3d_device_set_transform(struct wined3d_device *device,
        enum wined3d_transform_state state, const struct wined3d_matrix *matrix)
{
    TRACE("device %p, state %s, matrix %p.\n",
            device, debug_d3dtstype(state), matrix);
    TRACE("%.8e %.8e %.8e %.8e\n", matrix->_11, matrix->_12, matrix->_13, matrix->_14);
    TRACE("%.8e %.8e %.8e %.8e\n", matrix->_21, matrix->_22, matrix->_23, matrix->_24);
    TRACE("%.8e %.8e %.8e %.8e\n", matrix->_31, matrix->_32, matrix->_33, matrix->_34);
    TRACE("%.8e %.8e %.8e %.8e\n", matrix->_41, matrix->_42, matrix->_43, matrix->_44);

    /* If the new matrix is the same as the current one,
     * we cut off any further processing. this seems to be a reasonable
     * optimization because as was noticed, some apps (warcraft3 for example)
     * tend towards setting the same matrix repeatedly for some reason.
     *
     * From here on we assume that the new matrix is different, wherever it matters. */
    if (!memcmp(&device->cs->c.state->transforms[state], matrix, sizeof(*matrix)))
    {
        TRACE("The application is setting the same matrix over again.\n");
        return;
    }

    device->cs->c.state->transforms[state] = *matrix;
    wined3d_cs_emit_set_transform(device->cs, state, matrix);
}

static void wined3d_device_get_transform(const struct wined3d_device *device,
        enum wined3d_transform_state state, struct wined3d_matrix *matrix)
{
    TRACE("device %p, state %s, matrix %p.\n", device, debug_d3dtstype(state), matrix);

    *matrix = device->cs->c.state->transforms[state];
}

/* Note lights are real special cases. Although the device caps state only
 * e.g. 8 are supported, you can reference any indexes you want as long as
 * that number max are enabled at any one point in time. Therefore since the
 * indices can be anything, we need a hashmap of them. However, this causes
 * stateblock problems. When capturing the state block, I duplicate the
 * hashmap, but when recording, just build a chain pretty much of commands to
 * be replayed. */
static void wined3d_device_set_light(struct wined3d_device *device,
        UINT light_idx, const struct wined3d_light *light)
{
    struct wined3d_light_info *object = NULL;
    float rho;

    TRACE("device %p, light_idx %u, light %p.\n", device, light_idx, light);

    if (FAILED(wined3d_light_state_set_light(&device->cs->c.state->light_state, light_idx, light, &object)))
        return;

    /* Initialize the object. */
    TRACE("Light %u setting to type %#x, diffuse %s, specular %s, ambient %s, "
            "position {%.8e, %.8e, %.8e}, direction {%.8e, %.8e, %.8e}, "
            "range %.8e, falloff %.8e, theta %.8e, phi %.8e.\n",
            light_idx, light->type, debug_color(&light->diffuse),
            debug_color(&light->specular), debug_color(&light->ambient),
            light->position.x, light->position.y, light->position.z,
            light->direction.x, light->direction.y, light->direction.z,
            light->range, light->falloff, light->theta, light->phi);

    switch (light->type)
    {
        case WINED3D_LIGHT_POINT:
            /* Position */
            object->position.x = light->position.x;
            object->position.y = light->position.y;
            object->position.z = light->position.z;
            object->position.w = 1.0f;
            object->cutoff = 180.0f;
            /* FIXME: Range */
            break;

        case WINED3D_LIGHT_DIRECTIONAL:
            /* Direction */
            object->direction.x = -light->direction.x;
            object->direction.y = -light->direction.y;
            object->direction.z = -light->direction.z;
            object->direction.w = 0.0f;
            object->exponent = 0.0f;
            object->cutoff = 180.0f;
            break;

        case WINED3D_LIGHT_SPOT:
            /* Position */
            object->position.x = light->position.x;
            object->position.y = light->position.y;
            object->position.z = light->position.z;
            object->position.w = 1.0f;

            /* Direction */
            object->direction.x = light->direction.x;
            object->direction.y = light->direction.y;
            object->direction.z = light->direction.z;
            object->direction.w = 0.0f;

            /* opengl-ish and d3d-ish spot lights use too different models
             * for the light "intensity" as a function of the angle towards
             * the main light direction, so we only can approximate very
             * roughly. However, spot lights are rather rarely used in games
             * (if ever used at all). Furthermore if still used, probably
             * nobody pays attention to such details. */
            if (!light->falloff)
            {
                /* Falloff = 0 is easy, because d3d's and opengl's spot light
                 * equations have the falloff resp. exponent parameter as an
                 * exponent, so the spot light lighting will always be 1.0 for
                 * both of them, and we don't have to care for the rest of the
                 * rather complex calculation. */
                object->exponent = 0.0f;
            }
            else
            {
                rho = light->theta + (light->phi - light->theta) / (2 * light->falloff);
                if (rho < 0.0001f)
                    rho = 0.0001f;
                object->exponent = -0.3f / logf(cosf(rho / 2));
            }

            if (object->exponent > 128.0f)
                object->exponent = 128.0f;

            object->cutoff = (float)(light->phi * 90 / M_PI);
            /* FIXME: Range */
            break;

        case WINED3D_LIGHT_PARALLELPOINT:
            object->position.x = light->position.x;
            object->position.y = light->position.y;
            object->position.z = light->position.z;
            object->position.w = 1.0f;
            break;

        default:
            FIXME("Unrecognized light type %#x.\n", light->type);
    }

    wined3d_cs_emit_set_light(device->cs, object);
}

static void wined3d_device_set_light_enable(struct wined3d_device *device, UINT light_idx, BOOL enable)
{
    struct wined3d_light_state *light_state = &device->cs->c.state->light_state;
    struct wined3d_light_info *light_info;

    TRACE("device %p, light_idx %u, enable %#x.\n", device, light_idx, enable);

    /* Special case - enabling an undefined light creates one with a strict set of parameters. */
    if (!(light_info = wined3d_light_state_get_light(light_state, light_idx)))
    {
        TRACE("Light enabled requested but light not defined, so defining one!\n");
        wined3d_device_set_light(device, light_idx, &WINED3D_default_light);

        if (!(light_info = wined3d_light_state_get_light(light_state, light_idx)))
        {
            FIXME("Adding default lights has failed dismally\n");
            return;
        }
    }

    wined3d_light_state_enable_light(light_state, &device->adapter->d3d_info, light_info, enable);
    wined3d_cs_emit_set_light_enable(device->cs, light_idx, enable);
}

static HRESULT wined3d_device_set_clip_plane(struct wined3d_device *device,
        UINT plane_idx, const struct wined3d_vec4 *plane)
{
    struct wined3d_vec4 *clip_planes = device->cs->c.state->clip_planes;

    TRACE("device %p, plane_idx %u, plane %p.\n", device, plane_idx, plane);

    if (plane_idx >= device->adapter->d3d_info.limits.max_clip_distances)
    {
        TRACE("Application has requested clipplane this device doesn't support.\n");
        return WINED3DERR_INVALIDCALL;
    }

    if (!memcmp(&clip_planes[plane_idx], plane, sizeof(*plane)))
    {
        TRACE("Application is setting old values over, nothing to do.\n");
        return WINED3D_OK;
    }

    clip_planes[plane_idx] = *plane;

    wined3d_cs_emit_set_clip_plane(device->cs, plane_idx, plane);

    return WINED3D_OK;
}

HRESULT CDECL wined3d_device_set_clip_status(struct wined3d_device *device,
        const struct wined3d_clip_status *clip_status)
{
    FIXME("device %p, clip_status %p stub!\n", device, clip_status);

    if (!clip_status)
        return WINED3DERR_INVALIDCALL;

    return WINED3D_OK;
}

HRESULT CDECL wined3d_device_get_clip_status(const struct wined3d_device *device,
        struct wined3d_clip_status *clip_status)
{
    FIXME("device %p, clip_status %p stub!\n", device, clip_status);

    if (!clip_status)
        return WINED3DERR_INVALIDCALL;

    return WINED3D_OK;
}

static void wined3d_device_set_material(struct wined3d_device *device, const struct wined3d_material *material)
{
    TRACE("device %p, material %p.\n", device, material);

    device->cs->c.state->material = *material;
    wined3d_cs_emit_set_material(device->cs, material);
}

void CDECL wined3d_device_set_index_buffer(struct wined3d_device *device,
        struct wined3d_buffer *buffer, enum wined3d_format_id format_id, unsigned int offset)
{
    TRACE("device %p, buffer %p, format %s, offset %u.\n",
            device, buffer, debug_d3dformat(format_id), offset);

    wined3d_device_context_set_index_buffer(&device->cs->c, buffer, format_id, offset);
}

struct wined3d_buffer * CDECL wined3d_device_context_get_index_buffer(const struct wined3d_device_context *context,
        enum wined3d_format_id *format, unsigned int *offset)
{
    const struct wined3d_state *state = context->state;

    TRACE("context %p, format %p, offset %p.\n", context, format, offset);

    *format = state->index_format;
    if (offset)
        *offset = state->index_offset;
    return state->index_buffer;
}

void CDECL wined3d_device_set_base_vertex_index(struct wined3d_device *device, INT base_index)
{
    TRACE("device %p, base_index %d.\n", device, base_index);

    device->cs->c.state->base_vertex_index = base_index;
}

void CDECL wined3d_device_set_viewports(struct wined3d_device *device, unsigned int viewport_count,
        const struct wined3d_viewport *viewports)
{
    unsigned int i;

    TRACE("device %p, viewport_count %u, viewports %p.\n", device, viewport_count, viewports);

    for (i = 0; i < viewport_count; ++i)
    {
        TRACE("%u: x %.8e, y %.8e, w %.8e, h %.8e, min_z %.8e, max_z %.8e.\n",  i, viewports[i].x, viewports[i].y,
                viewports[i].width, viewports[i].height, viewports[i].min_z, viewports[i].max_z);
    }

    wined3d_device_context_set_viewports(&device->cs->c, viewport_count, viewports);
}

void CDECL wined3d_device_context_get_viewports(const struct wined3d_device_context *context,
        unsigned int *viewport_count, struct wined3d_viewport *viewports)
{
    const struct wined3d_state *state = context->state;
    unsigned int count;

    TRACE("context %p, viewport_count %p, viewports %p.\n", context, viewport_count, viewports);

    count = viewport_count ? min(*viewport_count, state->viewport_count) : 1;
    if (count && viewports)
        memcpy(viewports, state->viewports, count * sizeof(*viewports));
    if (viewport_count)
        *viewport_count = state->viewport_count;
}

static void resolve_depth_buffer(struct wined3d_device *device)
{
    const struct wined3d_state *state = device->cs->c.state;
    struct wined3d_rendertarget_view *src_view;
    struct wined3d_resource *dst_resource;
    struct wined3d_texture *dst_texture;

    if (!(dst_texture = state->textures[0]))
        return;
    dst_resource = &dst_texture->resource;
    if (!dst_resource->format->depth_size)
        return;
    if (!(src_view = state->fb.depth_stencil))
        return;

    wined3d_device_context_resolve_sub_resource(&device->cs->c, dst_resource, 0,
            src_view->resource, src_view->sub_resource_idx, dst_resource->format->id);
}

void CDECL wined3d_device_set_blend_state(struct wined3d_device *device,
        struct wined3d_blend_state *blend_state, const struct wined3d_color *blend_factor, unsigned int sample_mask)
{
    TRACE("device %p, blend_state %p, blend_factor %s, sample_mask %#x.\n",
            device, blend_state, debug_color(blend_factor), sample_mask);

    wined3d_device_context_set_blend_state(&device->cs->c, blend_state, blend_factor, sample_mask);
}

struct wined3d_blend_state * CDECL wined3d_device_context_get_blend_state(const struct wined3d_device_context *context,
        struct wined3d_color *blend_factor, unsigned int *sample_mask)
{
    const struct wined3d_state *state = context->state;

    TRACE("context %p, blend_factor %p, sample_mask %p.\n", context, blend_factor, sample_mask);

    *blend_factor = state->blend_factor;
    *sample_mask = state->sample_mask;
    return state->blend_state;
}

void CDECL wined3d_device_set_depth_stencil_state(struct wined3d_device *device,
        struct wined3d_depth_stencil_state *depth_stencil_state, unsigned int stencil_ref)
{
    TRACE("device %p, depth_stencil_state %p, stencil_ref %u.\n", device, depth_stencil_state, stencil_ref);

    wined3d_device_context_set_depth_stencil_state(&device->cs->c, depth_stencil_state, stencil_ref);
}

struct wined3d_depth_stencil_state * CDECL wined3d_device_context_get_depth_stencil_state(
        const struct wined3d_device_context *context, unsigned int *stencil_ref)
{
    const struct wined3d_state *state = context->state;

    TRACE("context %p, stencil_ref %p.\n", context, stencil_ref);

    *stencil_ref = state->stencil_ref;
    return state->depth_stencil_state;
}

void CDECL wined3d_device_set_rasterizer_state(struct wined3d_device *device,
        struct wined3d_rasterizer_state *rasterizer_state)
{
    TRACE("device %p, rasterizer_state %p.\n", device, rasterizer_state);

    wined3d_device_context_set_rasterizer_state(&device->cs->c, rasterizer_state);
}

struct wined3d_rasterizer_state * CDECL wined3d_device_context_get_rasterizer_state(
        struct wined3d_device_context *context)
{
    TRACE("context %p.\n", context);

    return context->state->rasterizer_state;
}

void CDECL wined3d_device_set_render_state(struct wined3d_device *device,
        enum wined3d_render_state state, DWORD value)
{
    TRACE("device %p, state %s (%#x), value %#x.\n", device, debug_d3drenderstate(state), state, value);

    if (state > WINEHIGHEST_RENDER_STATE)
    {
        WARN("Unhandled render state %#x.\n", state);
        return;
    }

    if (value == device->cs->c.state->render_states[state])
        TRACE("Application is setting the old value over, nothing to do.\n");
    else
    {
        device->cs->c.state->render_states[state] = value;
        wined3d_cs_emit_set_render_state(device->cs, state, value);
    }

    if (state == WINED3D_RS_POINTSIZE && value == WINED3D_RESZ_CODE)
    {
        TRACE("RESZ multisampled depth buffer resolve triggered.\n");
        resolve_depth_buffer(device);
    }
}

DWORD CDECL wined3d_device_get_render_state(const struct wined3d_device *device, enum wined3d_render_state state)
{
    TRACE("device %p, state %s (%#x).\n", device, debug_d3drenderstate(state), state);

    return device->cs->c.state->render_states[state];
}

static void wined3d_device_set_sampler_state(struct wined3d_device *device,
        UINT sampler_idx, enum wined3d_sampler_state state, DWORD value)
{
    TRACE("device %p, sampler_idx %u, state %s, value %#x.\n",
            device, sampler_idx, debug_d3dsamplerstate(state), value);

    if (value == device->cs->c.state->sampler_states[sampler_idx][state])
    {
        TRACE("Application is setting the old value over, nothing to do.\n");
        return;
    }

    device->cs->c.state->sampler_states[sampler_idx][state] = value;
    wined3d_cs_emit_set_sampler_state(device->cs, sampler_idx, state, value);
}

void CDECL wined3d_device_set_scissor_rects(struct wined3d_device *device, unsigned int rect_count,
        const RECT *rects)
{
    unsigned int i;

    TRACE("device %p, rect_count %u, rects %p.\n", device, rect_count, rects);

    for (i = 0; i < rect_count; ++i)
    {
        TRACE("%u: %s\n", i, wine_dbgstr_rect(&rects[i]));
    }

    wined3d_device_context_set_scissor_rects(&device->cs->c, rect_count, rects);
}

void CDECL wined3d_device_context_get_scissor_rects(const struct wined3d_device_context *context,
        unsigned int *rect_count, RECT *rects)
{
    const struct wined3d_state *state = context->state;
    unsigned int count;

    TRACE("context %p, rect_count %p, rects %p.\n", context, rect_count, rects);

    if (rects && (count = rect_count ? min(*rect_count, state->scissor_rect_count) : 1))
        memcpy(rects, state->scissor_rects, count * sizeof(*rects));
    if (rect_count)
        *rect_count = state->scissor_rect_count;
}

void CDECL wined3d_device_set_state(struct wined3d_device *device, struct wined3d_state *state)
{
    struct wined3d_device_context *context = &device->cs->c;
    const struct wined3d_light_info *light;
    unsigned int i, j;

    TRACE("device %p, state %p.\n", device, state);

    device->cs->c.state = state;
    wined3d_cs_emit_set_feature_level(device->cs, state->feature_level);

    for (i = 0; i < WINED3D_MAX_RENDER_TARGETS; ++i)
    {
        wined3d_device_context_emit_set_rendertarget_view(context, i, state->fb.render_targets[i]);
    }

    wined3d_device_context_emit_set_depth_stencil_view(context, state->fb.depth_stencil);
    wined3d_device_context_emit_set_vertex_declaration(context, state->vertex_declaration);

    for (i = 0; i < WINED3D_MAX_STREAM_OUTPUT_BUFFERS; ++i)
    {
        wined3d_device_context_emit_set_stream_output(context, i,
                state->stream_output[i].buffer, state->stream_output[i].offset);
    }

    for (i = 0; i < WINED3D_MAX_STREAMS; ++i)
    {
        wined3d_device_context_emit_set_stream_source(context, i, state->streams[i].buffer,
                state->streams[i].offset, state->streams[i].stride);
    }

    wined3d_device_context_emit_set_index_buffer(context, state->index_buffer,
            state->index_format, state->index_offset);

    wined3d_device_context_emit_set_predication(context, state->predicate, state->predicate_value);

    for (i = 0; i < WINED3D_SHADER_TYPE_COUNT; ++i)
    {
        wined3d_device_context_emit_set_shader(context, i, state->shader[i]);
        for (j = 0; j < MAX_CONSTANT_BUFFERS; ++j)
            wined3d_device_context_emit_set_constant_buffer(context, i, j, state->cb[i][j]);
        for (j = 0; j < MAX_SAMPLER_OBJECTS; ++j)
        {
            wined3d_device_context_emit_set_sampler(context, i, j, state->sampler[i][j]);
        }
        for (j = 0; j < MAX_SHADER_RESOURCE_VIEWS; ++j)
        {
            wined3d_device_context_emit_set_shader_resource_view(context, i, j, state->shader_resource_view[i][j]);
        }
    }

    for (i = 0; i < WINED3D_PIPELINE_COUNT; ++i)
    {
        for (j = 0; j < MAX_UNORDERED_ACCESS_VIEWS; ++j)
        {
            wined3d_device_context_emit_set_unordered_access_view(context, i, j,
                    state->unordered_access_view[i][j], ~0);
        }
    }

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_VS_F,
            0, WINED3D_MAX_VS_CONSTS_F, state->vs_consts_f);
    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_VS_I,
            0, WINED3D_MAX_CONSTS_I, state->vs_consts_i);
    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_VS_B,
            0, WINED3D_MAX_CONSTS_B, state->vs_consts_b);

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_PS_F,
            0, WINED3D_MAX_PS_CONSTS_F, state->ps_consts_f);
    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_PS_I,
            0, WINED3D_MAX_CONSTS_I, state->ps_consts_i);
    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_PS_B,
            0, WINED3D_MAX_CONSTS_B, state->ps_consts_b);

    for (i = 0; i < WINED3D_MAX_COMBINED_SAMPLERS; ++i)
    {
        wined3d_cs_emit_set_texture(device->cs, i, state->textures[i]);
        for (j = 0; j < WINED3D_HIGHEST_SAMPLER_STATE + 1; ++j)
        {
            wined3d_cs_emit_set_sampler_state(device->cs, i, j, state->sampler_states[i][j]);
        }
    }

    for (i = 0; i < WINED3D_MAX_TEXTURES; ++i)
    {
        for (j = 0; j < WINED3D_HIGHEST_TEXTURE_STATE + 1; ++j)
        {
            wined3d_cs_emit_set_texture_state(device->cs, i, j, state->texture_states[i][j]);
        }
    }

    for (i = 0; i < WINED3D_HIGHEST_TRANSFORM_STATE + 1; ++i)
    {
        wined3d_cs_emit_set_transform(device->cs, i, state->transforms + i);
    }

    for (i = 0; i < WINED3D_MAX_CLIP_DISTANCES; ++i)
    {
        wined3d_cs_emit_set_clip_plane(device->cs, i, state->clip_planes + i);
    }

    wined3d_cs_emit_set_material(device->cs, &state->material);

    wined3d_device_context_emit_set_viewports(context, state->viewport_count, state->viewports);
    wined3d_device_context_emit_set_scissor_rects(context, state->scissor_rect_count, state->scissor_rects);

    for (i = 0; i < LIGHTMAP_SIZE; ++i)
    {
        LIST_FOR_EACH_ENTRY(light, &state->light_state.light_map[i], struct wined3d_light_info, entry)
        {
            wined3d_device_set_light(device, light->OriginalIndex, &light->OriginalParms);
            wined3d_cs_emit_set_light_enable(device->cs, light->OriginalIndex, light->glIndex != -1);
        }
    }

    for (i = 0; i < WINEHIGHEST_RENDER_STATE + 1; ++i)
    {
        wined3d_cs_emit_set_render_state(device->cs, i, state->render_states[i]);
    }

    wined3d_device_context_emit_set_blend_state(context, state->blend_state, &state->blend_factor, state->sample_mask);
    wined3d_device_context_emit_set_depth_stencil_state(context, state->depth_stencil_state, state->stencil_ref);
    wined3d_device_context_emit_set_rasterizer_state(context, state->rasterizer_state);
}

struct wined3d_state * CDECL wined3d_device_get_state(struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->cs->c.state;
}

struct wined3d_device_context * CDECL wined3d_device_get_immediate_context(struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return &device->cs->c;
}

void CDECL wined3d_device_set_vertex_declaration(struct wined3d_device *device,
        struct wined3d_vertex_declaration *declaration)
{
    TRACE("device %p, declaration %p.\n", device, declaration);

    wined3d_device_context_set_vertex_declaration(&device->cs->c, declaration);
}

struct wined3d_vertex_declaration * CDECL wined3d_device_context_get_vertex_declaration(
        const struct wined3d_device_context *context)
{
    TRACE("context %p.\n", context);

    return context->state->vertex_declaration;
}

void CDECL wined3d_device_context_set_shader(struct wined3d_device_context *context,
        enum wined3d_shader_type type, struct wined3d_shader *shader)
{
    struct wined3d_state *state = context->state;
    struct wined3d_shader *prev;

    TRACE("context %p, type %#x, shader %p.\n", context, type, shader);

    prev = state->shader[type];
    if (shader == prev)
        return;

    if (shader)
        wined3d_shader_incref(shader);
    state->shader[type] = shader;
    wined3d_device_context_emit_set_shader(context, type, shader);
    if (prev)
        wined3d_shader_decref(prev);
}

struct wined3d_shader * CDECL wined3d_device_context_get_shader(const struct wined3d_device_context *context,
        enum wined3d_shader_type type)
{
    TRACE("context %p, type %#x.\n", context, type);

    return context->state->shader[type];
}

void CDECL wined3d_device_context_set_constant_buffer(struct wined3d_device_context *context,
        enum wined3d_shader_type type, unsigned int idx, struct wined3d_buffer *buffer)
{
    struct wined3d_state *state = context->state;
    struct wined3d_buffer *prev;

    TRACE("context %p, type %#x, idx %u, buffer %p.\n", context, type, idx, buffer);

    if (idx >= MAX_CONSTANT_BUFFERS)
    {
        WARN("Invalid constant buffer index %u.\n", idx);
        return;
    }

    prev = state->cb[type][idx];
    if (buffer == prev)
        return;

    if (buffer)
        wined3d_buffer_incref(buffer);
    state->cb[type][idx] = buffer;
    wined3d_device_context_emit_set_constant_buffer(context, type, idx, buffer);
    if (prev)
        wined3d_buffer_decref(prev);
}

void CDECL wined3d_device_context_set_blend_state(struct wined3d_device_context *context,
        struct wined3d_blend_state *blend_state, const struct wined3d_color *blend_factor, unsigned int sample_mask)
{
    struct wined3d_state *state = context->state;
    struct wined3d_blend_state *prev;

    TRACE("context %p, blend_state %p, blend_factor %p, sample_mask %#x.\n",
            context, blend_state, blend_factor, sample_mask);

    prev = state->blend_state;
    if (prev == blend_state && !memcmp(blend_factor, &state->blend_factor, sizeof(*blend_factor))
            && sample_mask == state->sample_mask)
        return;

    if (blend_state)
        wined3d_blend_state_incref(blend_state);
    state->blend_state = blend_state;
    state->blend_factor = *blend_factor;
    state->sample_mask = sample_mask;
    wined3d_device_context_emit_set_blend_state(context, blend_state, blend_factor, sample_mask);
    if (prev)
        wined3d_blend_state_decref(prev);
}

void CDECL wined3d_device_context_set_depth_stencil_state(struct wined3d_device_context *context,
        struct wined3d_depth_stencil_state *depth_stencil_state, unsigned int stencil_ref)
{
    struct wined3d_state *state = context->state;
    struct wined3d_depth_stencil_state *prev;

    TRACE("context %p, depth_stencil_state %p, stencil_ref %u.\n", context, depth_stencil_state, stencil_ref);

    prev = state->depth_stencil_state;
    if (prev == depth_stencil_state && state->stencil_ref == stencil_ref)
        return;

    if (depth_stencil_state)
        wined3d_depth_stencil_state_incref(depth_stencil_state);
    state->depth_stencil_state = depth_stencil_state;
    state->stencil_ref = stencil_ref;
    wined3d_device_context_emit_set_depth_stencil_state(context, depth_stencil_state, stencil_ref);
    if (prev)
        wined3d_depth_stencil_state_decref(prev);
}

void CDECL wined3d_device_context_set_rasterizer_state(struct wined3d_device_context *context,
        struct wined3d_rasterizer_state *rasterizer_state)
{
    struct wined3d_state *state = context->state;
    struct wined3d_rasterizer_state *prev;

    TRACE("context %p, rasterizer_state %p.\n", context, rasterizer_state);

    prev = state->rasterizer_state;
    if (prev == rasterizer_state)
        return;

    if (rasterizer_state)
        wined3d_rasterizer_state_incref(rasterizer_state);
    state->rasterizer_state = rasterizer_state;
    wined3d_device_context_emit_set_rasterizer_state(context, rasterizer_state);
    if (prev)
        wined3d_rasterizer_state_decref(prev);
}

void CDECL wined3d_device_context_set_viewports(struct wined3d_device_context *context, unsigned int viewport_count,
        const struct wined3d_viewport *viewports)
{
    struct wined3d_state *state = context->state;
    unsigned int i;

    TRACE("context %p, viewport_count %u, viewports %p.\n", context, viewport_count, viewports);

    for (i = 0; i < viewport_count; ++i)
    {
        TRACE("%u: x %.8e, y %.8e, w %.8e, h %.8e, min_z %.8e, max_z %.8e.\n",  i, viewports[i].x, viewports[i].y,
                viewports[i].width, viewports[i].height, viewports[i].min_z, viewports[i].max_z);
    }

    if (viewport_count)
        memcpy(state->viewports, viewports, viewport_count * sizeof(*viewports));
    else
        memset(state->viewports, 0, sizeof(state->viewports));
    state->viewport_count = viewport_count;

    wined3d_device_context_emit_set_viewports(context, viewport_count, viewports);
}

void CDECL wined3d_device_context_set_scissor_rects(struct wined3d_device_context *context, unsigned int rect_count,
        const RECT *rects)
{
    struct wined3d_state *state = context->state;
    unsigned int i;

    TRACE("context %p, rect_count %u, rects %p.\n", context, rect_count, rects);

    for (i = 0; i < rect_count; ++i)
    {
        TRACE("%u: %s\n", i, wine_dbgstr_rect(&rects[i]));
    }

    if (state->scissor_rect_count == rect_count
            && !memcmp(state->scissor_rects, rects, rect_count * sizeof(*rects)))
    {
        TRACE("App is setting the old scissor rectangles over, nothing to do.\n");
        return;
    }

    if (rect_count)
        memcpy(state->scissor_rects, rects, rect_count * sizeof(*rects));
    else
        memset(state->scissor_rects, 0, sizeof(state->scissor_rects));
    state->scissor_rect_count = rect_count;

    wined3d_device_context_emit_set_scissor_rects(context, rect_count, rects);
}

void CDECL wined3d_device_context_set_shader_resource_view(struct wined3d_device_context *context,
        enum wined3d_shader_type type, unsigned int idx, struct wined3d_shader_resource_view *view)
{
    struct wined3d_state *state = context->state;
    const struct wined3d_rendertarget_view *dsv;
    struct wined3d_shader_resource_view *prev;

    TRACE("context %p, type %#x, idx %u, view %p.\n", context, type, idx, view);

    if (idx >= MAX_SHADER_RESOURCE_VIEWS)
    {
        WARN("Invalid view index %u.\n", idx);
        return;
    }

    prev = state->shader_resource_view[type][idx];
    if (view == prev)
        return;

    if (view && (wined3d_is_srv_rtv_bound(view)
            || ((dsv = state->fb.depth_stencil)
            && dsv->resource == view->resource && wined3d_dsv_srv_conflict(dsv, view->format))))
    {
        WARN("Application is trying to bind resource which is attached as render target.\n");
        view = NULL;
    }

    if (view)
    {
        wined3d_shader_resource_view_incref(view);
        wined3d_srv_bind_count_inc(view);
    }

    state->shader_resource_view[type][idx] = view;
    wined3d_device_context_emit_set_shader_resource_view(context, type, idx, view);
    if (prev)
    {
        wined3d_srv_bind_count_dec(prev);
        wined3d_shader_resource_view_decref(prev);
    }
}

void CDECL wined3d_device_context_set_sampler(struct wined3d_device_context *context,
        enum wined3d_shader_type type, unsigned int idx, struct wined3d_sampler *sampler)
{
    struct wined3d_state *state = context->state;
    struct wined3d_sampler *prev;

    TRACE("context %p, type %#x, idx %u, sampler %p.\n", context, type, idx, sampler);

    if (idx >= MAX_SAMPLER_OBJECTS)
    {
        WARN("Invalid sampler index %u.\n", idx);
        return;
    }

    prev = state->sampler[type][idx];
    if (sampler == prev)
        return;

    if (sampler)
        wined3d_sampler_incref(sampler);
    state->sampler[type][idx] = sampler;
    wined3d_device_context_emit_set_sampler(context, type, idx, sampler);
    if (prev)
        wined3d_sampler_decref(prev);
}

void CDECL wined3d_device_context_set_unordered_access_view(struct wined3d_device_context *context,
        enum wined3d_pipeline pipeline, unsigned int idx, struct wined3d_unordered_access_view *uav,
        unsigned int initial_count)
{
    struct wined3d_state *state = context->state;
    struct wined3d_unordered_access_view *prev;

    TRACE("context %p, pipeline %#x, idx %u, uav %p, initial_count %u.\n", context, pipeline, idx, uav, initial_count);

    if (idx >= MAX_UNORDERED_ACCESS_VIEWS)
    {
        WARN("Invalid UAV index %u.\n", idx);
        return;
    }

    prev = state->unordered_access_view[pipeline][idx];
    if (uav == prev && initial_count == ~0u)
        return;

    if (uav)
        wined3d_unordered_access_view_incref(uav);
    state->unordered_access_view[pipeline][idx] = uav;
    wined3d_device_context_emit_set_unordered_access_view(context, pipeline, idx, uav, initial_count);
    if (prev)
        wined3d_unordered_access_view_decref(prev);
}

static void wined3d_device_context_unbind_srv_for_rtv(struct wined3d_device_context *context,
        const struct wined3d_rendertarget_view *view, BOOL dsv)
{
    struct wined3d_state *state = context->state;

    if (view && wined3d_is_rtv_srv_bound(view))
    {
        const struct wined3d_resource *resource = view->resource;
        const struct wined3d_shader_resource_view *srv;
        unsigned int i, j;

        WARN("Application sets bound resource as render target.\n");

        for (i = 0; i < WINED3D_SHADER_TYPE_COUNT; ++i)
            for (j = 0; j < MAX_SHADER_RESOURCE_VIEWS; ++j)
                if ((srv = state->shader_resource_view[i][j]) && srv->resource == resource
                        && ((!dsv && wined3d_is_srv_rtv_bound(srv))
                        || (dsv && wined3d_dsv_srv_conflict(view, srv->format))))
                    wined3d_device_context_set_shader_resource_view(context, i, j, NULL);
    }
}

HRESULT CDECL wined3d_device_context_set_rendertarget_view(struct wined3d_device_context *context,
        unsigned int view_idx, struct wined3d_rendertarget_view *view, BOOL set_viewport)
{
    struct wined3d_state *state = context->state;
    struct wined3d_rendertarget_view *prev;
    unsigned int max_rt_count;

    TRACE("context %p, view_idx %u, view %p, set_viewport %#x.\n",
            context, view_idx, view, set_viewport);

    max_rt_count = context->device->adapter->d3d_info.limits.max_rt_count;
    if (view_idx >= max_rt_count)
    {
        WARN("Only %u render targets are supported.\n", max_rt_count);
        return WINED3DERR_INVALIDCALL;
    }

    if (view && !(view->resource->bind_flags & WINED3D_BIND_RENDER_TARGET))
    {
        WARN("View resource %p doesn't have render target bind flags.\n", view->resource);
        return WINED3DERR_INVALIDCALL;
    }

    /* Set the viewport and scissor rectangles, if requested. Tests show that
     * stateblock recording is ignored, the change goes directly into the
     * primary stateblock. */
    if (!view_idx && set_viewport)
    {
        state->viewports[0].x = 0;
        state->viewports[0].y = 0;
        state->viewports[0].width = view->width;
        state->viewports[0].height = view->height;
        state->viewports[0].min_z = 0.0f;
        state->viewports[0].max_z = 1.0f;
        state->viewport_count = 1;
        wined3d_device_context_emit_set_viewports(context, 1, state->viewports);

        SetRect(&state->scissor_rects[0], 0, 0, view->width, view->height);
        state->scissor_rect_count = 1;
        wined3d_device_context_emit_set_scissor_rects(context, 1, state->scissor_rects);
    }

    prev = state->fb.render_targets[view_idx];
    if (view == prev)
        return WINED3D_OK;

    if (view)
    {
        wined3d_rendertarget_view_incref(view);
        wined3d_rtv_bind_count_inc(view);
    }
    state->fb.render_targets[view_idx] = view;
    wined3d_device_context_emit_set_rendertarget_view(context, view_idx, view);
    /* Release after the assignment, to prevent device_resource_released()
     * from seeing the surface as still in use. */
    if (prev)
    {
        wined3d_rtv_bind_count_dec(prev);
        wined3d_rendertarget_view_decref(prev);
    }

    wined3d_device_context_unbind_srv_for_rtv(context, view, FALSE);

    return WINED3D_OK;
}

HRESULT CDECL wined3d_device_context_set_depth_stencil_view(struct wined3d_device_context *context,
        struct wined3d_rendertarget_view *view)
{
    struct wined3d_fb_state *fb = &context->state->fb;
    struct wined3d_rendertarget_view *prev;

    TRACE("context %p, view %p.\n", context, view);

    if (view && !(view->resource->bind_flags & WINED3D_BIND_DEPTH_STENCIL))
    {
        WARN("View resource %p has incompatible %s bind flags.\n",
                view->resource, wined3d_debug_bind_flags(view->resource->bind_flags));
        return WINED3DERR_INVALIDCALL;
    }

    prev = fb->depth_stencil;
    if (prev == view)
    {
        TRACE("Trying to do a NOP SetRenderTarget operation.\n");
        return WINED3D_OK;
    }

    if ((fb->depth_stencil = view))
        wined3d_rendertarget_view_incref(view);
    wined3d_device_context_emit_set_depth_stencil_view(context, view);
    if (prev)
        wined3d_rendertarget_view_decref(prev);
    wined3d_device_context_unbind_srv_for_rtv(context, view, TRUE);

    return WINED3D_OK;
}

void CDECL wined3d_device_context_set_predication(struct wined3d_device_context *context,
        struct wined3d_query *predicate, BOOL value)
{
    struct wined3d_state *state = context->state;
    struct wined3d_query *prev;

    TRACE("context %p, predicate %p, value %#x.\n", context, predicate, value);

    prev = state->predicate;
    if (predicate)
    {
        FIXME("Predicated rendering not implemented.\n");
        wined3d_query_incref(predicate);
    }
    state->predicate = predicate;
    state->predicate_value = value;
    wined3d_device_context_emit_set_predication(context, predicate, value);
    if (prev)
        wined3d_query_decref(prev);
}

HRESULT CDECL wined3d_device_context_set_stream_source(struct wined3d_device_context *context,
        unsigned int stream_idx, struct wined3d_buffer *buffer, unsigned int offset, unsigned int stride)
{
    struct wined3d_stream_state *stream;
    struct wined3d_buffer *prev_buffer;

    TRACE("context %p, stream_idx %u, buffer %p, offset %u, stride %u.\n",
            context, stream_idx, buffer, offset, stride);

    if (stream_idx >= WINED3D_MAX_STREAMS)
    {
        WARN("Stream index %u out of range.\n", stream_idx);
        return WINED3DERR_INVALIDCALL;
    }
    else if (offset & 0x3)
    {
        WARN("Offset %u is not 4 byte aligned.\n", offset);
        return WINED3DERR_INVALIDCALL;
    }

    stream = &context->state->streams[stream_idx];
    prev_buffer = stream->buffer;

    if (prev_buffer == buffer
            && stream->stride == stride
            && stream->offset == offset)
    {
       TRACE("Application is setting the old values over, nothing to do.\n");
       return WINED3D_OK;
    }

    stream->buffer = buffer;
    stream->stride = stride;
    stream->offset = offset;
    if (buffer)
        wined3d_buffer_incref(buffer);
    wined3d_device_context_emit_set_stream_source(context, stream_idx, buffer, offset, stride);
    if (prev_buffer)
        wined3d_buffer_decref(prev_buffer);

    return WINED3D_OK;
}

void CDECL wined3d_device_context_set_index_buffer(struct wined3d_device_context *context,
        struct wined3d_buffer *buffer, enum wined3d_format_id format_id, unsigned int offset)
{
    struct wined3d_state *state = context->state;
    enum wined3d_format_id prev_format;
    struct wined3d_buffer *prev_buffer;
    unsigned int prev_offset;

    TRACE("context %p, buffer %p, format %s, offset %u.\n",
            context, buffer, debug_d3dformat(format_id), offset);

    prev_buffer = state->index_buffer;
    prev_format = state->index_format;
    prev_offset = state->index_offset;

    if (prev_buffer == buffer && prev_format == format_id && prev_offset == offset)
        return;

    if (buffer)
        wined3d_buffer_incref(buffer);
    state->index_buffer = buffer;
    state->index_format = format_id;
    state->index_offset = offset;
    wined3d_device_context_emit_set_index_buffer(context, buffer, format_id, offset);
    if (prev_buffer)
        wined3d_buffer_decref(prev_buffer);
}

void CDECL wined3d_device_context_set_vertex_declaration(struct wined3d_device_context *context,
        struct wined3d_vertex_declaration *declaration)
{
    struct wined3d_state *state = context->state;
    struct wined3d_vertex_declaration *prev;

    TRACE("context %p, declaration %p.\n", context, declaration);

    prev = state->vertex_declaration;
    if (declaration == prev)
        return;

    if (declaration)
        wined3d_vertex_declaration_incref(declaration);
    state->vertex_declaration = declaration;
    wined3d_device_context_emit_set_vertex_declaration(context, declaration);
    if (prev)
        wined3d_vertex_declaration_decref(prev);
}

void CDECL wined3d_device_context_set_stream_output(struct wined3d_device_context *context, unsigned int idx,
        struct wined3d_buffer *buffer, unsigned int offset)
{
    struct wined3d_stream_output *stream;
    struct wined3d_buffer *prev_buffer;

    TRACE("context %p, idx %u, buffer %p, offset %u.\n", context, idx, buffer, offset);

    if (idx >= WINED3D_MAX_STREAM_OUTPUT_BUFFERS)
    {
        WARN("Invalid stream output %u.\n", idx);
        return;
    }

    stream = &context->state->stream_output[idx];
    prev_buffer = stream->buffer;

    if (buffer)
        wined3d_buffer_incref(buffer);
    stream->buffer = buffer;
    stream->offset = offset;
    wined3d_device_context_emit_set_stream_output(context, idx, buffer, offset);
    if (prev_buffer)
        wined3d_buffer_decref(prev_buffer);
}

void CDECL wined3d_device_context_draw(struct wined3d_device_context *context, unsigned int start_vertex,
        unsigned int vertex_count, unsigned int start_instance, unsigned int instance_count)
{
    struct wined3d_state *state = context->state;

    TRACE("context %p, start_vertex %u, vertex_count %u, start_instance %u, instance_count %u.\n",
            context, start_vertex, vertex_count, start_instance, instance_count);

    wined3d_device_context_emit_draw(context, state->primitive_type, state->patch_vertex_count,
            0, start_vertex, vertex_count, start_instance, instance_count, false);
}

void CDECL wined3d_device_context_draw_indexed(struct wined3d_device_context *context, int base_vertex_index,
        unsigned int start_index, unsigned int index_count, unsigned int start_instance, unsigned int instance_count)
{
    struct wined3d_state *state = context->state;

    TRACE("context %p, base_vertex_index %d, start_index %u, index_count %u, start_instance %u, instance_count %u.\n",
            context, base_vertex_index, start_index, index_count, start_instance, instance_count);

    wined3d_device_context_emit_draw(context, state->primitive_type, state->patch_vertex_count,
            base_vertex_index, start_index, index_count, start_instance, instance_count, true);
}

void CDECL wined3d_device_set_vertex_shader(struct wined3d_device *device, struct wined3d_shader *shader)
{
    TRACE("device %p, shader %p.\n", device, shader);

    return wined3d_device_context_set_shader(&device->cs->c, WINED3D_SHADER_TYPE_VERTEX, shader);
}

struct wined3d_shader * CDECL wined3d_device_get_vertex_shader(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->cs->c.state->shader[WINED3D_SHADER_TYPE_VERTEX];
}

void CDECL wined3d_device_set_constant_buffer(struct wined3d_device *device,
        enum wined3d_shader_type type, UINT idx, struct wined3d_buffer *buffer)
{
    TRACE("device %p, type %#x, idx %u, buffer %p.\n", device, type, idx, buffer);

    return wined3d_device_context_set_constant_buffer(&device->cs->c, type, idx, buffer);
}

struct wined3d_buffer * CDECL wined3d_device_context_get_constant_buffer(const struct wined3d_device_context *context,
        enum wined3d_shader_type shader_type, unsigned int idx)
{
    TRACE("context %p, shader_type %#x, idx %u.\n", context, shader_type, idx);

    if (idx >= MAX_CONSTANT_BUFFERS)
    {
        WARN("Invalid constant buffer index %u.\n", idx);
        return NULL;
    }

    return context->state->cb[shader_type][idx];
}

void CDECL wined3d_device_set_vs_resource_view(struct wined3d_device *device,
        UINT idx, struct wined3d_shader_resource_view *view)
{
    TRACE("device %p, idx %u, view %p.\n", device, idx, view);

    wined3d_device_context_set_shader_resource_view(&device->cs->c, WINED3D_SHADER_TYPE_VERTEX, idx, view);
}

struct wined3d_shader_resource_view * CDECL wined3d_device_context_get_shader_resource_view(
        const struct wined3d_device_context *context, enum wined3d_shader_type shader_type, unsigned int idx)
{
    if (idx >= MAX_SHADER_RESOURCE_VIEWS)
    {
        WARN("Invalid view index %u.\n", idx);
        return NULL;
    }

    return context->state->shader_resource_view[shader_type][idx];
}

static struct wined3d_shader_resource_view *wined3d_device_get_shader_resource_view(
        const struct wined3d_device *device, enum wined3d_shader_type shader_type, unsigned int idx)
{
    if (idx >= MAX_SHADER_RESOURCE_VIEWS)
    {
        WARN("Invalid view index %u.\n", idx);
        return NULL;
    }

    return device->cs->c.state->shader_resource_view[shader_type][idx];
}

struct wined3d_shader_resource_view * CDECL wined3d_device_get_vs_resource_view(const struct wined3d_device *device,
        UINT idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_shader_resource_view(device, WINED3D_SHADER_TYPE_VERTEX, idx);
}

void CDECL wined3d_device_set_vs_sampler(struct wined3d_device *device, UINT idx, struct wined3d_sampler *sampler)
{
    TRACE("device %p, idx %u, sampler %p.\n", device, idx, sampler);

    wined3d_device_context_set_sampler(&device->cs->c, WINED3D_SHADER_TYPE_VERTEX, idx, sampler);
}

struct wined3d_sampler * CDECL wined3d_device_context_get_sampler(const struct wined3d_device_context *context,
        enum wined3d_shader_type shader_type, unsigned int idx)
{
    TRACE("context %p, shader_type %#x, idx %u.\n", context, shader_type, idx);

    if (idx >= MAX_SAMPLER_OBJECTS)
    {
        WARN("Invalid sampler index %u.\n", idx);
        return NULL;
    }

    return context->state->sampler[shader_type][idx];
}

static struct wined3d_sampler *wined3d_device_get_sampler(const struct wined3d_device *device,
        enum wined3d_shader_type shader_type, unsigned int idx)
{
    if (idx >= MAX_SAMPLER_OBJECTS)
    {
        WARN("Invalid sampler index %u.\n", idx);
        return NULL;
    }

    return device->cs->c.state->sampler[shader_type][idx];
}

struct wined3d_sampler * CDECL wined3d_device_get_vs_sampler(const struct wined3d_device *device, UINT idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_sampler(device, WINED3D_SHADER_TYPE_VERTEX, idx);
}

static void wined3d_device_set_vs_consts_b(struct wined3d_device *device,
        unsigned int start_idx, unsigned int count, const BOOL *constants)
{
    unsigned int i;

    TRACE("device %p, start_idx %u, count %u, constants %p.\n",
            device, start_idx, count, constants);

    memcpy(&device->cs->c.state->vs_consts_b[start_idx], constants, count * sizeof(*constants));
    if (TRACE_ON(d3d))
    {
        for (i = 0; i < count; ++i)
            TRACE("Set BOOL constant %u to %#x.\n", start_idx + i, constants[i]);
    }

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_VS_B, start_idx, count, constants);
}

static void wined3d_device_set_vs_consts_i(struct wined3d_device *device,
        unsigned int start_idx, unsigned int count, const struct wined3d_ivec4 *constants)
{
    unsigned int i;

    TRACE("device %p, start_idx %u, count %u, constants %p.\n",
            device, start_idx, count, constants);

    memcpy(&device->cs->c.state->vs_consts_i[start_idx], constants, count * sizeof(*constants));
    if (TRACE_ON(d3d))
    {
        for (i = 0; i < count; ++i)
            TRACE("Set ivec4 constant %u to %s.\n", start_idx + i, debug_ivec4(&constants[i]));
    }

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_VS_I, start_idx, count, constants);
}

static void wined3d_device_set_vs_consts_f(struct wined3d_device *device,
        unsigned int start_idx, unsigned int count, const struct wined3d_vec4 *constants)
{
    unsigned int i;

    TRACE("device %p, start_idx %u, count %u, constants %p.\n",
            device, start_idx, count, constants);

    memcpy(&device->cs->c.state->vs_consts_f[start_idx], constants, count * sizeof(*constants));
    if (TRACE_ON(d3d))
    {
        for (i = 0; i < count; ++i)
            TRACE("Set vec4 constant %u to %s.\n", start_idx + i, debug_vec4(&constants[i]));
    }

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_VS_F, start_idx, count, constants);
}

void CDECL wined3d_device_set_pixel_shader(struct wined3d_device *device, struct wined3d_shader *shader)
{
    TRACE("device %p, shader %p.\n", device, shader);

    return wined3d_device_context_set_shader(&device->cs->c, WINED3D_SHADER_TYPE_PIXEL, shader);
}

struct wined3d_shader * CDECL wined3d_device_get_pixel_shader(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->cs->c.state->shader[WINED3D_SHADER_TYPE_PIXEL];
}

void CDECL wined3d_device_set_ps_resource_view(struct wined3d_device *device,
        UINT idx, struct wined3d_shader_resource_view *view)
{
    TRACE("device %p, idx %u, view %p.\n", device, idx, view);

    wined3d_device_context_set_shader_resource_view(&device->cs->c, WINED3D_SHADER_TYPE_PIXEL, idx, view);
}

struct wined3d_shader_resource_view * CDECL wined3d_device_get_ps_resource_view(const struct wined3d_device *device,
        UINT idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_shader_resource_view(device, WINED3D_SHADER_TYPE_PIXEL, idx);
}

void CDECL wined3d_device_set_ps_sampler(struct wined3d_device *device, UINT idx, struct wined3d_sampler *sampler)
{
    TRACE("device %p, idx %u, sampler %p.\n", device, idx, sampler);

    wined3d_device_context_set_sampler(&device->cs->c, WINED3D_SHADER_TYPE_PIXEL, idx, sampler);
}

struct wined3d_sampler * CDECL wined3d_device_get_ps_sampler(const struct wined3d_device *device, UINT idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_sampler(device, WINED3D_SHADER_TYPE_PIXEL, idx);
}

static void wined3d_device_set_ps_consts_b(struct wined3d_device *device,
        unsigned int start_idx, unsigned int count, const BOOL *constants)
{
    unsigned int i;

    TRACE("device %p, start_idx %u, count %u, constants %p.\n",
            device, start_idx, count, constants);

    memcpy(&device->cs->c.state->ps_consts_b[start_idx], constants, count * sizeof(*constants));
    if (TRACE_ON(d3d))
    {
        for (i = 0; i < count; ++i)
            TRACE("Set BOOL constant %u to %#x.\n", start_idx + i, constants[i]);
    }

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_PS_B, start_idx, count, constants);
}

static void wined3d_device_set_ps_consts_i(struct wined3d_device *device,
        unsigned int start_idx, unsigned int count, const struct wined3d_ivec4 *constants)
{
    unsigned int i;

    TRACE("device %p, start_idx %u, count %u, constants %p.\n",
            device, start_idx, count, constants);

    memcpy(&device->cs->c.state->ps_consts_i[start_idx], constants, count * sizeof(*constants));
    if (TRACE_ON(d3d))
    {
        for (i = 0; i < count; ++i)
            TRACE("Set ivec4 constant %u to %s.\n", start_idx + i, debug_ivec4(&constants[i]));
    }

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_PS_I, start_idx, count, constants);
}

static void wined3d_device_set_ps_consts_f(struct wined3d_device *device,
        unsigned int start_idx, unsigned int count, const struct wined3d_vec4 *constants)
{
    unsigned int i;

    TRACE("device %p, start_idx %u, count %u, constants %p.\n",
            device, start_idx, count, constants);

    memcpy(&device->cs->c.state->ps_consts_f[start_idx], constants, count * sizeof(*constants));
    if (TRACE_ON(d3d))
    {
        for (i = 0; i < count; ++i)
            TRACE("Set vec4 constant %u to %s.\n", start_idx + i, debug_vec4(&constants[i]));
    }

    wined3d_cs_push_constants(device->cs, WINED3D_PUSH_CONSTANTS_PS_F, start_idx, count, constants);
}

void CDECL wined3d_device_set_hull_shader(struct wined3d_device *device, struct wined3d_shader *shader)
{
    TRACE("device %p, shader %p.\n", device, shader);

    return wined3d_device_context_set_shader(&device->cs->c, WINED3D_SHADER_TYPE_HULL, shader);
}

struct wined3d_shader * CDECL wined3d_device_get_hull_shader(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->cs->c.state->shader[WINED3D_SHADER_TYPE_HULL];
}

void CDECL wined3d_device_set_hs_resource_view(struct wined3d_device *device,
        unsigned int idx, struct wined3d_shader_resource_view *view)
{
    TRACE("device %p, idx %u, view %p.\n", device, idx, view);

    wined3d_device_context_set_shader_resource_view(&device->cs->c, WINED3D_SHADER_TYPE_HULL, idx, view);
}

struct wined3d_shader_resource_view * CDECL wined3d_device_get_hs_resource_view(const struct wined3d_device *device,
        unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_shader_resource_view(device, WINED3D_SHADER_TYPE_HULL, idx);
}

void CDECL wined3d_device_set_hs_sampler(struct wined3d_device *device,
        unsigned int idx, struct wined3d_sampler *sampler)
{
    TRACE("device %p, idx %u, sampler %p.\n", device, idx, sampler);

    wined3d_device_context_set_sampler(&device->cs->c, WINED3D_SHADER_TYPE_HULL, idx, sampler);
}

struct wined3d_sampler * CDECL wined3d_device_get_hs_sampler(const struct wined3d_device *device, unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_sampler(device, WINED3D_SHADER_TYPE_HULL, idx);
}

void CDECL wined3d_device_set_domain_shader(struct wined3d_device *device, struct wined3d_shader *shader)
{
    TRACE("device %p, shader %p.\n", device, shader);

    return wined3d_device_context_set_shader(&device->cs->c, WINED3D_SHADER_TYPE_DOMAIN, shader);
}

struct wined3d_shader * CDECL wined3d_device_get_domain_shader(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->cs->c.state->shader[WINED3D_SHADER_TYPE_DOMAIN];
}

void CDECL wined3d_device_set_ds_resource_view(struct wined3d_device *device,
        unsigned int idx, struct wined3d_shader_resource_view *view)
{
    TRACE("device %p, idx %u, view %p.\n", device, idx, view);

    wined3d_device_context_set_shader_resource_view(&device->cs->c, WINED3D_SHADER_TYPE_DOMAIN, idx, view);
}

struct wined3d_shader_resource_view * CDECL wined3d_device_get_ds_resource_view(const struct wined3d_device *device,
        unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_shader_resource_view(device, WINED3D_SHADER_TYPE_DOMAIN, idx);
}

void CDECL wined3d_device_set_ds_sampler(struct wined3d_device *device,
        unsigned int idx, struct wined3d_sampler *sampler)
{
    TRACE("device %p, idx %u, sampler %p.\n", device, idx, sampler);

    wined3d_device_context_set_sampler(&device->cs->c, WINED3D_SHADER_TYPE_DOMAIN, idx, sampler);
}

struct wined3d_sampler * CDECL wined3d_device_get_ds_sampler(const struct wined3d_device *device, unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_sampler(device, WINED3D_SHADER_TYPE_DOMAIN, idx);
}

void CDECL wined3d_device_set_geometry_shader(struct wined3d_device *device, struct wined3d_shader *shader)
{
    TRACE("device %p, shader %p.\n", device, shader);

    return wined3d_device_context_set_shader(&device->cs->c, WINED3D_SHADER_TYPE_GEOMETRY, shader);
}

struct wined3d_shader * CDECL wined3d_device_get_geometry_shader(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->cs->c.state->shader[WINED3D_SHADER_TYPE_GEOMETRY];
}

void CDECL wined3d_device_set_gs_resource_view(struct wined3d_device *device,
        UINT idx, struct wined3d_shader_resource_view *view)
{
    TRACE("device %p, idx %u, view %p.\n", device, idx, view);

    wined3d_device_context_set_shader_resource_view(&device->cs->c, WINED3D_SHADER_TYPE_GEOMETRY, idx, view);
}

struct wined3d_shader_resource_view * CDECL wined3d_device_get_gs_resource_view(const struct wined3d_device *device,
        UINT idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_shader_resource_view(device, WINED3D_SHADER_TYPE_GEOMETRY, idx);
}

void CDECL wined3d_device_set_gs_sampler(struct wined3d_device *device, UINT idx, struct wined3d_sampler *sampler)
{
    TRACE("device %p, idx %u, sampler %p.\n", device, idx, sampler);

    wined3d_device_context_set_sampler(&device->cs->c, WINED3D_SHADER_TYPE_GEOMETRY, idx, sampler);
}

struct wined3d_sampler * CDECL wined3d_device_get_gs_sampler(const struct wined3d_device *device, UINT idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_sampler(device, WINED3D_SHADER_TYPE_GEOMETRY, idx);
}

void CDECL wined3d_device_set_compute_shader(struct wined3d_device *device, struct wined3d_shader *shader)
{
    TRACE("device %p, shader %p.\n", device, shader);

    return wined3d_device_context_set_shader(&device->cs->c, WINED3D_SHADER_TYPE_COMPUTE, shader);
}

struct wined3d_shader * CDECL wined3d_device_get_compute_shader(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->cs->c.state->shader[WINED3D_SHADER_TYPE_COMPUTE];
}

void CDECL wined3d_device_set_cs_resource_view(struct wined3d_device *device,
        unsigned int idx, struct wined3d_shader_resource_view *view)
{
    TRACE("device %p, idx %u, view %p.\n", device, idx, view);

    wined3d_device_context_set_shader_resource_view(&device->cs->c, WINED3D_SHADER_TYPE_COMPUTE, idx, view);
}

struct wined3d_shader_resource_view * CDECL wined3d_device_get_cs_resource_view(const struct wined3d_device *device,
        unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_shader_resource_view(device, WINED3D_SHADER_TYPE_COMPUTE, idx);
}

void CDECL wined3d_device_set_cs_sampler(struct wined3d_device *device,
        unsigned int idx, struct wined3d_sampler *sampler)
{
    TRACE("device %p, idx %u, sampler %p.\n", device, idx, sampler);

    wined3d_device_context_set_sampler(&device->cs->c, WINED3D_SHADER_TYPE_COMPUTE, idx, sampler);
}

struct wined3d_sampler * CDECL wined3d_device_get_cs_sampler(const struct wined3d_device *device, unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_sampler(device, WINED3D_SHADER_TYPE_COMPUTE, idx);
}

struct wined3d_unordered_access_view * CDECL wined3d_device_context_get_unordered_access_view(
        const struct wined3d_device_context *context, enum wined3d_pipeline pipeline, unsigned int idx)
{
    TRACE("context %p, pipeline %#x, idx %u.\n", context, pipeline, idx);

    if (idx >= MAX_UNORDERED_ACCESS_VIEWS)
    {
        WARN("Invalid UAV index %u.\n", idx);
        return NULL;
    }

    return context->state->unordered_access_view[pipeline][idx];
}

static struct wined3d_unordered_access_view *wined3d_device_get_pipeline_unordered_access_view(
        const struct wined3d_device *device, enum wined3d_pipeline pipeline, unsigned int idx)
{
    if (idx >= MAX_UNORDERED_ACCESS_VIEWS)
    {
        WARN("Invalid UAV index %u.\n", idx);
        return NULL;
    }

    return device->cs->c.state->unordered_access_view[pipeline][idx];
}

void CDECL wined3d_device_set_cs_uav(struct wined3d_device *device, unsigned int idx,
        struct wined3d_unordered_access_view *uav, unsigned int initial_count)
{
    TRACE("device %p, idx %u, uav %p, initial_count %#x.\n", device, idx, uav, initial_count);

    wined3d_device_context_set_unordered_access_view(&device->cs->c, WINED3D_PIPELINE_COMPUTE, idx, uav, initial_count);
}

struct wined3d_unordered_access_view * CDECL wined3d_device_get_cs_uav(const struct wined3d_device *device,
        unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_pipeline_unordered_access_view(device, WINED3D_PIPELINE_COMPUTE, idx);
}

void CDECL wined3d_device_set_unordered_access_view(struct wined3d_device *device,
        unsigned int idx, struct wined3d_unordered_access_view *uav, unsigned int initial_count)
{
    TRACE("device %p, idx %u, uav %p, initial_count %#x.\n", device, idx, uav, initial_count);

    wined3d_device_context_set_unordered_access_view(&device->cs->c, WINED3D_PIPELINE_GRAPHICS, idx, uav, initial_count);
}

struct wined3d_unordered_access_view * CDECL wined3d_device_get_unordered_access_view(
        const struct wined3d_device *device, unsigned int idx)
{
    TRACE("device %p, idx %u.\n", device, idx);

    return wined3d_device_get_pipeline_unordered_access_view(device, WINED3D_PIPELINE_GRAPHICS, idx);
}

void CDECL wined3d_device_set_max_frame_latency(struct wined3d_device *device, unsigned int latency)
{
    unsigned int i;

    if (!latency)
        latency = 3;

    device->max_frame_latency = latency;
    for (i = 0; i < device->swapchain_count; ++i)
        swapchain_set_max_frame_latency(device->swapchains[i], device);
}

unsigned int CDECL wined3d_device_get_max_frame_latency(const struct wined3d_device *device)
{
    return device->max_frame_latency;
}

static unsigned int wined3d_get_flexible_vertex_size(DWORD fvf)
{
    unsigned int texcoord_count = (fvf & WINED3DFVF_TEXCOUNT_MASK) >> WINED3DFVF_TEXCOUNT_SHIFT;
    unsigned int i, size = 0;

    if (fvf & WINED3DFVF_NORMAL) size += 3 * sizeof(float);
    if (fvf & WINED3DFVF_DIFFUSE) size += sizeof(DWORD);
    if (fvf & WINED3DFVF_SPECULAR) size += sizeof(DWORD);
    if (fvf & WINED3DFVF_PSIZE) size += sizeof(DWORD);
    switch (fvf & WINED3DFVF_POSITION_MASK)
    {
        case WINED3DFVF_XYZ:    size += 3 * sizeof(float); break;
        case WINED3DFVF_XYZRHW: size += 4 * sizeof(float); break;
        case WINED3DFVF_XYZB1:  size += 4 * sizeof(float); break;
        case WINED3DFVF_XYZB2:  size += 5 * sizeof(float); break;
        case WINED3DFVF_XYZB3:  size += 6 * sizeof(float); break;
        case WINED3DFVF_XYZB4:  size += 7 * sizeof(float); break;
        case WINED3DFVF_XYZB5:  size += 8 * sizeof(float); break;
        case WINED3DFVF_XYZW:   size += 4 * sizeof(float); break;
        default: FIXME("Unexpected position mask %#x.\n", fvf & WINED3DFVF_POSITION_MASK);
    }
    for (i = 0; i < texcoord_count; ++i)
    {
        size += GET_TEXCOORD_SIZE_FROM_FVF(fvf, i) * sizeof(float);
    }

    return size;
}

static void wined3d_format_get_colour(const struct wined3d_format *format,
        const void *data, struct wined3d_color *colour)
{
    float *output = &colour->r;
    const uint32_t *u32_data;
    const uint16_t *u16_data;
    const float *f32_data;
    unsigned int i;

    static const struct wined3d_color default_colour = {0.0f, 0.0f, 0.0f, 1.0f};
    static unsigned int warned;

    switch (format->id)
    {
        case WINED3DFMT_B8G8R8A8_UNORM:
            u32_data = data;
            wined3d_color_from_d3dcolor(colour, *u32_data);
            break;

        case WINED3DFMT_R8G8B8A8_UNORM:
            u32_data = data;
            colour->r = (*u32_data & 0xffu) / 255.0f;
            colour->g = ((*u32_data >> 8) & 0xffu) / 255.0f;
            colour->b = ((*u32_data >> 16) & 0xffu) / 255.0f;
            colour->a = ((*u32_data >> 24) & 0xffu) / 255.0f;
            break;

        case WINED3DFMT_R16G16_UNORM:
        case WINED3DFMT_R16G16B16A16_UNORM:
            u16_data = data;
            *colour = default_colour;
            for (i = 0; i < format->component_count; ++i)
                output[i] = u16_data[i] / 65535.0f;
            break;

        case WINED3DFMT_R32_FLOAT:
        case WINED3DFMT_R32G32_FLOAT:
        case WINED3DFMT_R32G32B32_FLOAT:
        case WINED3DFMT_R32G32B32A32_FLOAT:
            f32_data = data;
            *colour = default_colour;
            for (i = 0; i < format->component_count; ++i)
                output[i] = f32_data[i];
            break;

        default:
            *colour = default_colour;
            if (!warned++)
                FIXME("Unhandled colour format conversion, format %s.\n", debug_d3dformat(format->id));
            break;
    }
}

static void wined3d_colour_from_mcs(struct wined3d_color *colour, enum wined3d_material_color_source mcs,
        const struct wined3d_color *material_colour, unsigned int index,
        const struct wined3d_stream_info *stream_info)
{
    const struct wined3d_stream_info_element *element = NULL;

    switch (mcs)
    {
        case WINED3D_MCS_MATERIAL:
            *colour = *material_colour;
            return;

        case WINED3D_MCS_COLOR1:
            if (!(stream_info->use_map & (1u << WINED3D_FFP_DIFFUSE)))
            {
                colour->r = colour->g = colour->b = colour->a = 1.0f;
                return;
            }
            element = &stream_info->elements[WINED3D_FFP_DIFFUSE];
            break;

        case WINED3D_MCS_COLOR2:
            if (!(stream_info->use_map & (1u << WINED3D_FFP_SPECULAR)))
            {
                colour->r = colour->g = colour->b = colour->a = 0.0f;
                return;
            }
            element = &stream_info->elements[WINED3D_FFP_SPECULAR];
            break;

        default:
            colour->r = colour->g = colour->b = colour->a = 0.0f;
            ERR("Invalid material colour source %#x.\n", mcs);
            return;
    }

    wined3d_format_get_colour(element->format, &element->data.addr[index * element->stride], colour);
}

static float wined3d_clamp(float value, float min_value, float max_value)
{
    return value < min_value ? min_value : value > max_value ? max_value : value;
}

static float wined3d_vec3_dot(const struct wined3d_vec3 *v0, const struct wined3d_vec3 *v1)
{
    return v0->x * v1->x + v0->y * v1->y + v0->z * v1->z;
}

static void wined3d_vec3_subtract(struct wined3d_vec3 *v0, const struct wined3d_vec3 *v1)
{
    v0->x -= v1->x;
    v0->y -= v1->y;
    v0->z -= v1->z;
}

static void wined3d_vec3_scale(struct wined3d_vec3 *v, float s)
{
    v->x *= s;
    v->y *= s;
    v->z *= s;
}

static void wined3d_vec3_normalise(struct wined3d_vec3 *v)
{
    float rnorm = 1.0f / sqrtf(wined3d_vec3_dot(v, v));

    if (isfinite(rnorm))
        wined3d_vec3_scale(v, rnorm);
}

static void wined3d_vec3_transform(struct wined3d_vec3 *dst,
        const struct wined3d_vec3 *v, const struct wined3d_matrix_3x3 *m)
{
    struct wined3d_vec3 tmp;

    tmp.x = v->x * m->_11 + v->y * m->_21 + v->z * m->_31;
    tmp.y = v->x * m->_12 + v->y * m->_22 + v->z * m->_32;
    tmp.z = v->x * m->_13 + v->y * m->_23 + v->z * m->_33;

    *dst = tmp;
}

static void wined3d_color_clamp(struct wined3d_color *dst, const struct wined3d_color *src,
        float min_value, float max_value)
{
    dst->r = wined3d_clamp(src->r, min_value, max_value);
    dst->g = wined3d_clamp(src->g, min_value, max_value);
    dst->b = wined3d_clamp(src->b, min_value, max_value);
    dst->a = wined3d_clamp(src->a, min_value, max_value);
}

static void wined3d_color_rgb_mul_add(struct wined3d_color *dst, const struct wined3d_color *src, float c)
{
    dst->r += src->r * c;
    dst->g += src->g * c;
    dst->b += src->b * c;
}

static void init_transformed_lights(struct lights_settings *ls,
        const struct wined3d_state *state, BOOL legacy_lighting, BOOL compute_lighting)
{
    const struct wined3d_light_info *lights[WINED3D_MAX_SOFTWARE_ACTIVE_LIGHTS];
    const struct wined3d_light_info *light_info;
    struct light_transformed *light;
    struct wined3d_vec4 vec4;
    unsigned int light_count;
    unsigned int i, index;

    memset(ls, 0, sizeof(*ls));

    ls->lighting = !!compute_lighting;
    ls->fog_mode = state->render_states[WINED3D_RS_FOGVERTEXMODE];
    ls->fog_coord_mode = state->render_states[WINED3D_RS_RANGEFOGENABLE]
            ? WINED3D_FFP_VS_FOG_RANGE : WINED3D_FFP_VS_FOG_DEPTH;
    ls->fog_start = wined3d_get_float_state(state, WINED3D_RS_FOGSTART);
    ls->fog_end = wined3d_get_float_state(state, WINED3D_RS_FOGEND);
    ls->fog_density = wined3d_get_float_state(state, WINED3D_RS_FOGDENSITY);

    if (ls->fog_mode == WINED3D_FOG_NONE && !compute_lighting)
        return;

    multiply_matrix(&ls->modelview_matrix, &state->transforms[WINED3D_TS_VIEW],
            &state->transforms[WINED3D_TS_WORLD_MATRIX(0)]);

    if (!compute_lighting)
        return;

    compute_normal_matrix(&ls->normal_matrix._11, legacy_lighting, &ls->modelview_matrix);

    wined3d_color_from_d3dcolor(&ls->ambient_light, state->render_states[WINED3D_RS_AMBIENT]);
    ls->legacy_lighting = !!legacy_lighting;
    ls->normalise = !!state->render_states[WINED3D_RS_NORMALIZENORMALS];
    ls->localviewer = !!state->render_states[WINED3D_RS_LOCALVIEWER];

    for (i = 0, index = 0; i < LIGHTMAP_SIZE && index < ARRAY_SIZE(lights); ++i)
    {
        LIST_FOR_EACH_ENTRY(light_info, &state->light_state.light_map[i], struct wined3d_light_info, entry)
        {
            if (!light_info->enabled)
                continue;

            switch (light_info->OriginalParms.type)
            {
                case WINED3D_LIGHT_DIRECTIONAL:
                    ++ls->directional_light_count;
                    break;

                case WINED3D_LIGHT_POINT:
                    ++ls->point_light_count;
                    break;

                case WINED3D_LIGHT_SPOT:
                    ++ls->spot_light_count;
                    break;

                case WINED3D_LIGHT_PARALLELPOINT:
                    ++ls->parallel_point_light_count;
                    break;

                default:
                    FIXME("Unhandled light type %#x.\n", light_info->OriginalParms.type);
                    continue;
            }
            lights[index++] = light_info;
            if (index == WINED3D_MAX_SOFTWARE_ACTIVE_LIGHTS)
                break;
        }
    }

    light_count = index;
    for (i = 0, index = 0; i < light_count; ++i)
    {
        light_info = lights[i];
        if (light_info->OriginalParms.type != WINED3D_LIGHT_DIRECTIONAL)
            continue;

        light = &ls->lights[index];
        wined3d_vec4_transform(&vec4, &light_info->direction, &state->transforms[WINED3D_TS_VIEW]);
        light->direction = *(struct wined3d_vec3 *)&vec4;
        wined3d_vec3_normalise(&light->direction);

        light->diffuse = light_info->OriginalParms.diffuse;
        light->ambient = light_info->OriginalParms.ambient;
        light->specular = light_info->OriginalParms.specular;
        ++index;
    }

    for (i = 0; i < light_count; ++i)
    {
        light_info = lights[i];
        if (light_info->OriginalParms.type != WINED3D_LIGHT_POINT)
            continue;

        light = &ls->lights[index];

        wined3d_vec4_transform(&light->position, &light_info->position, &state->transforms[WINED3D_TS_VIEW]);
        light->range = light_info->OriginalParms.range;
        light->c_att = light_info->OriginalParms.attenuation0;
        light->l_att = light_info->OriginalParms.attenuation1;
        light->q_att = light_info->OriginalParms.attenuation2;

        light->diffuse = light_info->OriginalParms.diffuse;
        light->ambient = light_info->OriginalParms.ambient;
        light->specular = light_info->OriginalParms.specular;
        ++index;
    }

    for (i = 0; i < light_count; ++i)
    {
        light_info = lights[i];
        if (light_info->OriginalParms.type != WINED3D_LIGHT_SPOT)
            continue;

        light = &ls->lights[index];

        wined3d_vec4_transform(&light->position, &light_info->position, &state->transforms[WINED3D_TS_VIEW]);
        wined3d_vec4_transform(&vec4, &light_info->direction, &state->transforms[WINED3D_TS_VIEW]);
        light->direction = *(struct wined3d_vec3 *)&vec4;
        wined3d_vec3_normalise(&light->direction);
        light->range = light_info->OriginalParms.range;
        light->falloff = light_info->OriginalParms.falloff;
        light->c_att = light_info->OriginalParms.attenuation0;
        light->l_att = light_info->OriginalParms.attenuation1;
        light->q_att = light_info->OriginalParms.attenuation2;
        light->cos_htheta = cosf(light_info->OriginalParms.theta / 2.0f);
        light->cos_hphi = cosf(light_info->OriginalParms.phi / 2.0f);

        light->diffuse = light_info->OriginalParms.diffuse;
        light->ambient = light_info->OriginalParms.ambient;
        light->specular = light_info->OriginalParms.specular;
        ++index;
    }

    for (i = 0; i < light_count; ++i)
    {
        light_info = lights[i];
        if (light_info->OriginalParms.type != WINED3D_LIGHT_PARALLELPOINT)
            continue;

        light = &ls->lights[index];

        wined3d_vec4_transform(&vec4, &light_info->position, &state->transforms[WINED3D_TS_VIEW]);
        *(struct wined3d_vec3 *)&light->position = *(struct wined3d_vec3 *)&vec4;
        wined3d_vec3_normalise((struct wined3d_vec3 *)&light->position);
        light->diffuse = light_info->OriginalParms.diffuse;
        light->ambient = light_info->OriginalParms.ambient;
        light->specular = light_info->OriginalParms.specular;
        ++index;
    }
}

static void update_light_diffuse_specular(struct wined3d_color *diffuse, struct wined3d_color *specular,
        const struct wined3d_vec3 *dir, float att, float material_shininess,
        const struct wined3d_vec3 *normal_transformed,
        const struct wined3d_vec3 *position_transformed_normalised,
        const struct light_transformed *light, const struct lights_settings *ls)
{
    struct wined3d_vec3 vec3;
    float t, c;

    c = wined3d_clamp(wined3d_vec3_dot(dir, normal_transformed), 0.0f, 1.0f);
    wined3d_color_rgb_mul_add(diffuse, &light->diffuse, c * att);

    vec3 = *dir;
    if (ls->localviewer)
        wined3d_vec3_subtract(&vec3, position_transformed_normalised);
    else
        vec3.z -= 1.0f;
    wined3d_vec3_normalise(&vec3);
    t = wined3d_vec3_dot(normal_transformed, &vec3);
    if (t > 0.0f && (!ls->legacy_lighting || material_shininess > 0.0f)
            && wined3d_vec3_dot(dir, normal_transformed) > 0.0f)
        wined3d_color_rgb_mul_add(specular, &light->specular, att * powf(t, material_shininess));
}

static void light_set_vertex_data(struct lights_settings *ls,
        const struct wined3d_vec4 *position)
{
    if (ls->fog_mode == WINED3D_FOG_NONE && !ls->lighting)
        return;

    wined3d_vec4_transform(&ls->position_transformed, position, &ls->modelview_matrix);
    wined3d_vec3_scale((struct wined3d_vec3 *)&ls->position_transformed, 1.0f / ls->position_transformed.w);
}

static void compute_light(struct wined3d_color *ambient, struct wined3d_color *diffuse,
        struct wined3d_color *specular, struct lights_settings *ls, const struct wined3d_vec3 *normal,
        float material_shininess)
{
    struct wined3d_vec3 position_transformed_normalised;
    struct wined3d_vec3 normal_transformed = {0.0f};
    const struct light_transformed *light;
    struct wined3d_vec3 dir, dst;
    unsigned int i, index;
    float att;

    position_transformed_normalised = *(const struct wined3d_vec3 *)&ls->position_transformed;
    wined3d_vec3_normalise(&position_transformed_normalised);

    if (normal)
    {
        wined3d_vec3_transform(&normal_transformed, normal, &ls->normal_matrix);
        if (ls->normalise)
            wined3d_vec3_normalise(&normal_transformed);
    }

    diffuse->r = diffuse->g = diffuse->b = diffuse->a = 0.0f;
    *specular = *diffuse;
    *ambient = ls->ambient_light;

    index = 0;
    for (i = 0; i < ls->directional_light_count; ++i, ++index)
    {
        light = &ls->lights[index];

        wined3d_color_rgb_mul_add(ambient, &light->ambient, 1.0f);
        if (normal)
            update_light_diffuse_specular(diffuse, specular, &light->direction, 1.0f, material_shininess,
                    &normal_transformed, &position_transformed_normalised, light, ls);
    }

    for (i = 0; i < ls->point_light_count; ++i, ++index)
    {
        light = &ls->lights[index];
        dir.x = light->position.x - ls->position_transformed.x;
        dir.y = light->position.y - ls->position_transformed.y;
        dir.z = light->position.z - ls->position_transformed.z;

        dst.z = wined3d_vec3_dot(&dir, &dir);
        dst.y = sqrtf(dst.z);
        dst.x = 1.0f;
        if (ls->legacy_lighting)
        {
            dst.y = (light->range - dst.y) / light->range;
            if (!(dst.y > 0.0f))
                continue;
            dst.z = dst.y * dst.y;
        }
        else
        {
            if (!(dst.y <= light->range))
                continue;
        }
        att = dst.x * light->c_att + dst.y * light->l_att + dst.z * light->q_att;
        if (!ls->legacy_lighting)
            att = 1.0f / att;

        wined3d_color_rgb_mul_add(ambient, &light->ambient, att);
        if (normal)
        {
            wined3d_vec3_normalise(&dir);
            update_light_diffuse_specular(diffuse, specular, &dir, att, material_shininess,
                    &normal_transformed, &position_transformed_normalised, light, ls);
        }
    }

    for (i = 0; i < ls->spot_light_count; ++i, ++index)
    {
        float t;

        light = &ls->lights[index];

        dir.x = light->position.x - ls->position_transformed.x;
        dir.y = light->position.y - ls->position_transformed.y;
        dir.z = light->position.z - ls->position_transformed.z;

        dst.z = wined3d_vec3_dot(&dir, &dir);
        dst.y = sqrtf(dst.z);
        dst.x = 1.0f;

        if (ls->legacy_lighting)
        {
            dst.y = (light->range - dst.y) / light->range;
            if (!(dst.y > 0.0f))
                continue;
            dst.z = dst.y * dst.y;
        }
        else
        {
            if (!(dst.y <= light->range))
                continue;
        }
        wined3d_vec3_normalise(&dir);
        t = -wined3d_vec3_dot(&dir, &light->direction);
        if (t > light->cos_htheta)
            att = 1.0f;
        else if (t <= light->cos_hphi)
            att = 0.0f;
        else
            att = powf((t - light->cos_hphi) / (light->cos_htheta - light->cos_hphi), light->falloff);

        t = dst.x * light->c_att + dst.y * light->l_att + dst.z * light->q_att;
        if (ls->legacy_lighting)
            att *= t;
        else
            att /= t;

        wined3d_color_rgb_mul_add(ambient, &light->ambient, att);

        if (normal)
            update_light_diffuse_specular(diffuse, specular, &dir, att, material_shininess,
                    &normal_transformed, &position_transformed_normalised, light, ls);
    }

    for (i = 0; i < ls->parallel_point_light_count; ++i, ++index)
    {
        light = &ls->lights[index];

        wined3d_color_rgb_mul_add(ambient, &light->ambient, 1.0f);
        if (normal)
            update_light_diffuse_specular(diffuse, specular, (const struct wined3d_vec3 *)&light->position,
                    1.0f, material_shininess, &normal_transformed, &position_transformed_normalised, light, ls);
    }
}

static float wined3d_calculate_fog_factor(float fog_coord, const struct lights_settings *ls)
{
    switch (ls->fog_mode)
    {
        case WINED3D_FOG_NONE:
            return fog_coord;
        case WINED3D_FOG_LINEAR:
            return (ls->fog_end - fog_coord) / (ls->fog_end - ls->fog_start);
        case WINED3D_FOG_EXP:
            return expf(-fog_coord * ls->fog_density);
        case WINED3D_FOG_EXP2:
            return expf(-fog_coord * fog_coord * ls->fog_density * ls->fog_density);
        default:
            ERR("Unhandled fog mode %#x.\n", ls->fog_mode);
            return 0.0f;
    }
}

static void update_fog_factor(float *fog_factor, struct lights_settings *ls)
{
    float fog_coord;

    if (ls->fog_mode == WINED3D_FOG_NONE)
        return;

    switch (ls->fog_coord_mode)
    {
        case WINED3D_FFP_VS_FOG_RANGE:
            fog_coord = sqrtf(wined3d_vec3_dot((const struct wined3d_vec3 *)&ls->position_transformed,
                    (const struct wined3d_vec3 *)&ls->position_transformed));
            break;

        case WINED3D_FFP_VS_FOG_DEPTH:
            fog_coord = fabsf(ls->position_transformed.z);
            break;

        default:
            ERR("Unhandled fog coordinate mode %#x.\n", ls->fog_coord_mode);
            return;
    }
    *fog_factor = wined3d_calculate_fog_factor(fog_coord, ls);
}

/* Context activation is done by the caller. */
#define copy_and_next(dest, src, size) memcpy(dest, src, size); dest += (size)
static HRESULT process_vertices_strided(const struct wined3d_device *device, DWORD dwDestIndex, DWORD dwCount,
        const struct wined3d_stream_info *stream_info, struct wined3d_buffer *dest, DWORD flags, DWORD dst_fvf)
{
    enum wined3d_material_color_source diffuse_source, specular_source, ambient_source, emissive_source;
    const struct wined3d_color *material_specular_state_colour;
    struct wined3d_matrix mat, proj_mat, view_mat, world_mat;
    const struct wined3d_state *state = device->cs->c.state;
    const struct wined3d_format *output_colour_format;
    static const struct wined3d_color black;
    struct wined3d_map_desc map_desc;
    struct wined3d_box box = {0};
    struct wined3d_viewport vp;
    unsigned int texture_count;
    struct lights_settings ls;
    unsigned int vertex_size;
    BOOL do_clip, lighting;
    float min_z, max_z;
    unsigned int i;
    BYTE *dest_ptr;
    HRESULT hr;

    if (!(stream_info->use_map & (1u << WINED3D_FFP_POSITION)))
    {
        ERR("Source has no position mask.\n");
        return WINED3DERR_INVALIDCALL;
    }

    if (state->render_states[WINED3D_RS_CLIPPING])
    {
        static BOOL warned = FALSE;
        /*
         * The clipping code is not quite correct. Some things need
         * to be checked against IDirect3DDevice3 (!), d3d8 and d3d9,
         * so disable clipping for now.
         * (The graphics in Half-Life are broken, and my processvertices
         *  test crashes with IDirect3DDevice3)
        do_clip = TRUE;
         */
        do_clip = FALSE;
        if (!warned)
        {
           warned = TRUE;
           FIXME("Clipping is broken and disabled for now\n");
        }
    }
    else
        do_clip = FALSE;

    vertex_size = wined3d_get_flexible_vertex_size(dst_fvf);
    box.left = dwDestIndex * vertex_size;
    box.right = box.left + dwCount * vertex_size;
    if (FAILED(hr = wined3d_resource_map(&dest->resource, 0, &map_desc, &box, WINED3D_MAP_WRITE)))
    {
        WARN("Failed to map buffer, hr %#x.\n", hr);
        return hr;
    }
    dest_ptr = map_desc.data;

    wined3d_device_get_transform(device, WINED3D_TS_VIEW, &view_mat);
    wined3d_device_get_transform(device, WINED3D_TS_PROJECTION, &proj_mat);
    wined3d_device_get_transform(device, WINED3D_TS_WORLD_MATRIX(0), &world_mat);

    TRACE("View mat:\n");
    TRACE("%.8e %.8e %.8e %.8e\n", view_mat._11, view_mat._12, view_mat._13, view_mat._14);
    TRACE("%.8e %.8e %.8e %.8e\n", view_mat._21, view_mat._22, view_mat._23, view_mat._24);
    TRACE("%.8e %.8e %.8e %.8e\n", view_mat._31, view_mat._32, view_mat._33, view_mat._34);
    TRACE("%.8e %.8e %.8e %.8e\n", view_mat._41, view_mat._42, view_mat._43, view_mat._44);

    TRACE("Proj mat:\n");
    TRACE("%.8e %.8e %.8e %.8e\n", proj_mat._11, proj_mat._12, proj_mat._13, proj_mat._14);
    TRACE("%.8e %.8e %.8e %.8e\n", proj_mat._21, proj_mat._22, proj_mat._23, proj_mat._24);
    TRACE("%.8e %.8e %.8e %.8e\n", proj_mat._31, proj_mat._32, proj_mat._33, proj_mat._34);
    TRACE("%.8e %.8e %.8e %.8e\n", proj_mat._41, proj_mat._42, proj_mat._43, proj_mat._44);

    TRACE("World mat:\n");
    TRACE("%.8e %.8e %.8e %.8e\n", world_mat._11, world_mat._12, world_mat._13, world_mat._14);
    TRACE("%.8e %.8e %.8e %.8e\n", world_mat._21, world_mat._22, world_mat._23, world_mat._24);
    TRACE("%.8e %.8e %.8e %.8e\n", world_mat._31, world_mat._32, world_mat._33, world_mat._34);
    TRACE("%.8e %.8e %.8e %.8e\n", world_mat._41, world_mat._42, world_mat._43, world_mat._44);

    /* Get the viewport */
    wined3d_device_context_get_viewports(&device->cs->c, NULL, &vp);
    TRACE("viewport x %.8e, y %.8e, width %.8e, height %.8e, min_z %.8e, max_z %.8e.\n",
          vp.x, vp.y, vp.width, vp.height, vp.min_z, vp.max_z);

    multiply_matrix(&mat,&view_mat,&world_mat);
    multiply_matrix(&mat,&proj_mat,&mat);

    texture_count = (dst_fvf & WINED3DFVF_TEXCOUNT_MASK) >> WINED3DFVF_TEXCOUNT_SHIFT;

    lighting = state->render_states[WINED3D_RS_LIGHTING]
            && (dst_fvf & (WINED3DFVF_DIFFUSE | WINED3DFVF_SPECULAR));
    wined3d_get_material_colour_source(&diffuse_source, &emissive_source,
            &ambient_source, &specular_source, state, stream_info);
    output_colour_format = wined3d_get_format(device->adapter, WINED3DFMT_B8G8R8A8_UNORM, 0);
    material_specular_state_colour = state->render_states[WINED3D_RS_SPECULARENABLE]
            ? &state->material.specular : &black;
    init_transformed_lights(&ls, state, device->adapter->d3d_info.wined3d_creation_flags
            & WINED3D_LEGACY_FFP_LIGHTING, lighting);

    wined3d_viewport_get_z_range(&vp, &min_z, &max_z);

    for (i = 0; i < dwCount; ++i)
    {
        const struct wined3d_stream_info_element *position_element = &stream_info->elements[WINED3D_FFP_POSITION];
        const float *p = (const float *)&position_element->data.addr[i * position_element->stride];
        struct wined3d_color ambient, diffuse, specular;
        struct wined3d_vec4 position;
        unsigned int tex_index;

        position.x = p[0];
        position.y = p[1];
        position.z = p[2];
        position.w = 1.0f;

        light_set_vertex_data(&ls, &position);

        if ( ((dst_fvf & WINED3DFVF_POSITION_MASK) == WINED3DFVF_XYZ ) ||
             ((dst_fvf & WINED3DFVF_POSITION_MASK) == WINED3DFVF_XYZRHW ) ) {
            /* The position first */
            float x, y, z, rhw;
            TRACE("In: ( %06.2f %06.2f %06.2f )\n", p[0], p[1], p[2]);

            /* Multiplication with world, view and projection matrix. */
            x   = (p[0] * mat._11) + (p[1] * mat._21) + (p[2] * mat._31) + mat._41;
            y   = (p[0] * mat._12) + (p[1] * mat._22) + (p[2] * mat._32) + mat._42;
            z   = (p[0] * mat._13) + (p[1] * mat._23) + (p[2] * mat._33) + mat._43;
            rhw = (p[0] * mat._14) + (p[1] * mat._24) + (p[2] * mat._34) + mat._44;

            TRACE("x=%f y=%f z=%f rhw=%f\n", x, y, z, rhw);

            /* WARNING: The following things are taken from d3d7 and were not yet checked
             * against d3d8 or d3d9!
             */

            /* Clipping conditions: From msdn
             *
             * A vertex is clipped if it does not match the following requirements
             * -rhw < x <= rhw
             * -rhw < y <= rhw
             *    0 < z <= rhw
             *    0 < rhw ( Not in d3d7, but tested in d3d7)
             *
             * If clipping is on is determined by the D3DVOP_CLIP flag in D3D7, and
             * by the D3DRS_CLIPPING in D3D9(according to the msdn, not checked)
             *
             */

            if (!do_clip || (-rhw - eps < x && -rhw - eps < y && -eps < z && x <= rhw + eps
                    && y <= rhw + eps && z <= rhw + eps && rhw > eps))
            {
                /* "Normal" viewport transformation (not clipped)
                 * 1) The values are divided by rhw
                 * 2) The y axis is negative, so multiply it with -1
                 * 3) Screen coordinates go from -(Width/2) to +(Width/2) and
                 *    -(Height/2) to +(Height/2). The z range is MinZ to MaxZ
                 * 4) Multiply x with Width/2 and add Width/2
                 * 5) The same for the height
                 * 6) Add the viewpoint X and Y to the 2D coordinates and
                 *    The minimum Z value to z
                 * 7) rhw = 1 / rhw Reciprocal of Homogeneous W....
                 *
                 * Well, basically it's simply a linear transformation into viewport
                 * coordinates
                 */

                x /= rhw;
                y /= rhw;
                z /= rhw;

                y *= -1;

                x *= vp.width / 2;
                y *= vp.height / 2;
                z *= max_z - min_z;

                x += vp.width / 2 + vp.x;
                y += vp.height / 2 + vp.y;
                z += min_z;

                rhw = 1 / rhw;
            } else {
                /* That vertex got clipped
                 * Contrary to OpenGL it is not dropped completely, it just
                 * undergoes a different calculation.
                 */
                TRACE("Vertex got clipped\n");
                x += rhw;
                y += rhw;

                x  /= 2;
                y  /= 2;

                /* Msdn mentions that Direct3D9 keeps a list of clipped vertices
                 * outside of the main vertex buffer memory. That needs some more
                 * investigation...
                 */
            }

            TRACE("Writing (%f %f %f) %f\n", x, y, z, rhw);


            ( (float *) dest_ptr)[0] = x;
            ( (float *) dest_ptr)[1] = y;
            ( (float *) dest_ptr)[2] = z;
            ( (float *) dest_ptr)[3] = rhw; /* SIC, see ddraw test! */

            dest_ptr += 3 * sizeof(float);

            if ((dst_fvf & WINED3DFVF_POSITION_MASK) == WINED3DFVF_XYZRHW)
                dest_ptr += sizeof(float);
        }

        if (dst_fvf & WINED3DFVF_PSIZE)
            dest_ptr += sizeof(DWORD);

        if (dst_fvf & WINED3DFVF_NORMAL)
        {
            const struct wined3d_stream_info_element *element = &stream_info->elements[WINED3D_FFP_NORMAL];
            const float *normal = (const float *)(element->data.addr + i * element->stride);
            /* AFAIK this should go into the lighting information */
            FIXME("Didn't expect the destination to have a normal\n");
            copy_and_next(dest_ptr, normal, 3 * sizeof(float));
        }

        if (lighting)
        {
            const struct wined3d_stream_info_element *element;
            struct wined3d_vec3 *normal;

            if (stream_info->use_map & (1u << WINED3D_FFP_NORMAL))
            {
                element = &stream_info->elements[WINED3D_FFP_NORMAL];
                normal = (struct wined3d_vec3 *)&element->data.addr[i * element->stride];
            }
            else
            {
                normal = NULL;
            }
            compute_light(&ambient, &diffuse, &specular, &ls, normal,
                    state->render_states[WINED3D_RS_SPECULARENABLE] ? state->material.power : 0.0f);
        }

        if (dst_fvf & WINED3DFVF_DIFFUSE)
        {
            struct wined3d_color material_diffuse, material_ambient, material_emissive, diffuse_colour;

            wined3d_colour_from_mcs(&material_diffuse, diffuse_source,
                    &state->material.diffuse, i, stream_info);

            if (lighting)
            {
                wined3d_colour_from_mcs(&material_ambient, ambient_source,
                        &state->material.ambient, i, stream_info);
                wined3d_colour_from_mcs(&material_emissive, emissive_source,
                        &state->material.emissive, i, stream_info);

                diffuse_colour.r = ambient.r * material_ambient.r
                        + diffuse.r * material_diffuse.r + material_emissive.r;
                diffuse_colour.g = ambient.g * material_ambient.g
                        + diffuse.g * material_diffuse.g + material_emissive.g;
                diffuse_colour.b = ambient.b * material_ambient.b
                        + diffuse.b * material_diffuse.b + material_emissive.b;
                diffuse_colour.a = material_diffuse.a;
            }
            else
            {
                diffuse_colour = material_diffuse;
            }
            wined3d_color_clamp(&diffuse_colour, &diffuse_colour, 0.0f, 1.0f);
            *((DWORD *)dest_ptr) = wined3d_format_convert_from_float(output_colour_format, &diffuse_colour);
            dest_ptr += sizeof(DWORD);
        }

        if (dst_fvf & WINED3DFVF_SPECULAR)
        {
            struct wined3d_color material_specular, specular_colour;

            wined3d_colour_from_mcs(&material_specular, specular_source,
                    material_specular_state_colour, i, stream_info);

            if (lighting)
            {
                specular_colour.r = specular.r * material_specular.r;
                specular_colour.g = specular.g * material_specular.g;
                specular_colour.b = specular.b * material_specular.b;
                specular_colour.a = ls.legacy_lighting ? 0.0f : material_specular.a;
            }
            else
            {
                specular_colour = material_specular;
            }
            update_fog_factor(&specular_colour.a, &ls);
            wined3d_color_clamp(&specular_colour, &specular_colour, 0.0f, 1.0f);
            *((DWORD *)dest_ptr) = wined3d_format_convert_from_float(output_colour_format, &specular_colour);
            dest_ptr += sizeof(DWORD);
        }

        for (tex_index = 0; tex_index < texture_count; ++tex_index)
        {
            const struct wined3d_stream_info_element *element = &stream_info->elements[WINED3D_FFP_TEXCOORD0 + tex_index];
            const float *tex_coord = (const float *)(element->data.addr + i * element->stride);
            if (!(stream_info->use_map & (1u << (WINED3D_FFP_TEXCOORD0 + tex_index))))
            {
                ERR("No source texture, but destination requests one\n");
                dest_ptr += GET_TEXCOORD_SIZE_FROM_FVF(dst_fvf, tex_index) * sizeof(float);
            }
            else
            {
                copy_and_next(dest_ptr, tex_coord, GET_TEXCOORD_SIZE_FROM_FVF(dst_fvf, tex_index) * sizeof(float));
            }
        }
    }

    wined3d_resource_unmap(&dest->resource, 0);

    return WINED3D_OK;
}
#undef copy_and_next

HRESULT CDECL wined3d_device_process_vertices(struct wined3d_device *device,
        UINT src_start_idx, UINT dst_idx, UINT vertex_count, struct wined3d_buffer *dst_buffer,
        const struct wined3d_vertex_declaration *declaration, DWORD flags, DWORD dst_fvf)
{
    struct wined3d_state *state = device->cs->c.state;
    struct wined3d_stream_info stream_info;
    struct wined3d_resource *resource;
    struct wined3d_box box = {0};
    struct wined3d_shader *vs;
    unsigned int i, j;
    HRESULT hr;
    WORD map;

    TRACE("device %p, src_start_idx %u, dst_idx %u, vertex_count %u, "
            "dst_buffer %p, declaration %p, flags %#x, dst_fvf %#x.\n",
            device, src_start_idx, dst_idx, vertex_count,
            dst_buffer, declaration, flags, dst_fvf);

    if (declaration)
        FIXME("Output vertex declaration not implemented yet.\n");

    vs = state->shader[WINED3D_SHADER_TYPE_VERTEX];
    state->shader[WINED3D_SHADER_TYPE_VERTEX] = NULL;
    wined3d_stream_info_from_declaration(&stream_info, state, &device->adapter->d3d_info);
    state->shader[WINED3D_SHADER_TYPE_VERTEX] = vs;

    /* We can't convert FROM a VBO, and vertex buffers used to source into
     * process_vertices() are unlikely to ever be used for drawing. Release
     * VBOs in those buffers and fix up the stream_info structure.
     *
     * Also apply the start index. */
    for (i = 0, map = stream_info.use_map; map; map >>= 1, ++i)
    {
        struct wined3d_stream_info_element *e;
        struct wined3d_map_desc map_desc;

        if (!(map & 1))
            continue;

        e = &stream_info.elements[i];
        resource = &state->streams[e->stream_idx].buffer->resource;
        box.left = src_start_idx * e->stride;
        box.right = box.left + vertex_count * e->stride;
        if (FAILED(wined3d_resource_map(resource, 0, &map_desc, &box, WINED3D_MAP_READ)))
        {
            ERR("Failed to map resource.\n");
            for (j = 0, map = stream_info.use_map; map && j < i; map >>= 1, ++j)
            {
                if (!(map & 1))
                    continue;

                e = &stream_info.elements[j];
                resource = &state->streams[e->stream_idx].buffer->resource;
                if (FAILED(wined3d_resource_unmap(resource, 0)))
                    ERR("Failed to unmap resource.\n");
            }
            return WINED3DERR_INVALIDCALL;
        }
        e->data.buffer_object = 0;
        e->data.addr += (ULONG_PTR)map_desc.data;
    }

    hr = process_vertices_strided(device, dst_idx, vertex_count,
            &stream_info, dst_buffer, flags, dst_fvf);

    for (i = 0, map = stream_info.use_map; map; map >>= 1, ++i)
    {
        if (!(map & 1))
            continue;

        resource = &state->streams[stream_info.elements[i].stream_idx].buffer->resource;
        if (FAILED(wined3d_resource_unmap(resource, 0)))
            ERR("Failed to unmap resource.\n");
    }

    return hr;
}

static void wined3d_device_set_texture_stage_state(struct wined3d_device *device,
        UINT stage, enum wined3d_texture_stage_state state, DWORD value)
{
    const struct wined3d_d3d_info *d3d_info = &device->adapter->d3d_info;

    TRACE("device %p, stage %u, state %s, value %#x.\n",
            device, stage, debug_d3dtexturestate(state), value);

    if (stage >= d3d_info->limits.ffp_blend_stages)
    {
        WARN("Attempting to set stage %u which is higher than the max stage %u, ignoring.\n",
                stage, d3d_info->limits.ffp_blend_stages - 1);
        return;
    }

    if (value == device->cs->c.state->texture_states[stage][state])
    {
        TRACE("Application is setting the old value over, nothing to do.\n");
        return;
    }

    device->cs->c.state->texture_states[stage][state] = value;

    wined3d_cs_emit_set_texture_state(device->cs, stage, state, value);
}

static void wined3d_device_set_texture(struct wined3d_device *device,
        UINT stage, struct wined3d_texture *texture)
{
    struct wined3d_state *state = device->cs->c.state;
    struct wined3d_texture *prev;

    TRACE("device %p, stage %u, texture %p.\n", device, stage, texture);

    /* Windows accepts overflowing this array... we do not. */
    if (stage >= ARRAY_SIZE(state->textures))
    {
        WARN("Ignoring invalid stage %u.\n", stage);
        return;
    }

    prev = state->textures[stage];
    TRACE("Previous texture %p.\n", prev);

    if (texture == prev)
    {
        TRACE("App is setting the same texture again, nothing to do.\n");
        return;
    }

    TRACE("Setting new texture to %p.\n", texture);
    state->textures[stage] = texture;

    if (texture)
        wined3d_texture_incref(texture);
    wined3d_cs_emit_set_texture(device->cs, stage, texture);
    if (prev)
        wined3d_texture_decref(prev);

    return;
}

void CDECL wined3d_device_apply_stateblock(struct wined3d_device *device,
        struct wined3d_stateblock *stateblock)
{
    BOOL set_blend_state = FALSE, set_depth_stencil_state = FALSE, set_rasterizer_state = FALSE;
    const struct wined3d_stateblock_state *state = &stateblock->stateblock_state;
    const struct wined3d_saved_states *changed = &stateblock->changed;
    const unsigned int word_bit_count = sizeof(DWORD) * CHAR_BIT;
    struct wined3d_device_context *context = &device->cs->c;
    unsigned int i, j, start, idx, vs_uniform_count;
    struct wined3d_range range;
    uint32_t map;

    TRACE("device %p, stateblock %p.\n", device, stateblock);

    if (changed->vertexShader)
        wined3d_device_set_vertex_shader(device, state->vs);
    if (changed->pixelShader)
        wined3d_device_set_pixel_shader(device, state->ps);

    vs_uniform_count = wined3d_device_get_vs_uniform_count(device);

    for (start = 0; ; start = range.offset + range.size)
    {
        if (!wined3d_bitmap_get_range(changed->vs_consts_f, vs_uniform_count, start, &range))
            break;

        wined3d_device_set_vs_consts_f(device, range.offset, range.size, &state->vs_consts_f[range.offset]);
    }

    map = changed->vertexShaderConstantsI;
    for (start = 0; ; start = range.offset + range.size)
    {
        if (!wined3d_bitmap_get_range(&map, WINED3D_MAX_CONSTS_I, start, &range))
            break;

        wined3d_device_set_vs_consts_i(device, range.offset, range.size, &state->vs_consts_i[range.offset]);
    }

    map = changed->vertexShaderConstantsB;
    for (start = 0; ; start = range.offset + range.size)
    {
        if (!wined3d_bitmap_get_range(&map, WINED3D_MAX_CONSTS_B, start, &range))
            break;

        wined3d_device_set_vs_consts_b(device, range.offset, range.size, &state->vs_consts_b[range.offset]);
    }

    for (start = 0; ; start = range.offset + range.size)
    {
        if (!wined3d_bitmap_get_range(changed->ps_consts_f, WINED3D_MAX_PS_CONSTS_F, start, &range))
            break;

        wined3d_device_set_ps_consts_f(device, range.offset, range.size, &state->ps_consts_f[range.offset]);
    }

    map = changed->pixelShaderConstantsI;
    for (start = 0; ; start = range.offset + range.size)
    {
        if (!wined3d_bitmap_get_range(&map, WINED3D_MAX_CONSTS_I, start, &range))
            break;

        wined3d_device_set_ps_consts_i(device, range.offset, range.size, &state->ps_consts_i[range.offset]);
    }

    map = changed->pixelShaderConstantsB;
    for (start = 0; ; start = range.offset + range.size)
    {
        if (!wined3d_bitmap_get_range(&map, WINED3D_MAX_CONSTS_B, start, &range))
            break;

        wined3d_device_set_ps_consts_b(device, range.offset, range.size, &state->ps_consts_b[range.offset]);
    }

    if (changed->lights)
    {
        for (i = 0; i < ARRAY_SIZE(state->light_state->light_map); ++i)
        {
            const struct wined3d_light_info *light;

            LIST_FOR_EACH_ENTRY(light, &state->light_state->light_map[i], struct wined3d_light_info, entry)
            {
                wined3d_device_set_light(device, light->OriginalIndex, &light->OriginalParms);
                wined3d_device_set_light_enable(device, light->OriginalIndex, light->glIndex != -1);
            }
        }
    }

    for (i = 0; i < ARRAY_SIZE(changed->renderState); ++i)
    {
        map = changed->renderState[i];
        while (map)
        {
            j = wined3d_bit_scan(&map);
            idx = i * word_bit_count + j;

            switch (idx)
            {
                case WINED3D_RS_BLENDFACTOR:
                case WINED3D_RS_MULTISAMPLEMASK:
                case WINED3D_RS_ALPHABLENDENABLE:
                case WINED3D_RS_SRCBLEND:
                case WINED3D_RS_DESTBLEND:
                case WINED3D_RS_BLENDOP:
                case WINED3D_RS_SEPARATEALPHABLENDENABLE:
                case WINED3D_RS_SRCBLENDALPHA:
                case WINED3D_RS_DESTBLENDALPHA:
                case WINED3D_RS_BLENDOPALPHA:
                case WINED3D_RS_COLORWRITEENABLE:
                case WINED3D_RS_COLORWRITEENABLE1:
                case WINED3D_RS_COLORWRITEENABLE2:
                case WINED3D_RS_COLORWRITEENABLE3:
                    set_blend_state = TRUE;
                    break;

                case WINED3D_RS_BACK_STENCILFAIL:
                case WINED3D_RS_BACK_STENCILFUNC:
                case WINED3D_RS_BACK_STENCILPASS:
                case WINED3D_RS_BACK_STENCILZFAIL:
                case WINED3D_RS_STENCILENABLE:
                case WINED3D_RS_STENCILFAIL:
                case WINED3D_RS_STENCILFUNC:
                case WINED3D_RS_STENCILREF:
                case WINED3D_RS_STENCILMASK:
                case WINED3D_RS_STENCILPASS:
                case WINED3D_RS_STENCILWRITEMASK:
                case WINED3D_RS_STENCILZFAIL:
                case WINED3D_RS_TWOSIDEDSTENCILMODE:
                case WINED3D_RS_ZENABLE:
                case WINED3D_RS_ZFUNC:
                case WINED3D_RS_ZWRITEENABLE:
                    set_depth_stencil_state = TRUE;
                    break;

                case WINED3D_RS_FILLMODE:
                case WINED3D_RS_CULLMODE:
                case WINED3D_RS_SLOPESCALEDEPTHBIAS:
                case WINED3D_RS_DEPTHBIAS:
                case WINED3D_RS_SCISSORTESTENABLE:
                case WINED3D_RS_ANTIALIASEDLINEENABLE:
                    set_rasterizer_state = TRUE;
                    break;

                default:
                    wined3d_device_set_render_state(device, idx, state->rs[idx]);
                    break;
            }
        }
    }

    if (set_rasterizer_state)
    {
        struct wined3d_rasterizer_state *rasterizer_state;
        struct wined3d_rasterizer_state_desc desc;
        struct wine_rb_entry *entry;
        union
        {
            DWORD d;
            float f;
        } bias;

        memset(&desc, 0, sizeof(desc));
        desc.fill_mode = state->rs[WINED3D_RS_FILLMODE];
        desc.cull_mode = state->rs[WINED3D_RS_CULLMODE];
        bias.d = state->rs[WINED3D_RS_DEPTHBIAS];
        desc.depth_bias = bias.f;
        bias.d = state->rs[WINED3D_RS_SLOPESCALEDEPTHBIAS];
        desc.scale_bias = bias.f;
        desc.depth_clip = TRUE;
        desc.scissor = state->rs[WINED3D_RS_SCISSORTESTENABLE];
        desc.line_antialias = state->rs[WINED3D_RS_ANTIALIASEDLINEENABLE];

        if ((entry = wine_rb_get(&device->rasterizer_states, &desc)))
        {
            rasterizer_state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_rasterizer_state, entry);
            wined3d_device_set_rasterizer_state(device, rasterizer_state);
        }
        else if (SUCCEEDED(wined3d_rasterizer_state_create(device, &desc, NULL,
                &wined3d_null_parent_ops, &rasterizer_state)))
        {
            wined3d_device_set_rasterizer_state(device, rasterizer_state);
            if (wine_rb_put(&device->rasterizer_states, &desc, &rasterizer_state->entry) == -1)
            {
                ERR("Failed to insert rasterizer state.\n");
                wined3d_rasterizer_state_decref(rasterizer_state);
            }
        }
    }

    if (set_blend_state || changed->alpha_to_coverage
            || wined3d_bitmap_is_set(changed->renderState, WINED3D_RS_ADAPTIVETESS_Y))
    {
        struct wined3d_blend_state *blend_state;
        struct wined3d_blend_state_desc desc;
        struct wine_rb_entry *entry;
        struct wined3d_color colour;
        unsigned int sample_mask;

        memset(&desc, 0, sizeof(desc));
        desc.alpha_to_coverage = state->alpha_to_coverage;
        desc.independent = FALSE;
        if (state->rs[WINED3D_RS_ADAPTIVETESS_Y] == WINED3DFMT_ATOC)
            desc.alpha_to_coverage = TRUE;
        desc.rt[0].enable = state->rs[WINED3D_RS_ALPHABLENDENABLE];
        desc.rt[0].src = state->rs[WINED3D_RS_SRCBLEND];
        desc.rt[0].dst = state->rs[WINED3D_RS_DESTBLEND];
        desc.rt[0].op = state->rs[WINED3D_RS_BLENDOP];
        if (state->rs[WINED3D_RS_SEPARATEALPHABLENDENABLE])
        {
            desc.rt[0].src_alpha = state->rs[WINED3D_RS_SRCBLENDALPHA];
            desc.rt[0].dst_alpha = state->rs[WINED3D_RS_DESTBLENDALPHA];
            desc.rt[0].op_alpha = state->rs[WINED3D_RS_BLENDOPALPHA];
        }
        else
        {
            desc.rt[0].src_alpha = state->rs[WINED3D_RS_SRCBLEND];
            desc.rt[0].dst_alpha = state->rs[WINED3D_RS_DESTBLEND];
            desc.rt[0].op_alpha = state->rs[WINED3D_RS_BLENDOP];
        }
        desc.rt[0].writemask = state->rs[WINED3D_RS_COLORWRITEENABLE];
        desc.rt[1].writemask = state->rs[WINED3D_RS_COLORWRITEENABLE1];
        desc.rt[2].writemask = state->rs[WINED3D_RS_COLORWRITEENABLE2];
        desc.rt[3].writemask = state->rs[WINED3D_RS_COLORWRITEENABLE3];
        if (desc.rt[1].writemask != desc.rt[0].writemask
                || desc.rt[2].writemask != desc.rt[0].writemask
                || desc.rt[3].writemask != desc.rt[0].writemask)
        {
            desc.independent = TRUE;
            for (i = 1; i < 4; ++i)
            {
                desc.rt[i].enable = desc.rt[0].enable;
                desc.rt[i].src = desc.rt[0].src;
                desc.rt[i].dst = desc.rt[0].dst;
                desc.rt[i].op = desc.rt[0].op;
                desc.rt[i].src_alpha = desc.rt[0].src_alpha;
                desc.rt[i].dst_alpha = desc.rt[0].dst_alpha;
                desc.rt[i].op_alpha = desc.rt[0].op_alpha;
            }
        }

        if (wined3d_bitmap_is_set(changed->renderState, WINED3D_RS_BLENDFACTOR))
            wined3d_color_from_d3dcolor(&colour, state->rs[WINED3D_RS_BLENDFACTOR]);
        else
            wined3d_device_context_get_blend_state(context, &colour, &sample_mask);

        if ((entry = wine_rb_get(&device->blend_states, &desc)))
        {
            blend_state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_blend_state, entry);
            wined3d_device_set_blend_state(device, blend_state, &colour, state->rs[WINED3D_RS_MULTISAMPLEMASK]);
        }
        else if (SUCCEEDED(wined3d_blend_state_create(device, &desc, NULL,
                &wined3d_null_parent_ops, &blend_state)))
        {
            wined3d_device_set_blend_state(device, blend_state, &colour, state->rs[WINED3D_RS_MULTISAMPLEMASK]);
            if (wine_rb_put(&device->blend_states, &desc, &blend_state->entry) == -1)
            {
                ERR("Failed to insert blend state.\n");
                wined3d_blend_state_decref(blend_state);
            }
        }
    }

    if (set_depth_stencil_state)
    {
        struct wined3d_depth_stencil_state *depth_stencil_state;
        struct wined3d_depth_stencil_state_desc desc;
        struct wine_rb_entry *entry;
        unsigned int stencil_ref;

        memset(&desc, 0, sizeof(desc));
        switch (state->rs[WINED3D_RS_ZENABLE])
        {
            case WINED3D_ZB_FALSE:
                desc.depth = FALSE;
                break;

            case WINED3D_ZB_USEW:
                FIXME("W buffer is not well handled.\n");
            case WINED3D_ZB_TRUE:
                desc.depth = TRUE;
                break;

            default:
                FIXME("Unrecognized depth buffer type %#x.\n", state->rs[WINED3D_RS_ZENABLE]);
        }
        desc.depth_write = state->rs[WINED3D_RS_ZWRITEENABLE];
        desc.depth_func = state->rs[WINED3D_RS_ZFUNC];
        desc.stencil = state->rs[WINED3D_RS_STENCILENABLE];
        desc.stencil_read_mask = state->rs[WINED3D_RS_STENCILMASK];
        desc.stencil_write_mask = state->rs[WINED3D_RS_STENCILWRITEMASK];
        desc.front.fail_op = state->rs[WINED3D_RS_STENCILFAIL];
        desc.front.depth_fail_op = state->rs[WINED3D_RS_STENCILZFAIL];
        desc.front.pass_op = state->rs[WINED3D_RS_STENCILPASS];
        desc.front.func = state->rs[WINED3D_RS_STENCILFUNC];

        if (state->rs[WINED3D_RS_TWOSIDEDSTENCILMODE])
        {
            desc.back.fail_op = state->rs[WINED3D_RS_BACK_STENCILFAIL];
            desc.back.depth_fail_op = state->rs[WINED3D_RS_BACK_STENCILZFAIL];
            desc.back.pass_op = state->rs[WINED3D_RS_BACK_STENCILPASS];
            desc.back.func = state->rs[WINED3D_RS_BACK_STENCILFUNC];
        }
        else
        {
            desc.back = desc.front;
        }

        if (wined3d_bitmap_is_set(changed->renderState, WINED3D_RS_STENCILREF))
            stencil_ref = state->rs[WINED3D_RS_STENCILREF];
        else
            wined3d_device_context_get_depth_stencil_state(context, &stencil_ref);

        if ((entry = wine_rb_get(&device->depth_stencil_states, &desc)))
        {
            depth_stencil_state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_depth_stencil_state, entry);
            wined3d_device_set_depth_stencil_state(device, depth_stencil_state, stencil_ref);
        }
        else if (SUCCEEDED(wined3d_depth_stencil_state_create(device, &desc, NULL,
                &wined3d_null_parent_ops, &depth_stencil_state)))
        {
            wined3d_device_set_depth_stencil_state(device, depth_stencil_state, stencil_ref);
            if (wine_rb_put(&device->depth_stencil_states, &desc, &depth_stencil_state->entry) == -1)
            {
                ERR("Failed to insert depth/stencil state.\n");
                wined3d_depth_stencil_state_decref(depth_stencil_state);
            }
        }
    }

    for (i = 0; i < ARRAY_SIZE(changed->textureState); ++i)
    {
        map = changed->textureState[i];
        while (map)
        {
            j = wined3d_bit_scan(&map);
            wined3d_device_set_texture_stage_state(device, i, j, state->texture_states[i][j]);
        }
    }

    for (i = 0; i < ARRAY_SIZE(changed->samplerState); ++i)
    {
        map = changed->samplerState[i];
        while (map)
        {
            j = wined3d_bit_scan(&map);
            wined3d_device_set_sampler_state(device, i, j, state->sampler_states[i][j]);
        }
    }

    if (changed->transforms)
    {
        for (i = 0; i < ARRAY_SIZE(changed->transform); ++i)
        {
            map = changed->transform[i];
            while (map)
            {
                j = wined3d_bit_scan(&map);
                idx = i * word_bit_count + j;
                wined3d_device_set_transform(device, idx, &state->transforms[idx]);
            }
        }
    }

    if (changed->indices)
        wined3d_device_set_index_buffer(device, state->index_buffer, state->index_format, 0);
    wined3d_device_set_base_vertex_index(device, state->base_vertex_index);
    if (changed->vertexDecl)
        wined3d_device_set_vertex_declaration(device, state->vertex_declaration);
    if (changed->material)
        wined3d_device_set_material(device, &state->material);
    if (changed->viewport)
        wined3d_device_set_viewports(device, 1, &state->viewport);
    if (changed->scissorRect)
        wined3d_device_set_scissor_rects(device, 1, &state->scissor_rect);

    map = changed->streamSource;
    while (map)
    {
        i = wined3d_bit_scan(&map);
        wined3d_device_set_stream_source(device, i, state->streams[i].buffer,
                state->streams[i].offset, state->streams[i].stride);
    }
    map = changed->streamFreq;
    while (map)
    {
        i = wined3d_bit_scan(&map);
        wined3d_device_set_stream_source_freq(device, i,
                state->streams[i].frequency | state->streams[i].flags);
    }

    map = changed->textures;
    while (map)
    {
        i = wined3d_bit_scan(&map);
        wined3d_device_set_texture(device, i, state->textures[i]);
    }

    map = changed->clipplane;
    while (map)
    {
        i = wined3d_bit_scan(&map);
        wined3d_device_set_clip_plane(device, i, &state->clip_planes[i]);
    }

    memset(&stateblock->changed, 0, sizeof(stateblock->changed));

    TRACE("Applied stateblock %p.\n", stateblock);
}

HRESULT CDECL wined3d_device_get_device_caps(const struct wined3d_device *device, struct wined3d_caps *caps)
{
    HRESULT hr;

    TRACE("device %p, caps %p.\n", device, caps);

    if (FAILED(hr = wined3d_get_device_caps(device->adapter, device->create_parms.device_type, caps)))
        return hr;

    if (device->create_parms.flags & WINED3DCREATE_SOFTWARE_VERTEXPROCESSING)
        caps->MaxVertexShaderConst = device->adapter->d3d_info.limits.vs_uniform_count_swvp;
    return hr;
}

HRESULT CDECL wined3d_device_get_display_mode(const struct wined3d_device *device, UINT swapchain_idx,
        struct wined3d_display_mode *mode, enum wined3d_display_rotation *rotation)
{
    struct wined3d_swapchain *swapchain;

    TRACE("device %p, swapchain_idx %u, mode %p, rotation %p.\n",
            device, swapchain_idx, mode, rotation);

    if (!(swapchain = wined3d_device_get_swapchain(device, swapchain_idx)))
        return WINED3DERR_INVALIDCALL;

    return wined3d_swapchain_get_display_mode(swapchain, mode, rotation);
}

HRESULT CDECL wined3d_device_begin_scene(struct wined3d_device *device)
{
    /* At the moment we have no need for any functionality at the beginning
     * of a scene. */
    TRACE("device %p.\n", device);

    if (device->inScene)
    {
        WARN("Already in scene, returning WINED3DERR_INVALIDCALL.\n");
        return WINED3DERR_INVALIDCALL;
    }
    device->inScene = TRUE;
    return WINED3D_OK;
}

HRESULT CDECL wined3d_device_end_scene(struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    if (!device->inScene)
    {
        WARN("Not in scene, returning WINED3DERR_INVALIDCALL.\n");
        return WINED3DERR_INVALIDCALL;
    }

    device->inScene = FALSE;
    return WINED3D_OK;
}

HRESULT CDECL wined3d_device_clear(struct wined3d_device *device, DWORD rect_count,
        const RECT *rects, DWORD flags, const struct wined3d_color *color, float depth, DWORD stencil)
{
    struct wined3d_fb_state *fb = &device->cs->c.state->fb;

    TRACE("device %p, rect_count %u, rects %p, flags %#x, color %s, depth %.8e, stencil %u.\n",
            device, rect_count, rects, flags, debug_color(color), depth, stencil);

    if (!rect_count && rects)
    {
        WARN("Rects is %p, but rect_count is 0, ignoring clear\n", rects);
        return WINED3D_OK;
    }

    if (flags & (WINED3DCLEAR_ZBUFFER | WINED3DCLEAR_STENCIL))
    {
        struct wined3d_rendertarget_view *ds = fb->depth_stencil;
        if (!ds)
        {
            WARN("Clearing depth and/or stencil without a depth stencil buffer attached, returning WINED3DERR_INVALIDCALL\n");
            /* TODO: What about depth stencil buffers without stencil bits? */
            return WINED3DERR_INVALIDCALL;
        }
        else if (flags & WINED3DCLEAR_TARGET)
        {
            if (ds->width < fb->render_targets[0]->width
                    || ds->height < fb->render_targets[0]->height)
            {
                WARN("Silently ignoring depth and target clear with mismatching sizes\n");
                return WINED3D_OK;
            }
        }
    }

    wined3d_cs_emit_clear(device->cs, rect_count, rects, flags, color, depth, stencil);

    return WINED3D_OK;
}

void CDECL wined3d_device_set_predication(struct wined3d_device *device,
        struct wined3d_query *predicate, BOOL value)
{
    TRACE("device %p, predicate %p, value %#x.\n", device, predicate, value);

    wined3d_device_context_set_predication(&device->cs->c, predicate, value);
}

struct wined3d_query * CDECL wined3d_device_context_get_predication(struct wined3d_device_context *context, BOOL *value)
{
    struct wined3d_state *state = context->state;

    TRACE("context %p, value %p.\n", context, value);

    if (value)
        *value = state->predicate_value;
    return state->predicate;
}

void CDECL wined3d_device_dispatch_compute(struct wined3d_device *device,
        unsigned int group_count_x, unsigned int group_count_y, unsigned int group_count_z)
{
    TRACE("device %p, group_count_x %u, group_count_y %u, group_count_z %u.\n",
            device, group_count_x, group_count_y, group_count_z);

    wined3d_device_context_dispatch(&device->cs->c, group_count_x, group_count_y, group_count_z);
}

void CDECL wined3d_device_dispatch_compute_indirect(struct wined3d_device *device,
        struct wined3d_buffer *buffer, unsigned int offset)
{
    TRACE("device %p, buffer %p, offset %u.\n", device, buffer, offset);

    wined3d_device_context_dispatch_indirect(&device->cs->c, buffer, offset);
}

void CDECL wined3d_device_context_set_primitive_type(struct wined3d_device_context *context,
        enum wined3d_primitive_type primitive_type, unsigned int patch_vertex_count)
{
    struct wined3d_state *state = context->state;

    TRACE("context %p, primitive_type %s, patch_vertex_count %u.\n",
            context, debug_d3dprimitivetype(primitive_type), patch_vertex_count);

    state->primitive_type = primitive_type;
    state->patch_vertex_count = patch_vertex_count;
}

void CDECL wined3d_device_context_get_primitive_type(const struct wined3d_device_context *context,
        enum wined3d_primitive_type *primitive_type, unsigned int *patch_vertex_count)
{
    const struct wined3d_state *state = context->state;

    TRACE("context %p, primitive_type %p, patch_vertex_count %p.\n",
            context, primitive_type, patch_vertex_count);

    *primitive_type = state->primitive_type;
    if (patch_vertex_count)
        *patch_vertex_count = state->patch_vertex_count;

    TRACE("Returning %s.\n", debug_d3dprimitivetype(*primitive_type));
}

HRESULT CDECL wined3d_device_draw_primitive(struct wined3d_device *device, UINT start_vertex, UINT vertex_count)
{
    TRACE("device %p, start_vertex %u, vertex_count %u.\n", device, start_vertex, vertex_count);

    wined3d_device_context_draw(&device->cs->c, start_vertex, vertex_count, 0, 0);

    return WINED3D_OK;
}

void CDECL wined3d_device_draw_primitive_instanced(struct wined3d_device *device,
        UINT start_vertex, UINT vertex_count, UINT start_instance, UINT instance_count)
{
    TRACE("device %p, start_vertex %u, vertex_count %u, start_instance %u, instance_count %u.\n",
            device, start_vertex, vertex_count, start_instance, instance_count);

    wined3d_device_context_draw(&device->cs->c, start_vertex, vertex_count, start_instance, instance_count);
}

void CDECL wined3d_device_draw_primitive_instanced_indirect(struct wined3d_device *device,
        struct wined3d_buffer *buffer, unsigned int offset)
{
    TRACE("device %p, buffer %p, offset %u.\n", device, buffer, offset);

    wined3d_device_context_draw_indirect(&device->cs->c, buffer, offset, false);
}

void CDECL wined3d_device_draw_indexed_primitive(struct wined3d_device *device, UINT start_idx, UINT index_count)
{
    struct wined3d_state *state = device->cs->c.state;

    TRACE("device %p, start_idx %u, index_count %u.\n", device, start_idx, index_count);

    wined3d_device_context_draw_indexed(&device->cs->c, state->base_vertex_index, start_idx, index_count, 0, 0);
}

void CDECL wined3d_device_draw_indexed_primitive_instanced(struct wined3d_device *device,
        UINT start_idx, UINT index_count, UINT start_instance, UINT instance_count)
{
    struct wined3d_state *state = device->cs->c.state;

    TRACE("device %p, start_idx %u, index_count %u, start_instance %u, instance_count %u.\n",
            device, start_idx, index_count, start_instance, instance_count);

    wined3d_device_context_draw_indexed(&device->cs->c, state->base_vertex_index,
            start_idx, index_count, start_instance, instance_count);
}

void CDECL wined3d_device_draw_indexed_primitive_instanced_indirect(struct wined3d_device *device,
        struct wined3d_buffer *buffer, unsigned int offset)
{
    TRACE("device %p, buffer %p, offset %u.\n", device, buffer, offset);

    wined3d_device_context_draw_indirect(&device->cs->c, buffer, offset, true);
}

HRESULT CDECL wined3d_device_update_texture(struct wined3d_device *device,
        struct wined3d_texture *src_texture, struct wined3d_texture *dst_texture)
{
    unsigned int src_size, dst_size, src_skip_levels = 0;
    unsigned int src_level_count, dst_level_count;
    const struct wined3d_dirty_regions *regions;
    unsigned int layer_count, level_count, i, j;
    enum wined3d_resource_type type;
    BOOL entire_texture = TRUE;
    struct wined3d_box box;

    TRACE("device %p, src_texture %p, dst_texture %p.\n", device, src_texture, dst_texture);

    /* Verify that the source and destination textures are non-NULL. */
    if (!src_texture || !dst_texture)
    {
        WARN("Source and destination textures must be non-NULL, returning WINED3DERR_INVALIDCALL.\n");
        return WINED3DERR_INVALIDCALL;
    }

    if (src_texture->resource.access & WINED3D_RESOURCE_ACCESS_GPU
            || src_texture->resource.usage & WINED3DUSAGE_SCRATCH)
    {
        WARN("Source resource is GPU accessible or a scratch resource.\n");
        return WINED3DERR_INVALIDCALL;
    }
    if (dst_texture->resource.access & WINED3D_RESOURCE_ACCESS_CPU)
    {
        WARN("Destination resource is CPU accessible.\n");
        return WINED3DERR_INVALIDCALL;
    }

    /* Verify that the source and destination textures are the same type. */
    type = src_texture->resource.type;
    if (dst_texture->resource.type != type)
    {
        WARN("Source and destination have different types, returning WINED3DERR_INVALIDCALL.\n");
        return WINED3DERR_INVALIDCALL;
    }

    layer_count = src_texture->layer_count;
    if (layer_count != dst_texture->layer_count)
    {
        WARN("Source and destination have different layer counts.\n");
        return WINED3DERR_INVALIDCALL;
    }

    if (src_texture->resource.format != dst_texture->resource.format)
    {
        WARN("Source and destination formats do not match.\n");
        return WINED3DERR_INVALIDCALL;
    }

    src_level_count = src_texture->level_count;
    dst_level_count = dst_texture->level_count;
    level_count = min(src_level_count, dst_level_count);

    src_size = max(src_texture->resource.width, src_texture->resource.height);
    src_size = max(src_size, src_texture->resource.depth);
    dst_size = max(dst_texture->resource.width, dst_texture->resource.height);
    dst_size = max(dst_size, dst_texture->resource.depth);
    while (src_size > dst_size)
    {
        src_size >>= 1;
        ++src_skip_levels;
    }

    if (wined3d_texture_get_level_width(src_texture, src_skip_levels) != dst_texture->resource.width
            || wined3d_texture_get_level_height(src_texture, src_skip_levels) != dst_texture->resource.height
            || wined3d_texture_get_level_depth(src_texture, src_skip_levels) != dst_texture->resource.depth)
    {
        WARN("Source and destination dimensions do not match.\n");
        return WINED3DERR_INVALIDCALL;
    }

    if ((regions = src_texture->dirty_regions))
    {
        for (i = 0; i < layer_count && entire_texture; ++i)
        {
            if (regions[i].box_count >= WINED3D_MAX_DIRTY_REGION_COUNT)
                continue;

            entire_texture = FALSE;
            break;
        }
    }

    /* Update every surface level of the texture. */
    if (entire_texture)
    {
        for (i = 0; i < level_count; ++i)
        {
            wined3d_texture_get_level_box(dst_texture, i, &box);
            for (j = 0; j < layer_count; ++j)
            {
                wined3d_device_context_emit_blt_sub_resource(&device->cs->c,
                        &dst_texture->resource, j * dst_level_count + i, &box,
                        &src_texture->resource, j * src_level_count + i + src_skip_levels, &box,
                        0, NULL, WINED3D_TEXF_POINT);
            }
        }
    }
    else
    {
        unsigned int src_level, box_count, k;
        const struct wined3d_box *boxes;
        struct wined3d_box b;

        for (i = 0; i < layer_count; ++i)
        {
            boxes = regions[i].boxes;
            box_count = regions[i].box_count;
            if (regions[i].box_count >= WINED3D_MAX_DIRTY_REGION_COUNT)
            {
                boxes = &b;
                box_count = 1;
                wined3d_texture_get_level_box(dst_texture, i, &b);
            }

            for (j = 0; j < level_count; ++j)
            {
                src_level = j + src_skip_levels;

                /* TODO: We could pass an array of boxes here to avoid
                 * multiple context acquisitions for the same resource. */
                for (k = 0; k < box_count; ++k)
                {
                    box = boxes[k];
                    if (src_level)
                    {
                        box.left >>= src_level;
                        box.top >>= src_level;
                        box.right = min((box.right + (1u << src_level) - 1) >> src_level,
                                wined3d_texture_get_level_width(src_texture, src_level));
                        box.bottom = min((box.bottom + (1u << src_level) - 1) >> src_level,
                                wined3d_texture_get_level_height(src_texture, src_level));
                        box.front >>= src_level;
                        box.back = min((box.back + (1u << src_level) - 1) >> src_level,
                                wined3d_texture_get_level_depth(src_texture, src_level));
                    }

                    wined3d_device_context_emit_blt_sub_resource(&device->cs->c,
                            &dst_texture->resource, i * dst_level_count + j, &box,
                            &src_texture->resource, i * src_level_count + src_level, &box,
                            0, NULL, WINED3D_TEXF_POINT);
                }
            }
        }
    }

    wined3d_texture_clear_dirty_regions(src_texture);

    return WINED3D_OK;
}

HRESULT CDECL wined3d_device_validate_device(const struct wined3d_device *device, DWORD *num_passes)
{
    const struct wined3d_state *state = device->cs->c.state;
    struct wined3d_texture *texture;
    DWORD i;

    TRACE("device %p, num_passes %p.\n", device, num_passes);

    for (i = 0; i < WINED3D_MAX_COMBINED_SAMPLERS; ++i)
    {
        if (state->sampler_states[i][WINED3D_SAMP_MIN_FILTER] == WINED3D_TEXF_NONE)
        {
            WARN("Sampler state %u has minfilter D3DTEXF_NONE, returning D3DERR_UNSUPPORTEDTEXTUREFILTER\n", i);
            return WINED3DERR_UNSUPPORTEDTEXTUREFILTER;
        }
        if (state->sampler_states[i][WINED3D_SAMP_MAG_FILTER] == WINED3D_TEXF_NONE)
        {
            WARN("Sampler state %u has magfilter D3DTEXF_NONE, returning D3DERR_UNSUPPORTEDTEXTUREFILTER\n", i);
            return WINED3DERR_UNSUPPORTEDTEXTUREFILTER;
        }

        texture = state->textures[i];
        if (!texture || texture->resource.format_flags & WINED3DFMT_FLAG_FILTERING) continue;

        if (state->sampler_states[i][WINED3D_SAMP_MAG_FILTER] != WINED3D_TEXF_POINT)
        {
            WARN("Non-filterable texture and mag filter enabled on sampler %u, returning E_FAIL\n", i);
            return E_FAIL;
        }
        if (state->sampler_states[i][WINED3D_SAMP_MIN_FILTER] != WINED3D_TEXF_POINT)
        {
            WARN("Non-filterable texture and min filter enabled on sampler %u, returning E_FAIL\n", i);
            return E_FAIL;
        }
        if (state->sampler_states[i][WINED3D_SAMP_MIP_FILTER] != WINED3D_TEXF_NONE
                && state->sampler_states[i][WINED3D_SAMP_MIP_FILTER] != WINED3D_TEXF_POINT)
        {
            WARN("Non-filterable texture and mip filter enabled on sampler %u, returning E_FAIL\n", i);
            return E_FAIL;
        }
    }

    if (wined3d_state_uses_depth_buffer(state)
            || (state->depth_stencil_state && state->depth_stencil_state->desc.stencil))
    {
        struct wined3d_rendertarget_view *rt = state->fb.render_targets[0];
        struct wined3d_rendertarget_view *ds = state->fb.depth_stencil;

        if (ds && rt && (ds->width < rt->width || ds->height < rt->height))
        {
            WARN("Depth stencil is smaller than the color buffer, returning D3DERR_CONFLICTINGRENDERSTATE\n");
            return WINED3DERR_CONFLICTINGRENDERSTATE;
        }
    }

    /* return a sensible default */
    *num_passes = 1;

    TRACE("returning D3D_OK\n");
    return WINED3D_OK;
}

void CDECL wined3d_device_set_software_vertex_processing(struct wined3d_device *device, BOOL software)
{
    static BOOL warned;

    TRACE("device %p, software %#x.\n", device, software);

    if (!warned)
    {
        FIXME("device %p, software %#x stub!\n", device, software);
        warned = TRUE;
    }

    device->softwareVertexProcessing = software;
}

BOOL CDECL wined3d_device_get_software_vertex_processing(const struct wined3d_device *device)
{
    static BOOL warned;

    TRACE("device %p.\n", device);

    if (!warned)
    {
        TRACE("device %p stub!\n", device);
        warned = TRUE;
    }

    return device->softwareVertexProcessing;
}

HRESULT CDECL wined3d_device_get_raster_status(const struct wined3d_device *device,
        UINT swapchain_idx, struct wined3d_raster_status *raster_status)
{
    struct wined3d_swapchain *swapchain;

    TRACE("device %p, swapchain_idx %u, raster_status %p.\n",
            device, swapchain_idx, raster_status);

    if (!(swapchain = wined3d_device_get_swapchain(device, swapchain_idx)))
        return WINED3DERR_INVALIDCALL;

    return wined3d_swapchain_get_raster_status(swapchain, raster_status);
}

HRESULT CDECL wined3d_device_set_npatch_mode(struct wined3d_device *device, float segments)
{
    static BOOL warned;

    TRACE("device %p, segments %.8e.\n", device, segments);

    if (segments != 0.0f)
    {
        if (!warned)
        {
            FIXME("device %p, segments %.8e stub!\n", device, segments);
            warned = TRUE;
        }
    }

    return WINED3D_OK;
}

float CDECL wined3d_device_get_npatch_mode(const struct wined3d_device *device)
{
    static BOOL warned;

    TRACE("device %p.\n", device);

    if (!warned)
    {
        FIXME("device %p stub!\n", device);
        warned = TRUE;
    }

    return 0.0f;
}

void CDECL wined3d_device_context_copy_uav_counter(struct wined3d_device_context *context,
        struct wined3d_buffer *dst_buffer, unsigned int offset, struct wined3d_unordered_access_view *uav)
{
    TRACE("context %p, dst_buffer %p, offset %u, uav %p.\n",
            context, dst_buffer, offset, uav);

    wined3d_device_context_emit_copy_uav_counter(context, dst_buffer, offset, uav);
}

static bool resources_format_compatible(const struct wined3d_resource *src_resource,
        const struct wined3d_resource *dst_resource)
{
    if (src_resource->format->id == dst_resource->format->id)
        return true;
    if (src_resource->format->typeless_id && src_resource->format->typeless_id == dst_resource->format->typeless_id)
        return true;
    if (src_resource->device->cs->c.state->feature_level < WINED3D_FEATURE_LEVEL_10_1)
        return false;
    if ((src_resource->format_flags & WINED3DFMT_FLAG_BLOCKS)
            && (dst_resource->format_flags & WINED3DFMT_FLAG_CAST_TO_BLOCK))
        return src_resource->format->block_byte_count == dst_resource->format->byte_count;
    if ((src_resource->format_flags & WINED3DFMT_FLAG_CAST_TO_BLOCK)
            && (dst_resource->format_flags & WINED3DFMT_FLAG_BLOCKS))
        return src_resource->format->byte_count == dst_resource->format->block_byte_count;
    return false;
}

void CDECL wined3d_device_context_copy_resource(struct wined3d_device_context *context,
        struct wined3d_resource *dst_resource, struct wined3d_resource *src_resource)
{
    unsigned int src_row_block_count, dst_row_block_count;
    struct wined3d_texture *dst_texture, *src_texture;
    unsigned int src_row_count, dst_row_count;
    struct wined3d_box src_box, dst_box;
    unsigned int i, j;

    TRACE("context %p, dst_resource %p, src_resource %p.\n", context, dst_resource, src_resource);

    if (src_resource == dst_resource)
    {
        WARN("Source and destination are the same resource.\n");
        return;
    }

    if (src_resource->type != dst_resource->type)
    {
        WARN("Resource types (%s / %s) don't match.\n",
                debug_d3dresourcetype(dst_resource->type),
                debug_d3dresourcetype(src_resource->type));
        return;
    }

    if (!resources_format_compatible(src_resource, dst_resource))
    {
        WARN("Resource formats %s and %s are incompatible.\n",
                debug_d3dformat(dst_resource->format->id),
                debug_d3dformat(src_resource->format->id));
        return;
    }

    src_row_block_count = (src_resource->width + (src_resource->format->block_width - 1))
            / src_resource->format->block_width;
    dst_row_block_count = (dst_resource->width + (dst_resource->format->block_width - 1))
            / dst_resource->format->block_width;
    src_row_count = (src_resource->height + (src_resource->format->block_height - 1))
            / src_resource->format->block_height;
    dst_row_count = (dst_resource->height + (dst_resource->format->block_height - 1))
            / dst_resource->format->block_height;

    if (src_row_block_count != dst_row_block_count || src_row_count != dst_row_count
            || src_resource->depth != dst_resource->depth)
    {
        WARN("Resource block dimensions (%ux%ux%u / %ux%ux%u) don't match.\n",
                dst_row_block_count, dst_row_count, dst_resource->depth,
                src_row_block_count, src_row_count, src_resource->depth);
        return;
    }

    if (dst_resource->type == WINED3D_RTYPE_BUFFER)
    {
        wined3d_box_set(&src_box, 0, 0, src_resource->size, 1, 0, 1);
        wined3d_device_context_emit_blt_sub_resource(context, dst_resource, 0, &src_box,
                src_resource, 0, &src_box, WINED3D_BLT_RAW, NULL, WINED3D_TEXF_POINT);
        return;
    }

    dst_texture = texture_from_resource(dst_resource);
    src_texture = texture_from_resource(src_resource);

    if (src_texture->layer_count != dst_texture->layer_count
            || src_texture->level_count != dst_texture->level_count)
    {
        WARN("Subresource layouts (%ux%u / %ux%u) don't match.\n",
                dst_texture->layer_count, dst_texture->level_count,
                src_texture->layer_count, src_texture->level_count);
        return;
    }

    for (i = 0; i < dst_texture->level_count; ++i)
    {
        wined3d_texture_get_level_box(src_texture, i, &src_box);
        wined3d_texture_get_level_box(dst_texture, i, &dst_box);
        for (j = 0; j < dst_texture->layer_count; ++j)
        {
            unsigned int idx = j * dst_texture->level_count + i;

            wined3d_device_context_emit_blt_sub_resource(context, dst_resource, idx, &dst_box,
                    src_resource, idx, &src_box, WINED3D_BLT_RAW, NULL, WINED3D_TEXF_POINT);
        }
    }
}

HRESULT CDECL wined3d_device_context_copy_sub_resource_region(struct wined3d_device_context *context,
        struct wined3d_resource *dst_resource, unsigned int dst_sub_resource_idx, unsigned int dst_x,
        unsigned int dst_y, unsigned int dst_z, struct wined3d_resource *src_resource,
        unsigned int src_sub_resource_idx, const struct wined3d_box *src_box, unsigned int flags)
{
    struct wined3d_box dst_box, b;

    TRACE("context %p, dst_resource %p, dst_sub_resource_idx %u, dst_x %u, dst_y %u, dst_z %u, "
            "src_resource %p, src_sub_resource_idx %u, src_box %s, flags %#x.\n",
            context, dst_resource, dst_sub_resource_idx, dst_x, dst_y, dst_z,
            src_resource, src_sub_resource_idx, debug_box(src_box), flags);

    if (flags)
        FIXME("Ignoring flags %#x.\n", flags);

    if (src_resource == dst_resource && src_sub_resource_idx == dst_sub_resource_idx)
    {
        WARN("Source and destination are the same sub-resource.\n");
        return WINED3DERR_INVALIDCALL;
    }

    if (!resources_format_compatible(src_resource, dst_resource))
    {
        WARN("Resource formats %s and %s are incompatible.\n",
                debug_d3dformat(dst_resource->format->id),
                debug_d3dformat(src_resource->format->id));
        return WINED3DERR_INVALIDCALL;
    }

    if (dst_resource->type == WINED3D_RTYPE_BUFFER)
    {
        if (src_resource->type != WINED3D_RTYPE_BUFFER)
        {
            WARN("Resource types (%s / %s) don't match.\n",
                    debug_d3dresourcetype(dst_resource->type),
                    debug_d3dresourcetype(src_resource->type));
            return WINED3DERR_INVALIDCALL;
        }

        if (dst_sub_resource_idx)
        {
            WARN("Invalid dst_sub_resource_idx %u.\n", dst_sub_resource_idx);
            return WINED3DERR_INVALIDCALL;
        }

        if (src_sub_resource_idx)
        {
            WARN("Invalid src_sub_resource_idx %u.\n", src_sub_resource_idx);
            return WINED3DERR_INVALIDCALL;
        }

        if (!src_box)
        {
            unsigned int dst_w;

            dst_w = dst_resource->size - dst_x;
            wined3d_box_set(&b, 0, 0, min(src_resource->size, dst_w), 1, 0, 1);
            src_box = &b;
        }
        else if ((src_box->left >= src_box->right
                || src_box->top >= src_box->bottom
                || src_box->front >= src_box->back))
        {
            WARN("Invalid box %s specified.\n", debug_box(src_box));
            return WINED3DERR_INVALIDCALL;
        }

        if (src_box->right > src_resource->size || dst_x >= dst_resource->size
                || src_box->right - src_box->left > dst_resource->size - dst_x)
        {
            WARN("Invalid range specified, dst_offset %u, src_offset %u, size %u.\n",
                    dst_x, src_box->left, src_box->right - src_box->left);
            return WINED3DERR_INVALIDCALL;
        }

        wined3d_box_set(&dst_box, dst_x, 0, dst_x + (src_box->right - src_box->left), 1, 0, 1);
    }
    else
    {
        struct wined3d_texture *dst_texture = texture_from_resource(dst_resource);
        struct wined3d_texture *src_texture = texture_from_resource(src_resource);
        unsigned int src_level = src_sub_resource_idx % src_texture->level_count;
        unsigned int src_row_block_count, src_row_count;

        if (dst_sub_resource_idx >= dst_texture->level_count * dst_texture->layer_count)
        {
            WARN("Invalid destination sub-resource %u.\n", dst_sub_resource_idx);
            return WINED3DERR_INVALIDCALL;
        }

        if (src_sub_resource_idx >= src_texture->level_count * src_texture->layer_count)
        {
            WARN("Invalid source sub-resource %u.\n", src_sub_resource_idx);
            return WINED3DERR_INVALIDCALL;
        }

        if (dst_texture->sub_resources[dst_sub_resource_idx].map_count)
        {
            WARN("Destination sub-resource %u is mapped.\n", dst_sub_resource_idx);
            return WINED3DERR_INVALIDCALL;
        }

        if (src_texture->sub_resources[src_sub_resource_idx].map_count)
        {
            WARN("Source sub-resource %u is mapped.\n", src_sub_resource_idx);
            return WINED3DERR_INVALIDCALL;
        }

        if (!src_box)
        {
            unsigned int src_w, src_h, src_d, dst_w, dst_h, dst_d, dst_level;

            src_w = wined3d_texture_get_level_width(src_texture, src_level);
            src_h = wined3d_texture_get_level_height(src_texture, src_level);
            src_d = wined3d_texture_get_level_depth(src_texture, src_level);

            dst_level = dst_sub_resource_idx % dst_texture->level_count;
            dst_w = wined3d_texture_get_level_width(dst_texture, dst_level) - dst_x;
            dst_h = wined3d_texture_get_level_height(dst_texture, dst_level) - dst_y;
            dst_d = wined3d_texture_get_level_depth(dst_texture, dst_level) - dst_z;

            wined3d_box_set(&b, 0, 0, min(src_w, dst_w), min(src_h, dst_h), 0, min(src_d, dst_d));
            src_box = &b;
        }
        else if (FAILED(wined3d_texture_check_box_dimensions(src_texture, src_level, src_box)))
        {
            WARN("Invalid source box %s.\n", debug_box(src_box));
            return WINED3DERR_INVALIDCALL;
        }

        if (src_resource->format->block_width == dst_resource->format->block_width
                && src_resource->format->block_height == dst_resource->format->block_height)
        {
            wined3d_box_set(&dst_box, dst_x, dst_y, dst_x + (src_box->right - src_box->left),
                    dst_y + (src_box->bottom - src_box->top), dst_z, dst_z + (src_box->back - src_box->front));
        }
        else
        {
            src_row_block_count = (src_box->right - src_box->left + src_resource->format->block_width - 1)
                    / src_resource->format->block_width;
            src_row_count = (src_box->bottom - src_box->top + src_resource->format->block_height - 1)
                    / src_resource->format->block_height;
            wined3d_box_set(&dst_box, dst_x, dst_y,
                    dst_x + (src_row_block_count * dst_resource->format->block_width),
                    dst_y + (src_row_count * dst_resource->format->block_height),
                    dst_z, dst_z + (src_box->back - src_box->front));
        }
        if (FAILED(wined3d_texture_check_box_dimensions(dst_texture,
                dst_sub_resource_idx % dst_texture->level_count, &dst_box)))
        {
            WARN("Invalid destination box %s.\n", debug_box(&dst_box));
            return WINED3DERR_INVALIDCALL;
        }
    }

    wined3d_device_context_emit_blt_sub_resource(context, dst_resource, dst_sub_resource_idx, &dst_box,
            src_resource, src_sub_resource_idx, src_box, WINED3D_BLT_RAW, NULL, WINED3D_TEXF_POINT);

    return WINED3D_OK;
}

void CDECL wined3d_device_context_update_sub_resource(struct wined3d_device_context *context,
        struct wined3d_resource *resource, unsigned int sub_resource_idx, const struct wined3d_box *box,
        const void *data, unsigned int row_pitch, unsigned int depth_pitch, unsigned int flags)
{
    unsigned int width, height, depth;
    struct wined3d_box b;

    TRACE("context %p, resource %p, sub_resource_idx %u, box %s, data %p, row_pitch %u, depth_pitch %u, flags %#x.\n",
            context, resource, sub_resource_idx, debug_box(box), data, row_pitch, depth_pitch, flags);

    if (flags)
        FIXME("Ignoring flags %#x.\n", flags);

    if (!(resource->access & WINED3D_RESOURCE_ACCESS_GPU))
    {
        WARN("Resource %p is not GPU accessible.\n", resource);
        return;
    }

    if (resource->type == WINED3D_RTYPE_BUFFER)
    {
        if (sub_resource_idx > 0)
        {
            WARN("Invalid sub_resource_idx %u.\n", sub_resource_idx);
            return;
        }

        width = resource->size;
        height = 1;
        depth = 1;
    }
    else
    {
        struct wined3d_texture *texture = texture_from_resource(resource);
        unsigned int level;

        if (sub_resource_idx >= texture->level_count * texture->layer_count)
        {
            WARN("Invalid sub_resource_idx %u.\n", sub_resource_idx);
            return;
        }

        level = sub_resource_idx % texture->level_count;
        width = wined3d_texture_get_level_width(texture, level);
        height = wined3d_texture_get_level_height(texture, level);
        depth = wined3d_texture_get_level_depth(texture, level);
    }

    if (!box)
    {
        wined3d_box_set(&b, 0, 0, width, height, 0, depth);
        box = &b;
    }
    else if (box->left >= box->right || box->right > width
            || box->top >= box->bottom || box->bottom > height
            || box->front >= box->back || box->back > depth)
    {
        WARN("Invalid box %s specified.\n", debug_box(box));
        return;
    }

    wined3d_device_context_emit_update_sub_resource(context, resource,
            sub_resource_idx, box, data, row_pitch, depth_pitch);
}

void CDECL wined3d_device_context_resolve_sub_resource(struct wined3d_device_context *context,
        struct wined3d_resource *dst_resource, unsigned int dst_sub_resource_idx,
        struct wined3d_resource *src_resource, unsigned int src_sub_resource_idx,
        enum wined3d_format_id format_id)
{
    struct wined3d_texture *dst_texture, *src_texture;
    unsigned int dst_level, src_level;
    struct wined3d_blt_fx fx = {0};
    RECT dst_rect, src_rect;

    TRACE("context %p, dst_resource %p, dst_sub_resource_idx %u, "
            "src_resource %p, src_sub_resource_idx %u, format %s.\n",
            context, dst_resource, dst_sub_resource_idx,
            src_resource, src_sub_resource_idx, debug_d3dformat(format_id));

    if (wined3d_format_is_typeless(dst_resource->format)
            || wined3d_format_is_typeless(src_resource->format))
    {
        FIXME("Multisample resolve is not fully supported for typeless formats "
                "(dst_format %s, src_format %s, format %s).\n",
                debug_d3dformat(dst_resource->format->id), debug_d3dformat(src_resource->format->id),
                debug_d3dformat(format_id));
    }
    if (dst_resource->type != WINED3D_RTYPE_TEXTURE_2D)
    {
        WARN("Invalid destination resource type %s.\n", debug_d3dresourcetype(dst_resource->type));
        return;
    }
    if (src_resource->type != WINED3D_RTYPE_TEXTURE_2D)
    {
        WARN("Invalid source resource type %s.\n", debug_d3dresourcetype(src_resource->type));
        return;
    }

    fx.resolve_format_id = format_id;

    dst_texture = texture_from_resource(dst_resource);
    src_texture = texture_from_resource(src_resource);

    dst_level = dst_sub_resource_idx % dst_texture->level_count;
    SetRect(&dst_rect, 0, 0, wined3d_texture_get_level_width(dst_texture, dst_level),
            wined3d_texture_get_level_height(dst_texture, dst_level));
    src_level = src_sub_resource_idx % src_texture->level_count;
    SetRect(&src_rect, 0, 0, wined3d_texture_get_level_width(src_texture, src_level),
            wined3d_texture_get_level_height(src_texture, src_level));
    wined3d_device_context_blt(context, dst_texture, dst_sub_resource_idx, &dst_rect,
            src_texture, src_sub_resource_idx, &src_rect, 0, &fx, WINED3D_TEXF_POINT);
}

HRESULT CDECL wined3d_device_context_clear_rendertarget_view(struct wined3d_device_context *context,
        struct wined3d_rendertarget_view *view, const RECT *rect, unsigned int flags,
        const struct wined3d_color *color, float depth, unsigned int stencil)
{
    struct wined3d_resource *resource;
    RECT r;

    TRACE("context %p, view %p, rect %s, flags %#x, color %s, depth %.8e, stencil %u.\n",
            context, view, wine_dbgstr_rect(rect), flags, debug_color(color), depth, stencil);

    if (!flags)
        return WINED3D_OK;

    resource = view->resource;
    if (resource->type == WINED3D_RTYPE_BUFFER)
    {
        FIXME("Not implemented for %s resources.\n", debug_d3dresourcetype(resource->type));
        return WINED3DERR_INVALIDCALL;
    }

    if (!rect)
    {
        SetRect(&r, 0, 0, view->width, view->height);
        rect = &r;
    }
    else
    {
        struct wined3d_box b = {rect->left, rect->top, rect->right, rect->bottom, 0, 1};
        struct wined3d_texture *texture = texture_from_resource(view->resource);
        HRESULT hr;

        if (FAILED(hr = wined3d_texture_check_box_dimensions(texture,
                view->sub_resource_idx % texture->level_count, &b)))
            return hr;
    }

    wined3d_device_context_emit_clear_rendertarget_view(context, view, rect, flags, color, depth, stencil);

    return WINED3D_OK;
}

void CDECL wined3d_device_context_clear_uav_uint(struct wined3d_device_context *context,
        struct wined3d_unordered_access_view *view, const struct wined3d_uvec4 *clear_value)
{
    TRACE("context %p, view %p, clear_value %s.\n", context, view, debug_uvec4(clear_value));

    wined3d_device_context_emit_clear_uav_uint(context, view, clear_value);
}

static unsigned int sanitise_map_flags(const struct wined3d_resource *resource, unsigned int flags)
{
    /* Not all flags make sense together, but Windows never returns an error.
     * Catch the cases that could cause issues. */
    if (flags & WINED3D_MAP_READ)
    {
        if (flags & WINED3D_MAP_DISCARD)
        {
            WARN("WINED3D_MAP_READ combined with WINED3D_MAP_DISCARD, ignoring flags.\n");
            return flags & (WINED3D_MAP_READ | WINED3D_MAP_WRITE);
        }
        if (flags & WINED3D_MAP_NOOVERWRITE)
        {
            WARN("WINED3D_MAP_READ combined with WINED3D_MAP_NOOVERWRITE, ignoring flags.\n");
            return flags & (WINED3D_MAP_READ | WINED3D_MAP_WRITE);
        }
    }
    else if (flags & (WINED3D_MAP_DISCARD | WINED3D_MAP_NOOVERWRITE))
    {
        if (!(resource->usage & WINED3DUSAGE_DYNAMIC))
        {
            WARN("DISCARD or NOOVERWRITE map on non-dynamic buffer, ignoring.\n");
            return flags & (WINED3D_MAP_READ | WINED3D_MAP_WRITE);
        }
        if ((flags & (WINED3D_MAP_DISCARD | WINED3D_MAP_NOOVERWRITE))
                == (WINED3D_MAP_DISCARD | WINED3D_MAP_NOOVERWRITE))
        {
            WARN("WINED3D_MAP_NOOVERWRITE used with WINED3D_MAP_DISCARD, ignoring WINED3D_MAP_DISCARD.\n");
            flags &= ~WINED3D_MAP_DISCARD;
        }
    }

    return flags;
}

HRESULT CDECL wined3d_device_context_map(struct wined3d_device_context *context,
        struct wined3d_resource *resource, unsigned int sub_resource_idx,
        struct wined3d_map_desc *map_desc, const struct wined3d_box *box, unsigned int flags)
{
    TRACE("context %p, resource %p, sub_resource_idx %u, map_desc %p, box %s, flags %#x.\n",
            context, resource, sub_resource_idx, map_desc, debug_box(box), flags);

    if (!(flags & (WINED3D_MAP_READ | WINED3D_MAP_WRITE)))
    {
        WARN("No read/write flags specified.\n");
        return E_INVALIDARG;
    }

    if ((flags & WINED3D_MAP_READ) && !(resource->access & WINED3D_RESOURCE_ACCESS_MAP_R))
    {
        WARN("Resource does not have MAP_R access.\n");
        return E_INVALIDARG;
    }

    if ((flags & WINED3D_MAP_WRITE) && !(resource->access & WINED3D_RESOURCE_ACCESS_MAP_W))
    {
        WARN("Resource does not have MAP_W access.\n");
        return E_INVALIDARG;
    }

    flags = sanitise_map_flags(resource, flags);
    wined3d_resource_wait_idle(resource);

    return context->ops->map(context, resource, sub_resource_idx, map_desc, box, flags);
}

HRESULT CDECL wined3d_device_context_unmap(struct wined3d_device_context *context,
        struct wined3d_resource *resource, unsigned int sub_resource_idx)
{
    TRACE("context %p, resource %p, sub_resource_idx %u.\n", context, resource, sub_resource_idx);

    return context->ops->unmap(context, resource, sub_resource_idx);
}

void CDECL wined3d_device_context_issue_query(struct wined3d_device_context *context,
        struct wined3d_query *query, unsigned int flags)
{
    TRACE("context %p, query %p, flags %#x.\n", context, query, flags);

    if (flags & WINED3DISSUE_END)
        ++query->counter_main;

    query->device->cs->c.ops->issue_query(context, query, flags);

    if (flags & WINED3DISSUE_BEGIN)
        query->state = QUERY_BUILDING;
    else
        query->state = QUERY_SIGNALLED;
}

struct wined3d_rendertarget_view * CDECL wined3d_device_context_get_rendertarget_view(
        const struct wined3d_device_context *context, unsigned int view_idx)
{
    unsigned int max_rt_count;

    TRACE("context %p, view_idx %u.\n", context, view_idx);

    max_rt_count = context->device->adapter->d3d_info.limits.max_rt_count;
    if (view_idx >= max_rt_count)
    {
        WARN("Only %u render targets are supported.\n", max_rt_count);
        return NULL;
    }

    return context->state->fb.render_targets[view_idx];
}

struct wined3d_rendertarget_view * CDECL wined3d_device_context_get_depth_stencil_view(
        const struct wined3d_device_context *context)
{
    TRACE("context %p.\n", context);

    return context->state->fb.depth_stencil;
}

HRESULT CDECL wined3d_device_set_rendertarget_view(struct wined3d_device *device,
        unsigned int view_idx, struct wined3d_rendertarget_view *view, BOOL set_viewport)
{
    TRACE("device %p, view_idx %u, view %p, set_viewport %#x.\n",
            device, view_idx, view, set_viewport);

    return wined3d_device_context_set_rendertarget_view(&device->cs->c, view_idx, view, set_viewport);
}

HRESULT CDECL wined3d_device_set_depth_stencil_view(struct wined3d_device *device,
        struct wined3d_rendertarget_view *view)
{
    TRACE("device %p, view %p.\n", device, view);

    return wined3d_device_context_set_depth_stencil_view(&device->cs->c, view);
}

void CDECL wined3d_device_context_generate_mipmaps(struct wined3d_device_context *context,
        struct wined3d_shader_resource_view *view)
{
    struct wined3d_texture *texture;

    TRACE("context %p, view %p.\n", context, view);

    if (view->resource->type == WINED3D_RTYPE_BUFFER)
    {
        WARN("Called on buffer resource %p.\n", view->resource);
        return;
    }

    texture = texture_from_resource(view->resource);
    if (!(texture->flags & WINED3D_TEXTURE_GENERATE_MIPMAPS))
    {
        WARN("Texture without the WINED3D_TEXTURE_GENERATE_MIPMAPS flag, ignoring.\n");
        return;
    }

    wined3d_device_context_emit_generate_mipmaps(context, view);
}

static struct wined3d_texture *wined3d_device_create_cursor_texture(struct wined3d_device *device,
        struct wined3d_texture *cursor_image, unsigned int sub_resource_idx)
{
    unsigned int texture_level = sub_resource_idx % cursor_image->level_count;
    struct wined3d_sub_resource_data data;
    struct wined3d_resource_desc desc;
    struct wined3d_map_desc map_desc;
    struct wined3d_texture *texture;
    HRESULT hr;

    if (FAILED(wined3d_resource_map(&cursor_image->resource, sub_resource_idx, &map_desc, NULL, WINED3D_MAP_READ)))
    {
        ERR("Failed to map source texture.\n");
        return NULL;
    }

    data.data = map_desc.data;
    data.row_pitch = map_desc.row_pitch;
    data.slice_pitch = map_desc.slice_pitch;

    desc.resource_type = WINED3D_RTYPE_TEXTURE_2D;
    desc.format = WINED3DFMT_B8G8R8A8_UNORM;
    desc.multisample_type = WINED3D_MULTISAMPLE_NONE;
    desc.multisample_quality = 0;
    desc.usage = WINED3DUSAGE_DYNAMIC;
    desc.bind_flags = 0;
    desc.access = WINED3D_RESOURCE_ACCESS_GPU;
    desc.width = wined3d_texture_get_level_width(cursor_image, texture_level);
    desc.height = wined3d_texture_get_level_height(cursor_image, texture_level);
    desc.depth = 1;
    desc.size = 0;

    hr = wined3d_texture_create(device, &desc, 1, 1, 0, &data, NULL, &wined3d_null_parent_ops, &texture);
    wined3d_resource_unmap(&cursor_image->resource, sub_resource_idx);
    if (FAILED(hr))
    {
        ERR("Failed to create cursor texture.\n");
        return NULL;
    }

    return texture;
}

HRESULT CDECL wined3d_device_set_cursor_properties(struct wined3d_device *device,
        UINT x_hotspot, UINT y_hotspot, struct wined3d_texture *texture, unsigned int sub_resource_idx)
{
    unsigned int texture_level = sub_resource_idx % texture->level_count;
    unsigned int cursor_width, cursor_height;
    struct wined3d_map_desc map_desc;

    TRACE("device %p, x_hotspot %u, y_hotspot %u, texture %p, sub_resource_idx %u.\n",
            device, x_hotspot, y_hotspot, texture, sub_resource_idx);

    if (sub_resource_idx >= texture->level_count * texture->layer_count
            || texture->resource.type != WINED3D_RTYPE_TEXTURE_2D)
        return WINED3DERR_INVALIDCALL;

    if (device->cursor_texture)
    {
        wined3d_texture_decref(device->cursor_texture);
        device->cursor_texture = NULL;
    }

    if (texture->resource.format->id != WINED3DFMT_B8G8R8A8_UNORM)
    {
        WARN("Texture %p has invalid format %s.\n",
                texture, debug_d3dformat(texture->resource.format->id));
        return WINED3DERR_INVALIDCALL;
    }

    /* Cursor width and height must all be powers of two */
    cursor_width = wined3d_texture_get_level_width(texture, texture_level);
    cursor_height = wined3d_texture_get_level_height(texture, texture_level);
    if ((cursor_width & (cursor_width - 1)) || (cursor_height & (cursor_height - 1)))
    {
        WARN("Cursor size %ux%u are not all powers of two.\n", cursor_width, cursor_height);
        return WINED3DERR_INVALIDCALL;
    }

    /* Do not store the surface's pointer because the application may
     * release it after setting the cursor image. Windows doesn't
     * addref the set surface, so we can't do this either without
     * creating circular refcount dependencies. */
    if (!(device->cursor_texture = wined3d_device_create_cursor_texture(device, texture, sub_resource_idx)))
    {
        ERR("Failed to create cursor texture.\n");
        return WINED3DERR_INVALIDCALL;
    }

    if (cursor_width == 32 && cursor_height == 32)
    {
        UINT mask_size = cursor_width * cursor_height / 8;
        ICONINFO cursor_info;
        DWORD *mask_bits;
        HCURSOR cursor;

        /* 32-bit user32 cursors ignore the alpha channel if it's all
         * zeroes, and use the mask instead. Fill the mask with all ones
         * to ensure we still get a fully transparent cursor. */
        if (!(mask_bits = heap_alloc(mask_size)))
            return E_OUTOFMEMORY;
        memset(mask_bits, 0xff, mask_size);

        wined3d_resource_map(&texture->resource, sub_resource_idx, &map_desc, NULL,
                WINED3D_MAP_NO_DIRTY_UPDATE | WINED3D_MAP_READ);
        cursor_info.fIcon = FALSE;
        cursor_info.xHotspot = x_hotspot;
        cursor_info.yHotspot = y_hotspot;
        cursor_info.hbmMask = CreateBitmap(cursor_width, cursor_height, 1, 1, mask_bits);
        cursor_info.hbmColor = CreateBitmap(cursor_width, cursor_height, 1, 32, map_desc.data);
        wined3d_resource_unmap(&texture->resource, sub_resource_idx);

        /* Create our cursor and clean up. */
        cursor = CreateIconIndirect(&cursor_info);
        if (cursor_info.hbmMask)
            DeleteObject(cursor_info.hbmMask);
        if (cursor_info.hbmColor)
            DeleteObject(cursor_info.hbmColor);
        if (device->hardwareCursor)
            DestroyCursor(device->hardwareCursor);
        device->hardwareCursor = cursor;
        if (device->bCursorVisible)
            SetCursor(cursor);

        heap_free(mask_bits);
    }

    TRACE("New cursor dimensions are %ux%u.\n", cursor_width, cursor_height);
    device->cursorWidth = cursor_width;
    device->cursorHeight = cursor_height;
    device->xHotSpot = x_hotspot;
    device->yHotSpot = y_hotspot;

    return WINED3D_OK;
}

void CDECL wined3d_device_set_cursor_position(struct wined3d_device *device,
        int x_screen_space, int y_screen_space, DWORD flags)
{
    TRACE("device %p, x %d, y %d, flags %#x.\n",
            device, x_screen_space, y_screen_space, flags);

    device->xScreenSpace = x_screen_space;
    device->yScreenSpace = y_screen_space;

    if (device->hardwareCursor)
    {
        POINT pt;

        GetCursorPos( &pt );
        if (x_screen_space == pt.x && y_screen_space == pt.y)
            return;
        SetCursorPos( x_screen_space, y_screen_space );

        /* Switch to the software cursor if position diverges from the hardware one. */
        GetCursorPos( &pt );
        if (x_screen_space != pt.x || y_screen_space != pt.y)
        {
            if (device->bCursorVisible) SetCursor( NULL );
            DestroyCursor( device->hardwareCursor );
            device->hardwareCursor = 0;
        }
    }
}

BOOL CDECL wined3d_device_show_cursor(struct wined3d_device *device, BOOL show)
{
    BOOL oldVisible = device->bCursorVisible;

    TRACE("device %p, show %#x.\n", device, show);

    /*
     * When ShowCursor is first called it should make the cursor appear at the OS's last
     * known cursor position.
     */
    if (show && !oldVisible)
    {
        POINT pt;
        GetCursorPos(&pt);
        device->xScreenSpace = pt.x;
        device->yScreenSpace = pt.y;
    }

    if (device->hardwareCursor)
    {
        device->bCursorVisible = show;
        if (show)
            SetCursor(device->hardwareCursor);
        else
            SetCursor(NULL);
    }
    else if (device->cursor_texture)
    {
        device->bCursorVisible = show;
    }

    return oldVisible;
}

void CDECL wined3d_device_evict_managed_resources(struct wined3d_device *device)
{
    struct wined3d_resource *resource, *cursor;

    TRACE("device %p.\n", device);

    LIST_FOR_EACH_ENTRY_SAFE(resource, cursor, &device->resources, struct wined3d_resource, resource_list_entry)
    {
        TRACE("Checking resource %p for eviction.\n", resource);

        if (wined3d_resource_access_is_managed(resource->access) && !resource->map_count)
        {
            TRACE("Evicting %p.\n", resource);
            wined3d_cs_emit_unload_resource(device->cs, resource);
        }
    }
}

void CDECL wined3d_device_context_flush(struct wined3d_device_context *context)
{
    TRACE("context %p.\n", context);

    context->ops->flush(context);
}

static void update_swapchain_flags(struct wined3d_texture *texture)
{
    unsigned int flags = texture->swapchain->state.desc.flags;

    if (flags & WINED3D_SWAPCHAIN_LOCKABLE_BACKBUFFER)
        texture->resource.access |= WINED3D_RESOURCE_ACCESS_MAP_R | WINED3D_RESOURCE_ACCESS_MAP_W;
    else
        texture->resource.access &= ~(WINED3D_RESOURCE_ACCESS_MAP_R | WINED3D_RESOURCE_ACCESS_MAP_W);

    if (flags & WINED3D_SWAPCHAIN_GDI_COMPATIBLE)
        texture->flags |= WINED3D_TEXTURE_GET_DC;
    else
        texture->flags &= ~WINED3D_TEXTURE_GET_DC;
}

HRESULT CDECL wined3d_device_reset(struct wined3d_device *device,
        const struct wined3d_swapchain_desc *swapchain_desc, const struct wined3d_display_mode *mode,
        wined3d_device_reset_cb callback, BOOL reset_state)
{
    const struct wined3d_d3d_info *d3d_info = &device->adapter->d3d_info;
    struct wined3d_swapchain_state *swapchain_state;
    struct wined3d_swapchain_desc *current_desc;
    struct wined3d_state *state = device->cs->c.state;
    struct wined3d_resource *resource, *cursor;
    struct wined3d_rendertarget_view *view;
    struct wined3d_swapchain *swapchain;
    struct wined3d_view_desc view_desc;
    BOOL backbuffer_resized, windowed;
    HRESULT hr = WINED3D_OK;
    unsigned int i;

    TRACE("device %p, swapchain_desc %p, mode %p, callback %p, reset_state %#x.\n",
            device, swapchain_desc, mode, callback, reset_state);

    wined3d_cs_finish(device->cs, WINED3D_CS_QUEUE_DEFAULT);

    if (!(swapchain = wined3d_device_get_swapchain(device, 0)))
    {
        ERR("Failed to get the first implicit swapchain.\n");
        return WINED3DERR_INVALIDCALL;
    }
    swapchain_state = &swapchain->state;
    current_desc = &swapchain_state->desc;

    if (reset_state)
    {
        if (device->logo_texture)
        {
            wined3d_texture_decref(device->logo_texture);
            device->logo_texture = NULL;
        }
        if (device->cursor_texture)
        {
            wined3d_texture_decref(device->cursor_texture);
            device->cursor_texture = NULL;
        }
        state_unbind_resources(state);
    }

    for (i = 0; i < d3d_info->limits.max_rt_count; ++i)
    {
        wined3d_device_set_rendertarget_view(device, i, NULL, FALSE);
    }
    wined3d_device_set_depth_stencil_view(device, NULL);

    if (reset_state)
    {
        LIST_FOR_EACH_ENTRY_SAFE(resource, cursor, &device->resources, struct wined3d_resource, resource_list_entry)
        {
            TRACE("Enumerating resource %p.\n", resource);
            if (FAILED(hr = callback(resource)))
                return hr;
        }
    }

    TRACE("New params:\n");
    TRACE("output %p\n", swapchain_desc->output);
    TRACE("backbuffer_width %u\n", swapchain_desc->backbuffer_width);
    TRACE("backbuffer_height %u\n", swapchain_desc->backbuffer_height);
    TRACE("backbuffer_format %s\n", debug_d3dformat(swapchain_desc->backbuffer_format));
    TRACE("backbuffer_count %u\n", swapchain_desc->backbuffer_count);
    TRACE("multisample_type %#x\n", swapchain_desc->multisample_type);
    TRACE("multisample_quality %u\n", swapchain_desc->multisample_quality);
    TRACE("swap_effect %#x\n", swapchain_desc->swap_effect);
    TRACE("device_window %p\n", swapchain_desc->device_window);
    TRACE("windowed %#x\n", swapchain_desc->windowed);
    TRACE("enable_auto_depth_stencil %#x\n", swapchain_desc->enable_auto_depth_stencil);
    if (swapchain_desc->enable_auto_depth_stencil)
        TRACE("auto_depth_stencil_format %s\n", debug_d3dformat(swapchain_desc->auto_depth_stencil_format));
    TRACE("flags %#x\n", swapchain_desc->flags);
    TRACE("refresh_rate %u\n", swapchain_desc->refresh_rate);
    TRACE("auto_restore_display_mode %#x\n", swapchain_desc->auto_restore_display_mode);

    if (swapchain_desc->backbuffer_bind_flags && swapchain_desc->backbuffer_bind_flags != WINED3D_BIND_RENDER_TARGET)
        FIXME("Got unexpected backbuffer bind flags %#x.\n", swapchain_desc->backbuffer_bind_flags);

    if (swapchain_desc->swap_effect != WINED3D_SWAP_EFFECT_DISCARD
            && swapchain_desc->swap_effect != WINED3D_SWAP_EFFECT_SEQUENTIAL
            && swapchain_desc->swap_effect != WINED3D_SWAP_EFFECT_COPY)
        FIXME("Unimplemented swap effect %#x.\n", swapchain_desc->swap_effect);

    /* No special treatment of these parameters. Just store them */
    current_desc->swap_effect = swapchain_desc->swap_effect;
    current_desc->enable_auto_depth_stencil = swapchain_desc->enable_auto_depth_stencil;
    current_desc->auto_depth_stencil_format = swapchain_desc->auto_depth_stencil_format;
    current_desc->refresh_rate = swapchain_desc->refresh_rate;
    current_desc->auto_restore_display_mode = swapchain_desc->auto_restore_display_mode;

    if (swapchain_desc->device_window && swapchain_desc->device_window != current_desc->device_window)
    {
        TRACE("Changing the device window from %p to %p.\n",
                current_desc->device_window, swapchain_desc->device_window);
        current_desc->device_window = swapchain_desc->device_window;
        swapchain_state->device_window = swapchain_desc->device_window;
        wined3d_swapchain_set_window(swapchain, NULL);
    }

    backbuffer_resized = swapchain_desc->backbuffer_width != current_desc->backbuffer_width
            || swapchain_desc->backbuffer_height != current_desc->backbuffer_height;
    windowed = current_desc->windowed;

    if (!swapchain_desc->windowed != !windowed || swapchain->reapply_mode
            || mode || (!swapchain_desc->windowed && backbuffer_resized))
    {
        /* Switch from windowed to fullscreen. */
        if (windowed && !swapchain_desc->windowed)
        {
            HWND focus_window = device->create_parms.focus_window;

            if (!focus_window)
                focus_window = swapchain->state.device_window;
            if (FAILED(hr = wined3d_device_acquire_focus_window(device, focus_window)))
            {
                ERR("Failed to acquire focus window, hr %#x.\n", hr);
                return hr;
            }
        }

        if (FAILED(hr = wined3d_swapchain_state_set_fullscreen(&swapchain->state,
                swapchain_desc, mode)))
            return hr;

        /* Switch from fullscreen to windowed. */
        if (!windowed && swapchain_desc->windowed)
            wined3d_device_release_focus_window(device);
    }
    else if (!swapchain_desc->windowed)
    {
        DWORD style = swapchain_state->style;
        DWORD exstyle = swapchain_state->exstyle;
        struct wined3d_output_desc output_desc;

        /* If we're in fullscreen, and the mode wasn't changed, we have to get
         * the window back into the right position. Some applications
         * (Battlefield 2, Guild Wars) move it and then call Reset() to clean
         * up their mess. Guild Wars also loses the device during that. */
        if (FAILED(hr = wined3d_output_get_desc(swapchain_desc->output, &output_desc)))
        {
            ERR("Failed to get output description, hr %#x.\n", hr);
            return hr;
        }

        swapchain_state->style = 0;
        swapchain_state->exstyle = 0;
        wined3d_swapchain_state_setup_fullscreen(swapchain_state, swapchain_state->device_window,
                output_desc.desktop_rect.left, output_desc.desktop_rect.top,
                swapchain_desc->backbuffer_width, swapchain_desc->backbuffer_height);
        swapchain_state->style = style;
        swapchain_state->exstyle = exstyle;
    }

    if (FAILED(hr = wined3d_swapchain_resize_buffers(swapchain, swapchain_desc->backbuffer_count,
            swapchain_desc->backbuffer_width, swapchain_desc->backbuffer_height, swapchain_desc->backbuffer_format,
            swapchain_desc->multisample_type, swapchain_desc->multisample_quality)))
        return hr;

    if (swapchain_desc->flags != current_desc->flags)
    {
        current_desc->flags = swapchain_desc->flags;

        update_swapchain_flags(swapchain->front_buffer);
        for (i = 0; i < current_desc->backbuffer_count; ++i)
        {
            update_swapchain_flags(swapchain->back_buffers[i]);
        }
    }

    if ((view = device->auto_depth_stencil_view))
    {
        device->auto_depth_stencil_view = NULL;
        wined3d_rendertarget_view_decref(view);
    }
    if (current_desc->enable_auto_depth_stencil)
    {
        struct wined3d_resource_desc texture_desc;
        struct wined3d_texture *texture;

        TRACE("Creating the depth stencil buffer.\n");

        texture_desc.resource_type = WINED3D_RTYPE_TEXTURE_2D;
        texture_desc.format = current_desc->auto_depth_stencil_format;
        texture_desc.multisample_type = current_desc->multisample_type;
        texture_desc.multisample_quality = current_desc->multisample_quality;
        texture_desc.usage = 0;
        texture_desc.bind_flags = WINED3D_BIND_DEPTH_STENCIL;
        texture_desc.access = WINED3D_RESOURCE_ACCESS_GPU;
        texture_desc.width = current_desc->backbuffer_width;
        texture_desc.height = current_desc->backbuffer_height;
        texture_desc.depth = 1;
        texture_desc.size = 0;

        if (FAILED(hr = device->device_parent->ops->create_swapchain_texture(device->device_parent,
                device->device_parent, &texture_desc, 0, &texture)))
        {
            ERR("Failed to create the auto depth/stencil surface, hr %#x.\n", hr);
            return WINED3DERR_INVALIDCALL;
        }

        view_desc.format_id = texture->resource.format->id;
        view_desc.flags = 0;
        view_desc.u.texture.level_idx = 0;
        view_desc.u.texture.level_count = 1;
        view_desc.u.texture.layer_idx = 0;
        view_desc.u.texture.layer_count = 1;
        hr = wined3d_rendertarget_view_create(&view_desc, &texture->resource,
                NULL, &wined3d_null_parent_ops, &device->auto_depth_stencil_view);
        wined3d_texture_decref(texture);
        if (FAILED(hr))
        {
            ERR("Failed to create rendertarget view, hr %#x.\n", hr);
            return hr;
        }
    }

    if ((view = device->back_buffer_view))
    {
        device->back_buffer_view = NULL;
        wined3d_rendertarget_view_decref(view);
    }
    if (current_desc->backbuffer_count && current_desc->backbuffer_bind_flags & WINED3D_BIND_RENDER_TARGET)
    {
        struct wined3d_resource *back_buffer = &swapchain->back_buffers[0]->resource;

        view_desc.format_id = back_buffer->format->id;
        view_desc.flags = 0;
        view_desc.u.texture.level_idx = 0;
        view_desc.u.texture.level_count = 1;
        view_desc.u.texture.layer_idx = 0;
        view_desc.u.texture.layer_count = 1;
        if (FAILED(hr = wined3d_rendertarget_view_create(&view_desc, back_buffer,
                NULL, &wined3d_null_parent_ops, &device->back_buffer_view)))
        {
            ERR("Failed to create rendertarget view, hr %#x.\n", hr);
            return hr;
        }
    }

    wine_rb_clear(&device->samplers, device_free_sampler, NULL);
    wine_rb_clear(&device->rasterizer_states, device_free_rasterizer_state, NULL);
    wine_rb_clear(&device->blend_states, device_free_blend_state, NULL);
    wine_rb_clear(&device->depth_stencil_states, device_free_depth_stencil_state, NULL);

    if (reset_state)
    {
        TRACE("Resetting state.\n");
        wined3d_cs_emit_reset_state(device->cs);
        state_cleanup(state);

        LIST_FOR_EACH_ENTRY_SAFE(resource, cursor, &device->resources, struct wined3d_resource, resource_list_entry)
        {
            TRACE("Unloading resource %p.\n", resource);
            wined3d_cs_emit_unload_resource(device->cs, resource);
        }

        device->adapter->adapter_ops->adapter_uninit_3d(device);

        wined3d_state_reset(state, &device->adapter->d3d_info);

        device_init_swapchain_state(device, swapchain);
        if (wined3d_settings.logo)
            device_load_logo(device, wined3d_settings.logo);
    }
    else
    {
        if ((view = device->back_buffer_view))
            wined3d_device_set_rendertarget_view(device, 0, view, FALSE);
        if ((view = device->auto_depth_stencil_view))
            wined3d_device_set_depth_stencil_view(device, view);
    }

    if (reset_state)
        hr = device->adapter->adapter_ops->adapter_init_3d(device);

    /* All done. There is no need to reload resources or shaders, this will happen automatically on the
     * first use
     */
    return hr;
}

HRESULT CDECL wined3d_device_set_dialog_box_mode(struct wined3d_device *device, BOOL enable_dialogs)
{
    TRACE("device %p, enable_dialogs %#x.\n", device, enable_dialogs);

    if (!enable_dialogs) FIXME("Dialogs cannot be disabled yet.\n");

    return WINED3D_OK;
}


void CDECL wined3d_device_get_creation_parameters(const struct wined3d_device *device,
        struct wined3d_device_creation_parameters *parameters)
{
    TRACE("device %p, parameters %p.\n", device, parameters);

    *parameters = device->create_parms;
}

struct wined3d * CDECL wined3d_device_get_wined3d(const struct wined3d_device *device)
{
    TRACE("device %p.\n", device);

    return device->wined3d;
}

void CDECL wined3d_device_set_gamma_ramp(const struct wined3d_device *device,
        UINT swapchain_idx, DWORD flags, const struct wined3d_gamma_ramp *ramp)
{
    struct wined3d_swapchain *swapchain;

    TRACE("device %p, swapchain_idx %u, flags %#x, ramp %p.\n",
            device, swapchain_idx, flags, ramp);

    if ((swapchain = wined3d_device_get_swapchain(device, swapchain_idx)))
        wined3d_swapchain_set_gamma_ramp(swapchain, flags, ramp);
}

void CDECL wined3d_device_get_gamma_ramp(const struct wined3d_device *device,
        UINT swapchain_idx, struct wined3d_gamma_ramp *ramp)
{
    struct wined3d_swapchain *swapchain;

    TRACE("device %p, swapchain_idx %u, ramp %p.\n",
            device, swapchain_idx, ramp);

    if ((swapchain = wined3d_device_get_swapchain(device, swapchain_idx)))
        wined3d_swapchain_get_gamma_ramp(swapchain, ramp);
}

void device_resource_add(struct wined3d_device *device, struct wined3d_resource *resource)
{
    TRACE("device %p, resource %p.\n", device, resource);

    wined3d_not_from_cs(device->cs);

    list_add_head(&device->resources, &resource->resource_list_entry);
}

static void device_resource_remove(struct wined3d_device *device, struct wined3d_resource *resource)
{
    TRACE("device %p, resource %p.\n", device, resource);

    wined3d_not_from_cs(device->cs);

    list_remove(&resource->resource_list_entry);
}

void device_resource_released(struct wined3d_device *device, struct wined3d_resource *resource)
{
    enum wined3d_resource_type type = resource->type;
    struct wined3d_state *state = device->cs->c.state;
    struct wined3d_rendertarget_view *rtv;
    unsigned int i;

    TRACE("device %p, resource %p, type %s.\n", device, resource, debug_d3dresourcetype(type));

    for (i = 0; i < ARRAY_SIZE(state->fb.render_targets); ++i)
    {
        if ((rtv = state->fb.render_targets[i]) && rtv->resource == resource)
            ERR("Resource %p is still in use as render target %u.\n", resource, i);
    }

    if ((rtv = state->fb.depth_stencil) && rtv->resource == resource)
        ERR("Resource %p is still in use as depth/stencil buffer.\n", resource);

    switch (type)
    {
        case WINED3D_RTYPE_TEXTURE_1D:
        case WINED3D_RTYPE_TEXTURE_2D:
        case WINED3D_RTYPE_TEXTURE_3D:
            for (i = 0; i < WINED3D_MAX_COMBINED_SAMPLERS; ++i)
            {
                if (&state->textures[i]->resource == resource)
                {
                    ERR("Texture resource %p is still in use, stage %u.\n", resource, i);
                    state->textures[i] = NULL;
                }
            }
            break;

        case WINED3D_RTYPE_BUFFER:
            for (i = 0; i < WINED3D_MAX_STREAMS; ++i)
            {
                if (&state->streams[i].buffer->resource == resource)
                {
                    ERR("Buffer resource %p is still in use, stream %u.\n", resource, i);
                    state->streams[i].buffer = NULL;
                }
            }

            if (&state->index_buffer->resource == resource)
            {
                ERR("Buffer resource %p is still in use as index buffer.\n", resource);
                state->index_buffer =  NULL;
            }
            break;

        default:
            break;
    }

    /* Remove the resource from the resourceStore */
    device_resource_remove(device, resource);

    TRACE("Resource released.\n");
}

static int wined3d_so_desc_compare(const void *key, const struct wine_rb_entry *entry)
{
    const struct wined3d_stream_output_desc *desc = &WINE_RB_ENTRY_VALUE(entry,
            struct wined3d_so_desc_entry, entry)->desc;
    const struct wined3d_stream_output_desc *k = key;
    unsigned int i;
    int ret;

    if ((ret = (k->element_count - desc->element_count)))
        return ret;
    if ((ret = (k->buffer_stride_count - desc->buffer_stride_count)))
        return ret;
    if ((ret = (k->rasterizer_stream_idx - desc->rasterizer_stream_idx)))
        return ret;

    for (i = 0; i < k->element_count; ++i)
    {
        const struct wined3d_stream_output_element *b = &desc->elements[i];
        const struct wined3d_stream_output_element *a = &k->elements[i];

        if ((ret = (a->stream_idx - b->stream_idx)))
            return ret;
        if ((ret = strcmp(a->semantic_name, b->semantic_name)))
            return ret;
        if ((ret = (a->semantic_idx - b->semantic_idx)))
            return ret;
        if ((ret = (a->component_idx - b->component_idx)))
            return ret;
        if ((ret = (a->component_count - b->component_count)))
            return ret;
        if ((ret = (a->output_slot - b->output_slot)))
            return ret;
    }

    for (i = 0; i < k->buffer_stride_count; ++i)
    {
        if ((ret = (k->buffer_strides[i] - desc->buffer_strides[i])))
            return ret;
    }

    return 0;
}

static int wined3d_sampler_compare(const void *key, const struct wine_rb_entry *entry)
{
    const struct wined3d_sampler *sampler = WINE_RB_ENTRY_VALUE(entry, struct wined3d_sampler, entry);

    return memcmp(&sampler->desc, key, sizeof(sampler->desc));
}

static int wined3d_rasterizer_state_compare(const void *key, const struct wine_rb_entry *entry)
{
    const struct wined3d_rasterizer_state *state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_rasterizer_state, entry);

    return memcmp(&state->desc, key, sizeof(state->desc));
}

static int wined3d_blend_state_compare(const void *key, const struct wine_rb_entry *entry)
{
    const struct wined3d_blend_state *state = WINE_RB_ENTRY_VALUE(entry, struct wined3d_blend_state, entry);

    return memcmp(&state->desc, key, sizeof(state->desc));
}

static int wined3d_depth_stencil_state_compare(const void *key, const struct wine_rb_entry *entry)
{
    const struct wined3d_depth_stencil_state *state
            = WINE_RB_ENTRY_VALUE(entry, struct wined3d_depth_stencil_state, entry);

    return memcmp(&state->desc, key, sizeof(state->desc));
}

HRESULT wined3d_device_init(struct wined3d_device *device, struct wined3d *wined3d,
        unsigned int adapter_idx, enum wined3d_device_type device_type, HWND focus_window, unsigned int flags,
        BYTE surface_alignment, const enum wined3d_feature_level *levels, unsigned int level_count,
        const BOOL *supported_extensions, struct wined3d_device_parent *device_parent)
{
    struct wined3d_adapter *adapter = wined3d->adapters[adapter_idx];
    const struct wined3d_fragment_pipe_ops *fragment_pipeline;
    const struct wined3d_vertex_pipe_ops *vertex_pipeline;
    unsigned int i;
    HRESULT hr;

    device->ref = 1;
    device->wined3d = wined3d;
    wined3d_incref(device->wined3d);
    device->adapter = adapter;
    device->device_parent = device_parent;
    list_init(&device->resources);
    list_init(&device->shaders);
    device->surface_alignment = surface_alignment;

    /* Save the creation parameters. */
    device->create_parms.adapter_idx = adapter_idx;
    device->create_parms.device_type = device_type;
    device->create_parms.focus_window = focus_window;
    device->create_parms.flags = flags;

    device->shader_backend = adapter->shader_backend;

    vertex_pipeline = adapter->vertex_pipe;

    fragment_pipeline = adapter->fragment_pipe;

    wine_rb_init(&device->so_descs, wined3d_so_desc_compare);
    wine_rb_init(&device->samplers, wined3d_sampler_compare);
    wine_rb_init(&device->rasterizer_states, wined3d_rasterizer_state_compare);
    wine_rb_init(&device->blend_states, wined3d_blend_state_compare);
    wine_rb_init(&device->depth_stencil_states, wined3d_depth_stencil_state_compare);

    if (vertex_pipeline->vp_states && fragment_pipeline->states
            && FAILED(hr = compile_state_table(device->state_table, device->multistate_funcs,
            &adapter->d3d_info, supported_extensions, vertex_pipeline,
            fragment_pipeline, adapter->misc_state_template)))
    {
        ERR("Failed to compile state table, hr %#x.\n", hr);
        wine_rb_destroy(&device->samplers, NULL, NULL);
        wine_rb_destroy(&device->rasterizer_states, NULL, NULL);
        wine_rb_destroy(&device->blend_states, NULL, NULL);
        wine_rb_destroy(&device->depth_stencil_states, NULL, NULL);
        wine_rb_destroy(&device->so_descs, NULL, NULL);
        wined3d_decref(device->wined3d);
        return hr;
    }

    device->max_frame_latency = 3;

    if (!(device->cs = wined3d_cs_create(device, levels, level_count)))
    {
        WARN("Failed to create command stream.\n");
        hr = E_FAIL;
        goto err;
    }

    return WINED3D_OK;

err:
    for (i = 0; i < ARRAY_SIZE(device->multistate_funcs); ++i)
    {
        heap_free(device->multistate_funcs[i]);
    }
    wine_rb_destroy(&device->samplers, NULL, NULL);
    wine_rb_destroy(&device->rasterizer_states, NULL, NULL);
    wine_rb_destroy(&device->blend_states, NULL, NULL);
    wine_rb_destroy(&device->depth_stencil_states, NULL, NULL);
    wine_rb_destroy(&device->so_descs, NULL, NULL);
    wined3d_decref(device->wined3d);
    return hr;
}

void device_invalidate_state(const struct wined3d_device *device, unsigned int state_id)
{
    unsigned int representative, i, idx, shift;
    struct wined3d_context *context;

    wined3d_from_cs(device->cs);

    if (STATE_IS_COMPUTE(state_id))
    {
        for (i = 0; i < device->context_count; ++i)
            context_invalidate_compute_state(device->contexts[i], state_id);
        return;
    }

    representative = device->state_table[state_id].representative;
    idx = representative / (sizeof(*context->dirty_graphics_states) * CHAR_BIT);
    shift = representative & ((sizeof(*context->dirty_graphics_states) * CHAR_BIT) - 1);
    for (i = 0; i < device->context_count; ++i)
    {
        device->contexts[i]->dirty_graphics_states[idx] |= (1u << shift);
    }
}

LRESULT device_process_message(struct wined3d_device *device, HWND window, BOOL unicode,
        UINT message, WPARAM wparam, LPARAM lparam, WNDPROC proc)
{
    if (message == WM_DESTROY)
    {
        TRACE("unregister window %p.\n", window);
        wined3d_unregister_window(window);

        if (InterlockedCompareExchangePointer((void **)&device->focus_window, NULL, window) != window)
            ERR("Window %p is not the focus window for device %p.\n", window, device);
    }
    else if (message == WM_DISPLAYCHANGE)
    {
        device->device_parent->ops->mode_changed(device->device_parent);
    }
    else if (message == WM_ACTIVATEAPP)
    {
        unsigned int i = device->swapchain_count;

        /* Deactivating the implicit swapchain may cause the application
         * (e.g. Deus Ex: GOTY) to destroy the device, so take care to
         * deactivate the implicit swapchain last, and to avoid accessing the
         * "device" pointer afterwards. */
        while (i--)
            wined3d_swapchain_activate(device->swapchains[i], wparam);
    }
    else if (message == WM_SYSCOMMAND)
    {
        if (wparam == SC_RESTORE && device->wined3d->flags & WINED3D_HANDLE_RESTORE)
        {
            if (unicode)
                DefWindowProcW(window, message, wparam, lparam);
            else
                DefWindowProcA(window, message, wparam, lparam);
        }
    }

    if (unicode)
        return CallWindowProcW(proc, window, message, wparam, lparam);
    else
        return CallWindowProcA(proc, window, message, wparam, lparam);
}
