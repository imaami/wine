/*
 * Copyright 2012 Nikolay Sivov for CodeWeavers
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

#include "dwrite_3.h"
#include "d2d1.h"

#include "wine/debug.h"
#include "wine/heap.h"
#include "wine/list.h"
#include "wine/unicode.h"

#define MS_GSUB_TAG DWRITE_MAKE_OPENTYPE_TAG('G','S','U','B')
#define MS_GPOS_TAG DWRITE_MAKE_OPENTYPE_TAG('G','P','O','S')

static const DWRITE_MATRIX identity =
{
    1.0f, 0.0f,
    0.0f, 1.0f,
    0.0f, 0.0f
};

static inline LPWSTR heap_strdupW(const WCHAR *str)
{
    LPWSTR ret = NULL;

    if(str) {
        DWORD size;

        size = (strlenW(str)+1)*sizeof(WCHAR);
        ret = heap_alloc(size);
        if(ret)
            memcpy(ret, str, size);
    }

    return ret;
}

static inline LPWSTR heap_strdupnW(const WCHAR *str, UINT32 len)
{
    WCHAR *ret = NULL;

    if (len)
    {
        ret = heap_alloc((len+1)*sizeof(WCHAR));
        if(ret)
        {
            memcpy(ret, str, len*sizeof(WCHAR));
            ret[len] = 0;
        }
    }

    return ret;
}

static inline const char *debugstr_range(const DWRITE_TEXT_RANGE *range)
{
    return wine_dbg_sprintf("%u:%u", range->startPosition, range->length);
}

static inline const char *debugstr_matrix(const DWRITE_MATRIX *m)
{
    if (!m) return "(null)";
    return wine_dbg_sprintf("{%.2f,%.2f,%.2f,%.2f,%.2f,%.2f}", m->m11, m->m12, m->m21, m->m22,
        m->dx, m->dy);
}

static inline BOOL dwrite_array_reserve(void **elements, size_t *capacity, size_t count, size_t size)
{
    size_t new_capacity, max_capacity;
    void *new_elements;

    if (count <= *capacity)
        return TRUE;

    max_capacity = ~(SIZE_T)0 / size;
    if (count > max_capacity)
        return FALSE;

    new_capacity = max(4, *capacity);
    while (new_capacity < count && new_capacity <= max_capacity / 2)
        new_capacity *= 2;
    if (new_capacity < count)
        new_capacity = max_capacity;

    if (!(new_elements = heap_realloc(*elements, new_capacity * size)))
        return FALSE;

    *elements = new_elements;
    *capacity = new_capacity;

    return TRUE;
}

static inline const char *debugstr_tag(DWORD tag)
{
    return debugstr_an((char *)&tag, 4);
}

const char *debugstr_sa_script(UINT16) DECLSPEC_HIDDEN;

static inline unsigned short get_table_entry(const unsigned short *table, WCHAR ch)
{
    return table[table[table[ch >> 8] + ((ch >> 4) & 0x0f)] + (ch & 0xf)];
}

static inline BOOL is_simulation_valid(DWRITE_FONT_SIMULATIONS simulations)
{
    return (simulations & ~(DWRITE_FONT_SIMULATIONS_NONE | DWRITE_FONT_SIMULATIONS_BOLD |
        DWRITE_FONT_SIMULATIONS_OBLIQUE)) == 0;
}

struct textlayout_desc
{
    IDWriteFactory7 *factory;
    const WCHAR *string;
    UINT32 length;
    IDWriteTextFormat *format;
    FLOAT max_width;
    FLOAT max_height;
    BOOL is_gdi_compatible;
    /* fields below are only meaningful for gdi-compatible layout */
    FLOAT ppdip;
    const DWRITE_MATRIX *transform;
    BOOL use_gdi_natural;
};

struct glyphrunanalysis_desc
{
    const DWRITE_GLYPH_RUN *run;
    const DWRITE_MATRIX *transform;
    DWRITE_RENDERING_MODE1 rendering_mode;
    DWRITE_MEASURING_MODE measuring_mode;
    DWRITE_GRID_FIT_MODE gridfit_mode;
    DWRITE_TEXT_ANTIALIAS_MODE aa_mode;
    D2D_POINT_2F origin;
};

struct fontface_desc
{
    IDWriteFactory7 *factory;
    DWRITE_FONT_FACE_TYPE face_type;
    IDWriteFontFile *file;
    IDWriteFontFileStream *stream;
    UINT32 index;
    DWRITE_FONT_SIMULATIONS simulations;
    struct dwrite_font_data *font_data; /* could be NULL when face is created directly with IDWriteFactory::CreateFontFace() */
};

struct dwrite_fonttable
{
    const BYTE *data;
    void *context;
    UINT32 size;
    BOOL exists;
};

struct fontfacecached
{
    struct list entry;
    IDWriteFontFace5 *fontface;
};

#define GLYPH_BLOCK_SHIFT 8
#define GLYPH_BLOCK_SIZE  (1UL << GLYPH_BLOCK_SHIFT)
#define GLYPH_BLOCK_MASK  (GLYPH_BLOCK_SIZE - 1)
#define GLYPH_MAX         65536

enum font_flags
{
    FONT_IS_SYMBOL                = 0x00000001,
    FONT_IS_MONOSPACED            = 0x00000002,
    FONT_IS_COLORED               = 0x00000004, /* CPAL/COLR support */
    FONTFACE_KERNING_PAIRS        = 0x00000008,
    FONTFACE_NO_KERNING_PAIRS     = 0x00000010,
    FONTFACE_VERTICAL_VARIANTS    = 0x00000020,
    FONTFACE_NO_VERTICAL_VARIANTS = 0x00000040,
};

struct dwrite_cmap;

typedef UINT16 (*p_cmap_get_glyph_func)(const struct dwrite_cmap *cmap, unsigned int ch);
typedef unsigned int (*p_cmap_get_ranges_func)(const struct dwrite_cmap *cmap, unsigned int max_count,
    DWRITE_UNICODE_RANGE *ranges);

struct dwrite_cmap
{
    const void *data;
    union
    {
        struct
        {
            unsigned int seg_count;
            unsigned int glyph_id_array_len;

            const UINT16 *ends;
            const UINT16 *starts;
            const UINT16 *id_delta;
            const UINT16 *id_range_offset;
            const UINT16 *glyph_id_array;
        } format4;
        struct
        {
            unsigned int first;
            unsigned int last;
        } format6_10;
        struct
        {
            unsigned int group_count;
        } format12_13;
    } u;
    p_cmap_get_glyph_func get_glyph;
    p_cmap_get_ranges_func get_ranges;
    unsigned short symbol : 1;
    IDWriteFontFileStream *stream;
    void *table_context;
};

extern void dwrite_cmap_init(struct dwrite_cmap *cmap, IDWriteFontFile *file, unsigned int face_index,
        DWRITE_FONT_FACE_TYPE face_type) DECLSPEC_HIDDEN;
extern void dwrite_cmap_release(struct dwrite_cmap *cmap) DECLSPEC_HIDDEN;
extern UINT16 opentype_cmap_get_glyph(const struct dwrite_cmap *cmap, unsigned int ch) DECLSPEC_HIDDEN;
extern HRESULT opentype_cmap_get_unicode_ranges(const struct dwrite_cmap *cmap, unsigned int max_count,
        DWRITE_UNICODE_RANGE *ranges, unsigned int *count) DECLSPEC_HIDDEN;

struct dwrite_fontface
{
    IDWriteFontFace5 IDWriteFontFace5_iface;
    IDWriteFontFaceReference IDWriteFontFaceReference_iface;
    LONG refcount;

    IDWriteFontFileStream *stream;
    IDWriteFontFile *file;
    UINT32 index;

    IDWriteFactory7 *factory;
    struct fontfacecached *cached;

    USHORT simulations;
    DWRITE_FONT_FACE_TYPE type;
    DWRITE_FONT_METRICS1 metrics;
    DWRITE_CARET_METRICS caret;
    struct
    {
        unsigned int ascent;
        unsigned int descent;
    } typo_metrics;
    unsigned int flags;

    struct dwrite_cmap cmap;

    struct dwrite_fonttable vdmx;
    struct dwrite_fonttable gasp;
    struct dwrite_fonttable cpal;
    struct dwrite_fonttable colr;
    struct dwrite_fonttable kern;
    DWRITE_GLYPH_METRICS *glyphs[GLYPH_MAX/GLYPH_BLOCK_SIZE];

    DWRITE_FONT_STYLE style;
    DWRITE_FONT_STRETCH stretch;
    DWRITE_FONT_WEIGHT weight;
    DWRITE_PANOSE panose;
    FONTSIGNATURE fontsig;
    UINT32 glyph_image_formats;

    IDWriteLocalizedStrings *info_strings[DWRITE_INFORMATIONAL_STRING_SUPPORTED_SCRIPT_LANGUAGE_TAG + 1];
    IDWriteLocalizedStrings *family_names;
    IDWriteLocalizedStrings *names;

    struct scriptshaping_cache *shaping_cache;

    LOGFONTW lf;
};

extern HRESULT create_numbersubstitution(DWRITE_NUMBER_SUBSTITUTION_METHOD,const WCHAR *locale,BOOL,IDWriteNumberSubstitution**) DECLSPEC_HIDDEN;
extern HRESULT create_textformat(const WCHAR*,IDWriteFontCollection*,DWRITE_FONT_WEIGHT,DWRITE_FONT_STYLE,DWRITE_FONT_STRETCH,
                                 FLOAT,const WCHAR*,IDWriteTextFormat**) DECLSPEC_HIDDEN;
extern HRESULT create_textlayout(const struct textlayout_desc*,IDWriteTextLayout**) DECLSPEC_HIDDEN;
extern HRESULT create_trimmingsign(IDWriteFactory7 *factory, IDWriteTextFormat *format,
        IDWriteInlineObject **sign) DECLSPEC_HIDDEN;
extern HRESULT create_typography(IDWriteTypography**) DECLSPEC_HIDDEN;
extern HRESULT create_localizedstrings(IDWriteLocalizedStrings**) DECLSPEC_HIDDEN;
extern HRESULT add_localizedstring(IDWriteLocalizedStrings*,const WCHAR*,const WCHAR*) DECLSPEC_HIDDEN;
extern HRESULT clone_localizedstrings(IDWriteLocalizedStrings *iface, IDWriteLocalizedStrings **strings) DECLSPEC_HIDDEN;
extern void    set_en_localizedstring(IDWriteLocalizedStrings*,const WCHAR*) DECLSPEC_HIDDEN;
extern void    sort_localizedstrings(IDWriteLocalizedStrings*) DECLSPEC_HIDDEN;
extern unsigned int get_localizedstrings_count(IDWriteLocalizedStrings *strings) DECLSPEC_HIDDEN;
extern BOOL localizedstrings_contains(IDWriteLocalizedStrings *strings, const WCHAR *str) DECLSPEC_HIDDEN;
extern HRESULT get_system_fontcollection(IDWriteFactory7 *factory, IDWriteFontCollection1 **collection) DECLSPEC_HIDDEN;
extern HRESULT get_eudc_fontcollection(IDWriteFactory7 *factory, IDWriteFontCollection3 **collection) DECLSPEC_HIDDEN;
extern IDWriteTextAnalyzer2 *get_text_analyzer(void) DECLSPEC_HIDDEN;
extern HRESULT create_font_file(IDWriteFontFileLoader *loader, const void *reference_key, UINT32 key_size, IDWriteFontFile **font_file) DECLSPEC_HIDDEN;
extern void    init_local_fontfile_loader(void) DECLSPEC_HIDDEN;
extern IDWriteFontFileLoader *get_local_fontfile_loader(void) DECLSPEC_HIDDEN;
extern HRESULT create_fontface(const struct fontface_desc *desc, struct list *cached_list,
        IDWriteFontFace5 **fontface) DECLSPEC_HIDDEN;
extern HRESULT create_font_collection(IDWriteFactory7 *factory, IDWriteFontFileEnumerator *enumerator, BOOL is_system,
       IDWriteFontCollection3 **collection) DECLSPEC_HIDDEN;
extern HRESULT create_glyphrunanalysis(const struct glyphrunanalysis_desc*,IDWriteGlyphRunAnalysis**) DECLSPEC_HIDDEN;
extern BOOL    is_system_collection(IDWriteFontCollection*) DECLSPEC_HIDDEN;
extern HRESULT get_local_refkey(const WCHAR*,const FILETIME*,void**,UINT32*) DECLSPEC_HIDDEN;
extern HRESULT get_filestream_from_file(IDWriteFontFile*,IDWriteFontFileStream**) DECLSPEC_HIDDEN;
extern BOOL    is_face_type_supported(DWRITE_FONT_FACE_TYPE) DECLSPEC_HIDDEN;
extern HRESULT get_family_names_from_stream(IDWriteFontFileStream*,UINT32,DWRITE_FONT_FACE_TYPE,IDWriteLocalizedStrings**) DECLSPEC_HIDDEN;
extern HRESULT create_colorglyphenum(FLOAT,FLOAT,const DWRITE_GLYPH_RUN*,const DWRITE_GLYPH_RUN_DESCRIPTION*,DWRITE_MEASURING_MODE,
    const DWRITE_MATRIX*,UINT32,IDWriteColorGlyphRunEnumerator**) DECLSPEC_HIDDEN;
extern BOOL lb_is_newline_char(WCHAR) DECLSPEC_HIDDEN;
extern HRESULT create_system_fontfallback(IDWriteFactory7 *factory, IDWriteFontFallback1 **fallback) DECLSPEC_HIDDEN;
extern void release_system_fontfallback(IDWriteFontFallback1 *fallback) DECLSPEC_HIDDEN;
extern HRESULT create_fontfallback_builder(IDWriteFactory7 *factory, IDWriteFontFallbackBuilder **builder) DECLSPEC_HIDDEN;
extern HRESULT create_matching_font(IDWriteFontCollection*,const WCHAR*,DWRITE_FONT_WEIGHT,DWRITE_FONT_STYLE,DWRITE_FONT_STRETCH,
    IDWriteFont**) DECLSPEC_HIDDEN;
extern HRESULT create_fontfacereference(IDWriteFactory7 *factory, IDWriteFontFile *file, UINT32 face_index,
        DWRITE_FONT_SIMULATIONS simulations, DWRITE_FONT_AXIS_VALUE const *axis_values, UINT32 axis_values_count,
        IDWriteFontFaceReference1 **reference) DECLSPEC_HIDDEN;
extern HRESULT factory_get_cached_fontface(IDWriteFactory7 *factory, IDWriteFontFile * const *files, UINT32 num_files,
        DWRITE_FONT_SIMULATIONS simulations, struct list **cache, REFIID riid, void **obj) DECLSPEC_HIDDEN;
extern void factory_detach_fontcollection(IDWriteFactory7 *factory, IDWriteFontCollection3 *collection) DECLSPEC_HIDDEN;
extern void factory_detach_gdiinterop(IDWriteFactory7 *factory, IDWriteGdiInterop1 *interop) DECLSPEC_HIDDEN;
extern struct fontfacecached *factory_cache_fontface(IDWriteFactory7 *factory, struct list *fontfaces,
        IDWriteFontFace5 *fontface) DECLSPEC_HIDDEN;
extern void    get_logfont_from_font(IDWriteFont*,LOGFONTW*) DECLSPEC_HIDDEN;
extern void    get_logfont_from_fontface(IDWriteFontFace*,LOGFONTW*) DECLSPEC_HIDDEN;
extern HRESULT get_fontsig_from_font(IDWriteFont*,FONTSIGNATURE*) DECLSPEC_HIDDEN;
extern HRESULT get_fontsig_from_fontface(IDWriteFontFace*,FONTSIGNATURE*) DECLSPEC_HIDDEN;
extern HRESULT create_gdiinterop(IDWriteFactory7 *factory, IDWriteGdiInterop1 **interop) DECLSPEC_HIDDEN;
extern void fontface_detach_from_cache(IDWriteFontFace5 *fontface) DECLSPEC_HIDDEN;
extern void factory_lock(IDWriteFactory7 *factory) DECLSPEC_HIDDEN;
extern void factory_unlock(IDWriteFactory7 *factory) DECLSPEC_HIDDEN;
extern HRESULT create_inmemory_fileloader(IDWriteInMemoryFontFileLoader **loader) DECLSPEC_HIDDEN;
extern HRESULT create_font_resource(IDWriteFactory7 *factory, IDWriteFontFile *file, UINT32 face_index,
        IDWriteFontResource **resource) DECLSPEC_HIDDEN;
extern HRESULT create_fontset_builder(IDWriteFactory7 *factory, IDWriteFontSetBuilder2 **ret) DECLSPEC_HIDDEN;
extern HRESULT compute_glyph_origins(DWRITE_GLYPH_RUN const *run, DWRITE_MEASURING_MODE measuring_mode,
        D2D1_POINT_2F baseline_origin, DWRITE_MATRIX const *transform, D2D1_POINT_2F *origins) DECLSPEC_HIDDEN;

struct dwrite_fontface;

extern float fontface_get_scaled_design_advance(struct dwrite_fontface *fontface, DWRITE_MEASURING_MODE measuring_mode,
        float emsize, float ppdip, const DWRITE_MATRIX *transform, UINT16 glyph, BOOL is_sideways) DECLSPEC_HIDDEN;
extern struct dwrite_fontface *unsafe_impl_from_IDWriteFontFace(IDWriteFontFace *iface) DECLSPEC_HIDDEN;

/* Opentype font table functions */
struct dwrite_font_props
{
    DWRITE_FONT_STYLE style;
    DWRITE_FONT_STRETCH stretch;
    DWRITE_FONT_WEIGHT weight;
    DWRITE_PANOSE panose;
    FONTSIGNATURE fontsig;
    LOGFONTW lf;
    UINT32 flags;
};

struct file_stream_desc {
    IDWriteFontFileStream *stream;
    DWRITE_FONT_FACE_TYPE face_type;
    UINT32 face_index;
};

extern const void* get_fontface_table(IDWriteFontFace5 *fontface, UINT32 tag,
        struct dwrite_fonttable *table) DECLSPEC_HIDDEN;

struct tag_array
{
    unsigned int *tags;
    size_t capacity;
    size_t count;
};

struct ot_gsubgpos_table
{
    struct dwrite_fonttable table;
    unsigned int script_list;
    unsigned int feature_list;
    unsigned int lookup_list;
};

extern HRESULT opentype_analyze_font(IDWriteFontFileStream*,BOOL*,DWRITE_FONT_FILE_TYPE*,DWRITE_FONT_FACE_TYPE*,UINT32*) DECLSPEC_HIDDEN;
extern HRESULT opentype_try_get_font_table(const struct file_stream_desc *stream_desc, UINT32 tag, const void **data,
        void **context, UINT32 *size, BOOL *exists) DECLSPEC_HIDDEN;
extern void opentype_get_font_properties(struct file_stream_desc*,struct dwrite_font_props*) DECLSPEC_HIDDEN;
extern void opentype_get_font_metrics(struct file_stream_desc*,DWRITE_FONT_METRICS1*,DWRITE_CARET_METRICS*) DECLSPEC_HIDDEN;
extern void opentype_get_font_typo_metrics(struct file_stream_desc *stream_desc, unsigned int *ascent,
        unsigned int *descent) DECLSPEC_HIDDEN;
extern HRESULT opentype_get_font_info_strings(const struct file_stream_desc *stream_desc,
        DWRITE_INFORMATIONAL_STRING_ID id, IDWriteLocalizedStrings **strings) DECLSPEC_HIDDEN;
extern HRESULT opentype_get_font_familyname(struct file_stream_desc*,IDWriteLocalizedStrings**) DECLSPEC_HIDDEN;
extern HRESULT opentype_get_font_facename(struct file_stream_desc*,WCHAR*,IDWriteLocalizedStrings**) DECLSPEC_HIDDEN;
extern void opentype_get_typographic_features(struct ot_gsubgpos_table *table, unsigned int script_index,
        unsigned int language_index, struct tag_array *tags) DECLSPEC_HIDDEN;
extern BOOL opentype_get_vdmx_size(const struct dwrite_fonttable *table, INT ppem, UINT16 *ascent,
        UINT16 *descent) DECLSPEC_HIDDEN;
extern unsigned int opentype_get_cpal_palettecount(const struct dwrite_fonttable *table) DECLSPEC_HIDDEN;
extern unsigned int opentype_get_cpal_paletteentrycount(const struct dwrite_fonttable *table) DECLSPEC_HIDDEN;
extern HRESULT opentype_get_cpal_entries(const struct dwrite_fonttable *table, unsigned int palette,
        unsigned int first_entry_index, unsigned int entry_count, DWRITE_COLOR_F *entries) DECLSPEC_HIDDEN;
extern UINT32 opentype_get_glyph_image_formats(IDWriteFontFace5 *fontface) DECLSPEC_HIDDEN;
extern DWRITE_CONTAINER_TYPE opentype_analyze_container_type(void const *, UINT32) DECLSPEC_HIDDEN;
extern HRESULT opentype_get_kerning_pairs(struct dwrite_fontface *fontface, unsigned int count,
        const UINT16 *glyphs, INT32 *values) DECLSPEC_HIDDEN;
extern BOOL opentype_has_kerning_pairs(struct dwrite_fontface *fontface) DECLSPEC_HIDDEN;

struct dwrite_colorglyph {
    USHORT layer; /* [0, num_layers) index indicating current layer */
    /* base glyph record data, set once on initialization */
    USHORT first_layer;
    USHORT num_layers;
    /* current layer record data, updated every time glyph is switched to next layer */
    UINT16 glyph;
    UINT16 palette_index;
};

extern HRESULT opentype_get_colr_glyph(const struct dwrite_fonttable *table, UINT16 glyph,
        struct dwrite_colorglyph *color_glyph) DECLSPEC_HIDDEN;
extern void opentype_colr_next_glyph(const struct dwrite_fonttable *table,
        struct dwrite_colorglyph *color_glyph) DECLSPEC_HIDDEN;

enum gasp_flags {
    GASP_GRIDFIT             = 0x0001,
    GASP_DOGRAY              = 0x0002,
    GASP_SYMMETRIC_GRIDFIT   = 0x0004,
    GASP_SYMMETRIC_SMOOTHING = 0x0008,
};

extern unsigned int opentype_get_gasp_flags(const struct dwrite_fonttable *gasp, float emsize) DECLSPEC_HIDDEN;

/* BiDi helpers */
extern HRESULT bidi_computelevels(const WCHAR*,UINT32,UINT8,UINT8*,UINT8*) DECLSPEC_HIDDEN;

/* FreeType integration */
struct dwrite_glyphbitmap
{
    IDWriteFontFace4 *fontface;
    DWORD simulations;
    float emsize;
    BOOL nohint;
    BOOL aliased;
    UINT16 glyph;
    INT pitch;
    RECT bbox;
    BYTE *buf;
    DWRITE_MATRIX *m;
};

extern BOOL init_freetype(void) DECLSPEC_HIDDEN;
extern void release_freetype(void) DECLSPEC_HIDDEN;

extern HRESULT freetype_get_design_glyph_metrics(struct dwrite_fontface *fontface, UINT16 glyph,
        DWRITE_GLYPH_METRICS *metrics) DECLSPEC_HIDDEN;
extern void freetype_notify_cacheremove(IDWriteFontFace5 *fontface) DECLSPEC_HIDDEN;
extern HRESULT freetype_get_glyph_outline(IDWriteFontFace5 *fontface, float emSize, UINT16 glyph,
        D2D1_POINT_2F origin, IDWriteGeometrySink *sink) DECLSPEC_HIDDEN;
extern UINT16 freetype_get_glyphcount(IDWriteFontFace5 *fontface) DECLSPEC_HIDDEN;
extern void freetype_get_glyph_bbox(struct dwrite_glyphbitmap *bitmap_desc) DECLSPEC_HIDDEN;
extern BOOL freetype_get_glyph_bitmap(struct dwrite_glyphbitmap*) DECLSPEC_HIDDEN;
extern INT32 freetype_get_glyph_advance(IDWriteFontFace5 *fontface, FLOAT emsize, UINT16 index,
        DWRITE_MEASURING_MODE measuring_mode, BOOL *has_contours) DECLSPEC_HIDDEN;
extern void freetype_get_design_glyph_bbox(IDWriteFontFace4*,UINT16,UINT16,RECT*) DECLSPEC_HIDDEN;

/* Glyph shaping */
enum SCRIPT_JUSTIFY
{
    SCRIPT_JUSTIFY_NONE,
    SCRIPT_JUSTIFY_ARABIC_BLANK,
    SCRIPT_JUSTIFY_CHARACTER,
    SCRIPT_JUSTIFY_RESERVED1,
    SCRIPT_JUSTIFY_BLANK,
    SCRIPT_JUSTIFY_RESERVED2,
    SCRIPT_JUSTIFY_RESERVED3,
    SCRIPT_JUSTIFY_ARABIC_NORMAL,
    SCRIPT_JUSTIFY_ARABIC_KASHIDA,
    SCRIPT_JUSTIFY_ARABIC_ALEF,
    SCRIPT_JUSTIFY_ARABIC_HA,
    SCRIPT_JUSTIFY_ARABIC_RA,
    SCRIPT_JUSTIFY_ARABIC_BA,
    SCRIPT_JUSTIFY_ARABIC_BARA,
    SCRIPT_JUSTIFY_ARABIC_SEEN,
    SCRIPT_JUSTIFY_ARABIC_SEEN_M
};

struct scriptshaping_cache
{
    const struct shaping_font_ops *font;
    void *context;
    UINT16 upem;

    struct ot_gsubgpos_table gsub;
    struct ot_gsubgpos_table gpos;

    struct
    {
        struct dwrite_fonttable table;
        unsigned int classdef;
        unsigned int markattachclassdef;
        unsigned int markglyphsetdef;
    } gdef;
};

struct shaping_glyph_info
{
    /* Combined features mask. */
    unsigned int mask;
    /* Derived from glyph class, supplied by GDEF. */
    unsigned int props;
    /* Used for GPOS mark and cursive attachments. */
    int attach_chain;
    /* Only relevant for isClusterStart glyphs. Indicates text position for this cluster. */
    unsigned int start_text_idx;
    unsigned int codepoint;
};

struct shaping_glyph_properties
{
    UINT16 justification : 4;
    UINT16 isClusterStart : 1;
    UINT16 isDiacritic : 1;
    UINT16 isZeroWidthSpace : 1;
    UINT16 reserved : 1;
    UINT16 components : 4;
    UINT16 lig_component : 4;
};

struct scriptshaping_context;

typedef void (*p_apply_context_lookup)(struct scriptshaping_context *context, unsigned int lookup_index);

enum shaping_feature_flags
{
    FEATURE_GLOBAL = 0x1,
    FEATURE_GLOBAL_SEARCH = 0x2,
    FEATURE_MANUAL_ZWNJ = 0x4,
    FEATURE_MANUAL_ZWJ = 0x8,
    FEATURE_MANUAL_JOINERS = FEATURE_MANUAL_ZWNJ | FEATURE_MANUAL_ZWJ,
    FEATURE_HAS_FALLBACK = 0x10,
    FEATURE_NEEDS_FALLBACK = 0x20,
};

struct shaping_feature
{
    unsigned int tag;
    unsigned int index;
    unsigned int flags;
    unsigned int max_value;
    unsigned int default_value;
    unsigned int mask;
    unsigned int shift;
    unsigned int stage;
};

#define MAX_SHAPING_STAGE 16

struct shaping_features;

typedef void (*stage_func)(struct scriptshaping_context *context,
        const struct shaping_features *features);

struct shaping_stage
{
    stage_func func;
    unsigned int last_lookup;
};

struct shaping_features
{
    struct shaping_feature *features;
    size_t count;
    size_t capacity;
    unsigned int stage;
    struct shaping_stage stages[MAX_SHAPING_STAGE];
};

struct shaper
{
    void (*collect_features)(struct scriptshaping_context *context, struct shaping_features *features);
    void (*setup_masks)(struct scriptshaping_context *context, const struct shaping_features *features);
};

extern const struct shaper arabic_shaper DECLSPEC_HIDDEN;

extern void shape_enable_feature(struct shaping_features *features, unsigned int tag,
        unsigned int flags) DECLSPEC_HIDDEN;
extern void shape_add_feature_full(struct shaping_features *features, unsigned int tag,
        unsigned int flags, unsigned int value) DECLSPEC_HIDDEN;
extern unsigned int shape_get_feature_1_mask(const struct shaping_features *features,
        unsigned int tag) DECLSPEC_HIDDEN;
extern void shape_start_next_stage(struct shaping_features *features, stage_func func) DECLSPEC_HIDDEN;

struct scriptshaping_context
{
    struct scriptshaping_cache *cache;
    const struct shaper *shaper;
    unsigned int script;
    UINT32 language_tag;

    const WCHAR *text;
    unsigned int length;
    BOOL is_rtl;
    BOOL is_sideways;

    union
    {
        struct
        {
            const UINT16 *glyphs;
            const DWRITE_SHAPING_GLYPH_PROPERTIES *glyph_props;
            DWRITE_SHAPING_TEXT_PROPERTIES *text_props;
            const UINT16 *clustermap;
            p_apply_context_lookup apply_context_lookup;
        } pos;
        struct
        {
            UINT16 *glyphs;
            DWRITE_SHAPING_GLYPH_PROPERTIES *glyph_props;
            DWRITE_SHAPING_TEXT_PROPERTIES *text_props;
            UINT16 *clustermap;
            p_apply_context_lookup apply_context_lookup;
            unsigned int max_glyph_count;
            unsigned int capacity;
            const WCHAR *digits;
        } subst;
        struct
        {
            UINT16 *glyphs;
            struct shaping_glyph_properties *glyph_props;
            DWRITE_SHAPING_TEXT_PROPERTIES *text_props;
            UINT16 *clustermap;
            p_apply_context_lookup apply_context_lookup;
        } buffer;
    } u;

    const struct ot_gsubgpos_table *table; /* Either GSUB or GPOS. */
    struct
    {
        const DWRITE_TYPOGRAPHIC_FEATURES **features;
        const unsigned int *range_lengths;
        unsigned int range_count;
    } user_features;
    unsigned int global_mask;
    unsigned int lookup_mask; /* Currently processed feature mask, set in main loop. */
    unsigned int auto_zwj;
    unsigned int auto_zwnj;
    struct shaping_glyph_info *glyph_infos;
    unsigned int has_gpos_attachment : 1;

    unsigned int cur;
    unsigned int glyph_count;
    unsigned int nesting_level_left;

    float emsize;
    DWRITE_MEASURING_MODE measuring_mode;
    float *advances;
    DWRITE_GLYPH_OFFSET *offsets;
};

struct shaping_font_ops
{
    void (*grab_font_table)(void *context, UINT32 table, const BYTE **data, UINT32 *size, void **data_context);
    void (*release_font_table)(void *context, void *data_context);
    UINT16 (*get_font_upem)(void *context);
    BOOL (*has_glyph)(void *context, unsigned int codepoint);
    UINT16 (*get_glyph)(void *context, unsigned int codepoint);
};

extern struct scriptshaping_cache *create_scriptshaping_cache(void *context,
        const struct shaping_font_ops *font_ops) DECLSPEC_HIDDEN;
extern void release_scriptshaping_cache(struct scriptshaping_cache*) DECLSPEC_HIDDEN;
extern struct scriptshaping_cache *fontface_get_shaping_cache(struct dwrite_fontface *fontface) DECLSPEC_HIDDEN;

extern void opentype_layout_scriptshaping_cache_init(struct scriptshaping_cache *cache) DECLSPEC_HIDDEN;
extern DWORD opentype_layout_find_script(const struct scriptshaping_cache *cache, DWORD kind, DWORD tag,
        unsigned int *script_index) DECLSPEC_HIDDEN;
extern DWORD opentype_layout_find_language(const struct scriptshaping_cache *cache, DWORD kind, DWORD tag,
        unsigned int script_index, unsigned int *language_index) DECLSPEC_HIDDEN;
extern void opentype_layout_apply_gsub_features(struct scriptshaping_context *context, unsigned int script_index,
        unsigned int language_index, struct shaping_features *features) DECLSPEC_HIDDEN;
extern void opentype_layout_apply_gpos_features(struct scriptshaping_context *context, unsigned int script_index,
        unsigned int language_index, struct shaping_features *features) DECLSPEC_HIDDEN;
extern BOOL opentype_layout_check_feature(struct scriptshaping_context *context, unsigned int script_index,
        unsigned int language_index, struct shaping_feature *feature, unsigned int glyph_count,
        const UINT16 *glyphs, UINT8 *feature_applies) DECLSPEC_HIDDEN;
extern void opentype_layout_unsafe_to_break(struct scriptshaping_context *context, unsigned int start,
        unsigned int end) DECLSPEC_HIDDEN;
extern BOOL opentype_has_vertical_variants(struct dwrite_fontface *fontface) DECLSPEC_HIDDEN;
extern HRESULT opentype_get_vertical_glyph_variants(struct dwrite_fontface *fontface, unsigned int glyph_count,
        const UINT16 *nominal_glyphs, UINT16 *glyphs) DECLSPEC_HIDDEN;

extern HRESULT shape_get_glyphs(struct scriptshaping_context *context, const unsigned int *scripts) DECLSPEC_HIDDEN;
extern HRESULT shape_get_positions(struct scriptshaping_context *context, const unsigned int *scripts) DECLSPEC_HIDDEN;
extern HRESULT shape_get_typographic_features(struct scriptshaping_context *context, const unsigned int *scripts,
        unsigned int max_tagcount, unsigned int *actual_tagcount, unsigned int *tags) DECLSPEC_HIDDEN;
extern HRESULT shape_check_typographic_feature(struct scriptshaping_context *context, const unsigned int *scripts,
        unsigned int tag, unsigned int glyph_count, const UINT16 *glyphs, UINT8 *feature_applies) DECLSPEC_HIDDEN;
