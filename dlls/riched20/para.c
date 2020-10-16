/*
 * RichEdit - functions working on paragraphs of text (diParagraph).
 * 
 * Copyright 2004 by Krzysztof Foltman
 * Copyright 2006 by Phil Krylov
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

#include "editor.h"

WINE_DEFAULT_DEBUG_CHANNEL(richedit);

void para_mark_rewrap( ME_TextEditor *editor, ME_Paragraph *para )
{
    para->nFlags |= MEPF_REWRAP;
    para_mark_add( editor, para );
}

static ME_Paragraph *para_create( ME_TextEditor *editor )
{
    ME_DisplayItem *item = ME_MakeDI(diParagraph);

    ME_SetDefaultParaFormat(editor, &item->member.para.fmt);
    item->member.para.nFlags = MEPF_REWRAP;

    return &item->member.para;
}

void destroy_para(ME_TextEditor *editor, ME_DisplayItem *item)
{
    assert(item->type == diParagraph);

    if (item->member.para.nWidth == editor->nTotalWidth)
    {
        item->member.para.nWidth = 0;
        editor->nTotalWidth = get_total_width(editor);
    }
    editor->total_rows -= item->member.para.nRows;
    ME_DestroyString(item->member.para.text);
    para_num_clear( &item->member.para.para_num );
    para_mark_remove( editor, &item->member.para );
    ME_DestroyDisplayItem(item);
}

/* Note para_next/prev will return the start and end doc nodes */
ME_Paragraph *para_next( ME_Paragraph *para )
{
    if (para->next_para) return &para->next_para->member.para;
    return NULL;
}

ME_Paragraph *para_prev( ME_Paragraph *para )
{
    if (para->prev_para && para->prev_para->type == diParagraph) return &para->prev_para->member.para;
    return NULL;
}

int get_total_width(ME_TextEditor *editor)
{
    ME_Paragraph *para;
    int total_width = 0;

    if (editor->pBuffer->pFirst && editor->pBuffer->pLast)
    {
        para = &editor->pBuffer->pFirst->next->member.para;
        while (para != &editor->pBuffer->pLast->member.para && para->next_para)
        {
            total_width = max(total_width, para->nWidth);
            para = &para->next_para->member.para;
        }
    }

    return total_width;
}

static int para_mark_compare( const void *key, const struct wine_rb_entry *entry )
{
    ME_Paragraph *para = WINE_RB_ENTRY_VALUE( entry, ME_Paragraph, marked_entry );

    return *(int *)key - para->nCharOfs;
}

void para_mark_remove( ME_TextEditor *editor, ME_Paragraph *para )
{
    wine_rb_remove_key( &editor->marked_paras, &para->nCharOfs );
}

void para_mark_add( ME_TextEditor *editor, ME_Paragraph *para )
{
    wine_rb_put( &editor->marked_paras, &para->nCharOfs, &para->marked_entry );
}

ME_Run *para_first_run( ME_Paragraph *para )
{
    ME_DisplayItem *di;

    for (di = para_get_di( para ); di != para->next_para; di = di->next )
    {
        if (di->type != diRun) continue;
        return &di->member.run;
    }
    ERR( "failed to find run in paragraph\n" );
    return NULL;
}

ME_Run *para_end_run( ME_Paragraph *para )
{
    return para->eop_run;
}

void ME_MakeFirstParagraph(ME_TextEditor *editor)
{
  static const WCHAR cr_lf[] = {'\r','\n',0};
  ME_Context c;
  CHARFORMAT2W cf;
  const CHARFORMATW *host_cf;
  LOGFONTW lf;
  HFONT hf;
  ME_TextBuffer *text = editor->pBuffer;
  ME_Paragraph *para = para_create( editor );
  ME_Run *run;
  ME_Style *style;
  int eol_len;

  ME_InitContext(&c, editor, ITextHost_TxGetDC(editor->texthost));

  hf = GetStockObject(SYSTEM_FONT);
  assert(hf);
  GetObjectW(hf, sizeof(LOGFONTW), &lf);
  ZeroMemory(&cf, sizeof(cf));
  cf.cbSize = sizeof(cf);
  cf.dwMask = CFM_ANIMATION|CFM_BACKCOLOR|CFM_CHARSET|CFM_COLOR|CFM_FACE|CFM_KERNING|CFM_LCID|CFM_OFFSET;
  cf.dwMask |= CFM_REVAUTHOR|CFM_SIZE|CFM_SPACING|CFM_STYLE|CFM_UNDERLINETYPE|CFM_WEIGHT;
  cf.dwMask |= CFM_ALLCAPS|CFM_BOLD|CFM_DISABLED|CFM_EMBOSS|CFM_HIDDEN;
  cf.dwMask |= CFM_IMPRINT|CFM_ITALIC|CFM_LINK|CFM_OUTLINE|CFM_PROTECTED;
  cf.dwMask |= CFM_REVISED|CFM_SHADOW|CFM_SMALLCAPS|CFM_STRIKEOUT;
  cf.dwMask |= CFM_SUBSCRIPT|CFM_UNDERLINE;
  
  cf.dwEffects = CFE_AUTOCOLOR | CFE_AUTOBACKCOLOR;
  lstrcpyW(cf.szFaceName, lf.lfFaceName);
  /* Convert system font height from logical units to twips for cf.yHeight */
  cf.yHeight = (lf.lfHeight * 72 * 1440) / (c.dpi.cy * c.dpi.cy);
  if (lf.lfWeight > FW_NORMAL) cf.dwEffects |= CFE_BOLD;
  cf.wWeight = lf.lfWeight;
  if (lf.lfItalic) cf.dwEffects |= CFE_ITALIC;
  if (lf.lfUnderline) cf.dwEffects |= CFE_UNDERLINE;
  cf.bUnderlineType = CFU_UNDERLINE;
  if (lf.lfStrikeOut) cf.dwEffects |= CFE_STRIKEOUT;
  cf.bPitchAndFamily = lf.lfPitchAndFamily;
  cf.bCharSet = lf.lfCharSet;
  cf.lcid = GetSystemDefaultLCID();

  style = ME_MakeStyle(&cf);
  text->pDefaultStyle = style;

  if (ITextHost_TxGetCharFormat(editor->texthost, &host_cf) == S_OK)
  {
    ZeroMemory(&cf, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cfany_to_cf2w(&cf, (CHARFORMAT2W *)host_cf);
    ME_SetDefaultCharFormat(editor, &cf);
  }

  eol_len = editor->bEmulateVersion10 ? 2 : 1;
  para->text = ME_MakeStringN( cr_lf, eol_len );

  run = run_create( style, MERF_ENDPARA );
  run->nCharOfs = 0;
  run->len = eol_len;
  run->para = para;
  para->eop_run = run;

  ME_InsertBefore( text->pLast, para_get_di( para) );
  ME_InsertBefore( text->pLast, run_get_di( run ) );
  para->prev_para = text->pFirst;
  para->next_para = text->pLast;
  text->pFirst->member.para.next_para = para_get_di( para );
  text->pLast->member.para.prev_para = para_get_di( para );

  text->pLast->member.para.nCharOfs = editor->bEmulateVersion10 ? 2 : 1;

  wine_rb_init( &editor->marked_paras, para_mark_compare );
  para_mark_add( editor, para );
  ME_DestroyContext(&c);
}

static void ME_MarkForWrapping(ME_TextEditor *editor, ME_DisplayItem *first, const ME_DisplayItem *last)
{
  while(first != last)
  {
    para_mark_rewrap( editor, &first->member.para );
    first = first->member.para.next_para;
  }
}

void ME_MarkAllForWrapping(ME_TextEditor *editor)
{
  ME_MarkForWrapping(editor, editor->pBuffer->pFirst->member.para.next_para, editor->pBuffer->pLast);
}

static void table_update_flags( ME_Paragraph *para )
{
    para->fmt.dwMask |= PFM_TABLE | PFM_TABLEROWDELIMITER;

    if (para->pCell) para->nFlags |= MEPF_CELL;
    else para->nFlags &= ~MEPF_CELL;

    if (para->nFlags & MEPF_ROWEND) para->fmt.wEffects |= PFE_TABLEROWDELIMITER;
    else para->fmt.wEffects &= ~PFE_TABLEROWDELIMITER;

    if (para->nFlags & (MEPF_ROWSTART | MEPF_CELL | MEPF_ROWEND))
        para->fmt.wEffects |= PFE_TABLE;
    else
        para->fmt.wEffects &= ~PFE_TABLE;
}

static inline BOOL para_num_same_list( const PARAFORMAT2 *item, const PARAFORMAT2 *base )
{
    return item->wNumbering == base->wNumbering &&
        item->wNumberingStart == base->wNumberingStart &&
        item->wNumberingStyle == base->wNumberingStyle &&
        !(item->wNumberingStyle & PFNS_NEWNUMBER);
}

static int para_num_get_num( ME_Paragraph *para )
{
    ME_DisplayItem *prev;
    int num = para->fmt.wNumberingStart;

    for (prev = para->prev_para; prev->type == diParagraph;
         para = &prev->member.para, prev = prev->member.para.prev_para, num++)
    {
        if (!para_num_same_list( &prev->member.para.fmt, &para->fmt )) break;
    }
    return num;
}

static ME_String *para_num_get_str( ME_Paragraph *para, WORD num )
{
    /* max 4 Roman letters (representing '8') / decade + '(' + ')' */
    ME_String *str = ME_MakeStringEmpty( 20 + 2 );
    WCHAR *p;
    static const WCHAR fmtW[] = {'%', 'd', 0};
    static const WORD letter_base[] = { 1, 26, 26 * 26, 26 * 26 * 26 };
    /* roman_base should start on a '5' not a '1', otherwise the 'total' code will need adjusting.
       'N' and 'O' are what MS uses for 5000 and 10000, their version doesn't work well above 30000,
       but we'll use 'P' as the obvious extension, this gets us up to 2^16, which is all we care about. */
    static const struct
    {
        int base;
        char letter;
    }
    roman_base[] =
    {
        {50000, 'P'}, {10000, 'O'}, {5000, 'N'}, {1000, 'M'},
        {500, 'D'}, {100, 'C'}, {50, 'L'}, {10, 'X'}, {5, 'V'}, {1, 'I'}
    };
    int i, len;
    WORD letter, total, char_offset = 0;

    if (!str) return NULL;

    p = str->szData;

    if ((para->fmt.wNumberingStyle & 0xf00) == PFNS_PARENS)
        *p++ = '(';

    switch (para->fmt.wNumbering)
    {
    case PFN_ARABIC:
    default:
        p += swprintf( p, 20, fmtW, num );
        break;

    case PFN_LCLETTER:
        char_offset = 'a' - 'A';
        /* fall through */
    case PFN_UCLETTER:
        if (!num) num = 1;

        /* This is not base-26 (or 27) as zeros don't count unless they are leading zeros.
           It's simplest to start with the least significant letter, so first calculate how many letters are needed. */
        for (i = 0, total = 0; i < ARRAY_SIZE( letter_base ); i++)
        {
            total += letter_base[i];
            if (num < total) break;
        }
        len = i;
        for (i = 0; i < len; i++)
        {
            num -= letter_base[i];
            letter = (num / letter_base[i]) % 26;
            p[len - i - 1] = letter + 'A' + char_offset;
        }
        p += len;
        *p = 0;
        break;

    case PFN_LCROMAN:
        char_offset = 'a' - 'A';
        /* fall through */
    case PFN_UCROMAN:
        if (!num) num = 1;

        for (i = 0; i < ARRAY_SIZE( roman_base ); i++)
        {
            if (i > 0)
            {
                if (i % 2 == 0) /* eg 5000, check for 9000 */
                    total = roman_base[i].base + 4 * roman_base[i + 1].base;
                else  /* eg 1000, check for 4000 */
                    total = 4 * roman_base[i].base;

                if (num / total)
                {
                    *p++ = roman_base[(i & ~1) + 1].letter + char_offset;
                    *p++ = roman_base[i - 1].letter + char_offset;
                    num -= total;
                    continue;
                }
            }

            len = num / roman_base[i].base;
            while (len--)
            {
                *p++ = roman_base[i].letter + char_offset;
                num -= roman_base[i].base;
            }
        }
        *p = 0;
        break;
    }

    switch (para->fmt.wNumberingStyle & 0xf00)
    {
    case PFNS_PARENS:
    case PFNS_PAREN:
        *p++ = ')';
        *p = 0;
        break;

    case PFNS_PERIOD:
        *p++ = '.';
        *p = 0;
        break;
    }

    str->nLen = p - str->szData;
    return str;
}

void para_num_init( ME_Context *c, ME_Paragraph *para )
{
    ME_Style *style;
    CHARFORMAT2W cf;
    static const WCHAR bullet_font[] = {'S','y','m','b','o','l',0};
    static const WCHAR bullet_str[] = {0xb7, 0};
    static const WCHAR spaceW[] = {' ', 0};
    SIZE sz;

    if (!para->fmt.wNumbering) return;
    if (para->para_num.style && para->para_num.text) return;

    if (!para->para_num.style)
    {
        style = para->eop_run->style;

        if (para->fmt.wNumbering == PFN_BULLET)
        {
            cf.cbSize = sizeof(cf);
            cf.dwMask = CFM_FACE | CFM_CHARSET;
            memcpy( cf.szFaceName, bullet_font, sizeof(bullet_font) );
            cf.bCharSet = SYMBOL_CHARSET;
            style = ME_ApplyStyle( c->editor, style, &cf );
        }
        else
        {
            ME_AddRefStyle( style );
        }

        para->para_num.style = style;
    }

    if (!para->para_num.text)
    {
        if (para->fmt.wNumbering != PFN_BULLET)
            para->para_num.text = para_num_get_str( para, para_num_get_num( para ) );
        else
            para->para_num.text = ME_MakeStringConst( bullet_str, 1 );
    }

    select_style( c, para->para_num.style );
    GetTextExtentPointW( c->hDC, para->para_num.text->szData, para->para_num.text->nLen, &sz );
    para->para_num.width = sz.cx;
    GetTextExtentPointW( c->hDC, spaceW, 1, &sz );
    para->para_num.width += sz.cx;
}

void para_num_clear( struct para_num *pn )
{
    if (pn->style)
    {
        ME_ReleaseStyle( pn->style );
        pn->style = NULL;
    }
    ME_DestroyString( pn->text );
    pn->text = NULL;
}

static void para_num_clear_list( ME_TextEditor *editor, ME_Paragraph *para, const PARAFORMAT2 *orig_fmt )
{
    do
    {
        para_mark_rewrap( editor, para );
        para_num_clear( &para->para_num );
        if (para->next_para->type != diParagraph) break;
        para = &para->next_para->member.para;
    } while (para_num_same_list( &para->fmt, orig_fmt ));
}

static BOOL ME_SetParaFormat(ME_TextEditor *editor, ME_Paragraph *para, const PARAFORMAT2 *pFmt)
{
  PARAFORMAT2 copy;
  DWORD dwMask;

  assert(para->fmt.cbSize == sizeof(PARAFORMAT2));
  dwMask = pFmt->dwMask;
  if (pFmt->cbSize < sizeof(PARAFORMAT))
    return FALSE;
  else if (pFmt->cbSize < sizeof(PARAFORMAT2))
    dwMask &= PFM_ALL;
  else
    dwMask &= PFM_ALL2;

  add_undo_set_para_fmt( editor, para );

  copy = para->fmt;

#define COPY_FIELD(m, f) \
  if (dwMask & (m)) {                           \
    para->fmt.dwMask |= m;                      \
    para->fmt.f = pFmt->f;                      \
  }

  COPY_FIELD(PFM_NUMBERING, wNumbering);
  COPY_FIELD(PFM_STARTINDENT, dxStartIndent);
  if (dwMask & PFM_OFFSETINDENT)
    para->fmt.dxStartIndent += pFmt->dxStartIndent;
  COPY_FIELD(PFM_RIGHTINDENT, dxRightIndent);
  COPY_FIELD(PFM_OFFSET, dxOffset);
  COPY_FIELD(PFM_ALIGNMENT, wAlignment);
  if (dwMask & PFM_TABSTOPS)
  {
    para->fmt.cTabCount = pFmt->cTabCount;
    memcpy(para->fmt.rgxTabs, pFmt->rgxTabs, pFmt->cTabCount*sizeof(LONG));
  }

#define EFFECTS_MASK (PFM_RTLPARA|PFM_KEEP|PFM_KEEPNEXT|PFM_PAGEBREAKBEFORE| \
                      PFM_NOLINENUMBER|PFM_NOWIDOWCONTROL|PFM_DONOTHYPHEN|PFM_SIDEBYSIDE| \
                      PFM_TABLE)
  /* we take for granted that PFE_xxx is the hiword of the corresponding PFM_xxx */
  if (dwMask & EFFECTS_MASK)
  {
    para->fmt.dwMask |= dwMask & EFFECTS_MASK;
    para->fmt.wEffects &= ~HIWORD(dwMask);
    para->fmt.wEffects |= pFmt->wEffects & HIWORD(dwMask);
  }
#undef EFFECTS_MASK

  COPY_FIELD(PFM_SPACEBEFORE, dySpaceBefore);
  COPY_FIELD(PFM_SPACEAFTER, dySpaceAfter);
  COPY_FIELD(PFM_LINESPACING, dyLineSpacing);
  COPY_FIELD(PFM_STYLE, sStyle);
  COPY_FIELD(PFM_LINESPACING, bLineSpacingRule);
  COPY_FIELD(PFM_SHADING, wShadingWeight);
  COPY_FIELD(PFM_SHADING, wShadingStyle);
  COPY_FIELD(PFM_NUMBERINGSTART, wNumberingStart);
  COPY_FIELD(PFM_NUMBERINGSTYLE, wNumberingStyle);
  COPY_FIELD(PFM_NUMBERINGTAB, wNumberingTab);
  COPY_FIELD(PFM_BORDER, wBorderSpace);
  COPY_FIELD(PFM_BORDER, wBorderWidth);
  COPY_FIELD(PFM_BORDER, wBorders);

  para->fmt.dwMask |= dwMask;
#undef COPY_FIELD

  if (memcmp(&copy, &para->fmt, sizeof(PARAFORMAT2)))
  {
    para_mark_rewrap( editor, para );
    if (((dwMask & PFM_NUMBERING)      && (copy.wNumbering != para->fmt.wNumbering)) ||
        ((dwMask & PFM_NUMBERINGSTART) && (copy.wNumberingStart != para->fmt.wNumberingStart)) ||
        ((dwMask & PFM_NUMBERINGSTYLE) && (copy.wNumberingStyle != para->fmt.wNumberingStyle)))
    {
        para_num_clear_list( editor, para, &copy );
    }
  }

  return TRUE;
}

/* split paragraph at the beginning of the run */
ME_Paragraph *para_split( ME_TextEditor *editor, ME_Run *run, ME_Style *style,
                          const WCHAR *eol_str, int eol_len, int paraFlags )
{
  ME_Paragraph *new_para = para_create( editor ), *old_para, *next_para;
  ME_Run *end_run, *next_run;
  int ofs, i;
  int run_flags = MERF_ENDPARA;

  if (!editor->bEmulateVersion10) /* v4.1 */
  {
    /* At most 1 of MEPF_CELL, MEPF_ROWSTART, or MEPF_ROWEND should be set. */
    assert( !(paraFlags & ~(MEPF_CELL | MEPF_ROWSTART | MEPF_ROWEND)) );
    assert( !(paraFlags & (paraFlags-1)) );
    if (paraFlags == MEPF_CELL)
        run_flags |= MERF_ENDCELL;
    else if (paraFlags == MEPF_ROWSTART)
      run_flags |= MERF_TABLESTART | MERF_HIDDEN;
  }
  else /* v1.0 - v3.0 */
    assert( !(paraFlags & (MEPF_CELL |MEPF_ROWSTART | MEPF_ROWEND)) );

  old_para = run->para;
  assert( old_para->fmt.cbSize == sizeof(PARAFORMAT2) );

  /* Clear any cached para numbering following this paragraph */
  if (old_para->fmt.wNumbering)
      para_num_clear_list( editor, old_para, &old_para->fmt );

  new_para->text = ME_VSplitString( old_para->text, run->nCharOfs );

  end_run = run_create( style, run_flags );
  ofs = end_run->nCharOfs = run->nCharOfs;
  end_run->len = eol_len;
  end_run->para = run->para;
  ME_AppendString( old_para->text, eol_str, eol_len );
  next_para = &old_para->next_para->member.para;

  add_undo_join_paras( editor, old_para->nCharOfs + ofs );

  /* Update selection cursors to point to the correct paragraph. */
  for (i = 0; i < editor->nCursors; i++)
  {
    if (editor->pCursors[i].pPara == para_get_di( old_para ) &&
        run->nCharOfs <= editor->pCursors[i].pRun->member.run.nCharOfs)
    {
      editor->pCursors[i].pPara = para_get_di( new_para );
    }
  }

  /* the new paragraph will have a different starting offset, so update its runs */
  for (next_run = run; next_run; next_run = run_next( next_run ))
  {
    next_run->nCharOfs -= ofs;
    next_run->para = new_para;
  }

  new_para->nCharOfs = old_para->nCharOfs + ofs;
  new_para->nCharOfs += eol_len;
  new_para->nFlags = 0;
  para_mark_rewrap( editor, new_para );

  /* FIXME initialize format style and call ME_SetParaFormat blah blah */
  new_para->fmt = old_para->fmt;
  new_para->border = old_para->border;

  /* insert paragraph into paragraph double linked list */
  new_para->prev_para = para_get_di( old_para );
  new_para->next_para = para_get_di( next_para );
  old_para->next_para = para_get_di( new_para );
  next_para->prev_para = para_get_di( new_para );

  /* insert end run of the old paragraph, and new paragraph, into DI double linked list */
  ME_InsertBefore( run_get_di( run ), para_get_di( new_para ) );
  ME_InsertBefore( para_get_di( new_para ), run_get_di( end_run ) );

  /* Fix up the paras' eop_run ptrs */
  new_para->eop_run = old_para->eop_run;
  old_para->eop_run = end_run;

  if (!editor->bEmulateVersion10) /* v4.1 */
  {
    if (paraFlags & (MEPF_ROWSTART | MEPF_CELL))
    {
      ME_DisplayItem *cell = ME_MakeDI(diCell);
      ME_InsertBefore( para_get_di( new_para ), cell );
      new_para->pCell = cell;
      cell->member.cell.next_cell = NULL;
      if (paraFlags & MEPF_ROWSTART)
      {
        old_para->nFlags |= MEPF_ROWSTART;
        cell->member.cell.prev_cell = NULL;
        cell->member.cell.parent_cell = old_para->pCell;
        if (old_para->pCell)
          cell->member.cell.nNestingLevel = old_para->pCell->member.cell.nNestingLevel + 1;
        else
          cell->member.cell.nNestingLevel = 1;
      }
      else
      {
        cell->member.cell.prev_cell = old_para->pCell;
        assert(cell->member.cell.prev_cell);
        cell->member.cell.prev_cell->member.cell.next_cell = cell;
        assert( old_para->nFlags & MEPF_CELL );
        assert( !(old_para->nFlags & MEPF_ROWSTART) );
        cell->member.cell.nNestingLevel = cell->member.cell.prev_cell->member.cell.nNestingLevel;
        cell->member.cell.parent_cell = cell->member.cell.prev_cell->member.cell.parent_cell;
      }
    }
    else if (paraFlags & MEPF_ROWEND)
    {
      old_para->nFlags |= MEPF_ROWEND;
      old_para->pCell = old_para->pCell->member.cell.parent_cell;
      new_para->pCell = old_para->pCell;
      assert( old_para->prev_para->member.para.nFlags & MEPF_CELL );
      assert( !(old_para->prev_para->member.para.nFlags & MEPF_ROWSTART) );
      if (new_para->pCell != new_para->next_para->member.para.pCell
          && new_para->next_para->member.para.pCell
          && !new_para->next_para->member.para.pCell->member.cell.prev_cell)
      {
        /* Row starts just after the row that was ended. */
        new_para->nFlags |= MEPF_ROWSTART;
      }
    }
    else new_para->pCell = old_para->pCell;

    table_update_flags( old_para );
    table_update_flags( new_para );
  }

  /* force rewrap of the */
  if (old_para->prev_para->type == diParagraph)
    para_mark_rewrap( editor, &old_para->prev_para->member.para );

  para_mark_rewrap( editor, &new_para->prev_para->member.para );

  /* we've added the end run, so we need to modify nCharOfs in the next paragraphs */
  ME_PropagateCharOffset( para_get_di( next_para ), eol_len );
  editor->nParagraphs++;

  return new_para;
}

/* join para with the next para keeping para's style using the paragraph fmt
   specified in use_first_fmt */
ME_Paragraph *para_join( ME_TextEditor *editor, ME_Paragraph *para, BOOL use_first_fmt )
{
  ME_DisplayItem *tmp, *pCell = NULL;
  ME_Paragraph *next = para_next( para );
  ME_Run *end_run, *next_first_run, *tmp_run;
  int i, shift;
  int end_len;
  CHARFORMAT2W fmt;
  ME_Cursor startCur, endCur;
  ME_String *eol_str;

  assert( next && para_next( next ) );

  /* Clear any cached para numbering following this paragraph */
  if (para->fmt.wNumbering) para_num_clear_list( editor, para, &para->fmt );

  end_run = para_end_run( para );
  next_first_run = para_first_run( next );

  end_len = end_run->len;
  eol_str = ME_VSplitString( para->text, end_run->nCharOfs );
  ME_AppendString( para->text, next->text->szData, next->text->nLen );

  /* null char format operation to store the original char format for the ENDPARA run */
  ME_InitCharFormat2W(&fmt);
  startCur.pPara = para_get_di( para );
  startCur.pRun = run_get_di( end_run );
  endCur.pPara = para_get_di( next );
  endCur.pRun = run_get_di( next_first_run );
  startCur.nOffset = endCur.nOffset = 0;

  ME_SetCharFormat(editor, &startCur, &endCur, &fmt);

  if (!editor->bEmulateVersion10) /* v4.1 */
  {
    /* Table cell/row properties are always moved over from the removed para. */
    para->nFlags = next->nFlags;
    para->pCell = next->pCell;

    /* Remove cell boundary if it is between the end paragraph run and the next
     * paragraph display item. */
    for (tmp = run_get_di( end_run ); tmp != para_get_di( next ); tmp = tmp->next)
    {
      if (tmp->type == diCell)
      {
        pCell = tmp;
        break;
      }
    }
  }

  add_undo_split_para( editor, next, eol_str, pCell ? &pCell->member.cell : NULL );

  if (pCell)
  {
    ME_Remove( pCell );
    if (pCell->member.cell.prev_cell)
      pCell->member.cell.prev_cell->member.cell.next_cell = pCell->member.cell.next_cell;
    if (pCell->member.cell.next_cell)
      pCell->member.cell.next_cell->member.cell.prev_cell = pCell->member.cell.prev_cell;
    ME_DestroyDisplayItem( pCell );
  }

  if (!use_first_fmt)
  {
    add_undo_set_para_fmt( editor, para );
    para->fmt = next->fmt;
    para->border = next->border;
  }

  shift = next->nCharOfs - para->nCharOfs - end_len;

  /* Update selection cursors so they don't point to the removed end
   * paragraph run, and point to the correct paragraph. */
  for (i = 0; i < editor->nCursors; i++)
  {
    if (editor->pCursors[i].pRun == run_get_di( end_run ))
    {
      editor->pCursors[i].pRun = run_get_di( next_first_run );
      editor->pCursors[i].nOffset = 0;
    }
    else if (editor->pCursors[i].pPara == para_get_di( next ))
      editor->pCursors[i].pPara = para_get_di( para );
  }

  for (tmp_run = next_first_run; tmp_run; tmp_run = run_next( tmp_run ))
  {
    TRACE( "shifting %s by %d (previous %d)\n", debugstr_run( tmp_run ), shift, tmp_run->nCharOfs );
    tmp_run->nCharOfs += shift;
    tmp_run->para = para;
  }

  /* Fix up the para's eop_run ptr */
  para->eop_run = next->eop_run;

  ME_Remove( run_get_di( end_run ) );
  ME_DestroyDisplayItem( run_get_di( end_run) );

  if (editor->pLastSelStartPara == para_get_di( next ))
    editor->pLastSelStartPara = para_get_di( para );
  if (editor->pLastSelEndPara == para_get_di( next ))
    editor->pLastSelEndPara = para_get_di( para );

  para->next_para = next->next_para;
  next->next_para->member.para.prev_para = para_get_di( para );
  ME_Remove( para_get_di(next) );
  destroy_para( editor, para_get_di( next ) );

  ME_PropagateCharOffset( para->next_para, -end_len );

  ME_CheckCharOffsets(editor);

  editor->nParagraphs--;
  para_mark_rewrap( editor, para );
  return para;
}

ME_DisplayItem *ME_GetParagraph(ME_DisplayItem *item) {
  return ME_FindItemBackOrHere(item, diParagraph);
}

void ME_DumpParaStyleToBuf(const PARAFORMAT2 *pFmt, char buf[2048])
{
  char *p;
  p = buf;

#define DUMP(mask, name, fmt, field) \
  if (pFmt->dwMask & (mask)) p += sprintf(p, "%-22s" fmt "\n", name, pFmt->field); \
  else p += sprintf(p, "%-22sN/A\n", name);

/* we take for granted that PFE_xxx is the hiword of the corresponding PFM_xxx */
#define DUMP_EFFECT(mask, name) \
  p += sprintf(p, "%-22s%s\n", name, (pFmt->dwMask & (mask)) ? ((pFmt->wEffects & ((mask) >> 16)) ? "yes" : "no") : "N/A");

  DUMP(PFM_NUMBERING,      "Numbering:",         "%u", wNumbering);
  DUMP_EFFECT(PFM_DONOTHYPHEN,     "Disable auto-hyphen:");
  DUMP_EFFECT(PFM_KEEP,            "No page break in para:");
  DUMP_EFFECT(PFM_KEEPNEXT,        "No page break in para & next:");
  DUMP_EFFECT(PFM_NOLINENUMBER,    "No line number:");
  DUMP_EFFECT(PFM_NOWIDOWCONTROL,  "No widow & orphan:");
  DUMP_EFFECT(PFM_PAGEBREAKBEFORE, "Page break before:");
  DUMP_EFFECT(PFM_RTLPARA,         "RTL para:");
  DUMP_EFFECT(PFM_SIDEBYSIDE,      "Side by side:");
  DUMP_EFFECT(PFM_TABLE,           "Table:");
  DUMP(PFM_OFFSETINDENT,   "Offset indent:",     "%d", dxStartIndent);
  DUMP(PFM_STARTINDENT,    "Start indent:",      "%d", dxStartIndent);
  DUMP(PFM_RIGHTINDENT,    "Right indent:",      "%d", dxRightIndent);
  DUMP(PFM_OFFSET,         "Offset:",            "%d", dxOffset);
  if (pFmt->dwMask & PFM_ALIGNMENT) {
    switch (pFmt->wAlignment) {
    case PFA_LEFT   : p += sprintf(p, "Alignment:            left\n"); break;
    case PFA_RIGHT  : p += sprintf(p, "Alignment:            right\n"); break;
    case PFA_CENTER : p += sprintf(p, "Alignment:            center\n"); break;
    case PFA_JUSTIFY: p += sprintf(p, "Alignment:            justify\n"); break;
    default         : p += sprintf(p, "Alignment:            incorrect %d\n", pFmt->wAlignment); break;
    }
  }
  else p += sprintf(p, "Alignment:            N/A\n");
  DUMP(PFM_TABSTOPS,       "Tab Stops:",         "%d", cTabCount);
  if (pFmt->dwMask & PFM_TABSTOPS) {
    int i;
    p += sprintf(p, "\t");
    for (i = 0; i < pFmt->cTabCount; i++) p += sprintf(p, "%x ", pFmt->rgxTabs[i]);
    p += sprintf(p, "\n");
  }
  DUMP(PFM_SPACEBEFORE,    "Space Before:",      "%d", dySpaceBefore);
  DUMP(PFM_SPACEAFTER,     "Space After:",       "%d", dySpaceAfter);
  DUMP(PFM_LINESPACING,    "Line spacing:",      "%d", dyLineSpacing);
  DUMP(PFM_STYLE,          "Text style:",        "%d", sStyle);
  DUMP(PFM_LINESPACING,    "Line spacing rule:", "%u", bLineSpacingRule);
  /* bOutlineLevel should be 0 */
  DUMP(PFM_SHADING,        "Shading Weight:",    "%u", wShadingWeight);
  DUMP(PFM_SHADING,        "Shading Style:",     "%u", wShadingStyle);
  DUMP(PFM_NUMBERINGSTART, "Numbering Start:",   "%u", wNumberingStart);
  DUMP(PFM_NUMBERINGSTYLE, "Numbering Style:",   "0x%x", wNumberingStyle);
  DUMP(PFM_NUMBERINGTAB,   "Numbering Tab:",     "%u", wNumberingStyle);
  DUMP(PFM_BORDER,         "Border Space:",      "%u", wBorderSpace);
  DUMP(PFM_BORDER,         "Border Width:",      "%u", wBorderWidth);
  DUMP(PFM_BORDER,         "Borders:",           "%u", wBorders);

#undef DUMP
#undef DUMP_EFFECT
}

void
ME_GetSelectionParas(ME_TextEditor *editor, ME_DisplayItem **para, ME_DisplayItem **para_end)
{
  ME_Cursor *pEndCursor = &editor->pCursors[1];

  *para = editor->pCursors[0].pPara;
  *para_end = editor->pCursors[1].pPara;
  if (*para == *para_end)
    return;

  if ((*para_end)->member.para.nCharOfs < (*para)->member.para.nCharOfs) {
    ME_DisplayItem *tmp = *para;

    *para = *para_end;
    *para_end = tmp;
    pEndCursor = &editor->pCursors[0];
  }

  /* The paragraph at the end of a non-empty selection isn't included
   * if the selection ends at the start of the paragraph. */
  if (!pEndCursor->pRun->member.run.nCharOfs && !pEndCursor->nOffset)
    *para_end = (*para_end)->member.para.prev_para;
}


BOOL ME_SetSelectionParaFormat(ME_TextEditor *editor, const PARAFORMAT2 *pFmt)
{
  ME_DisplayItem *para, *para_end;

  ME_GetSelectionParas(editor, &para, &para_end);

  do {
    ME_SetParaFormat(editor, &para->member.para, pFmt);
    if (para == para_end)
      break;
    para = para->member.para.next_para;
  } while(1);

  return TRUE;
}

static void ME_GetParaFormat(ME_TextEditor *editor,
                             const ME_DisplayItem *para,
                             PARAFORMAT2 *pFmt)
{
  UINT cbSize = pFmt->cbSize;
  if (pFmt->cbSize >= sizeof(PARAFORMAT2)) {
    *pFmt = para->member.para.fmt;
  } else {
    CopyMemory(pFmt, &para->member.para.fmt, pFmt->cbSize);
    pFmt->dwMask &= PFM_ALL;
  }
  pFmt->cbSize = cbSize;
}

void ME_GetSelectionParaFormat(ME_TextEditor *editor, PARAFORMAT2 *pFmt)
{
  ME_DisplayItem *para, *para_end;
  PARAFORMAT2 *curFmt;

  if (pFmt->cbSize < sizeof(PARAFORMAT)) {
    pFmt->dwMask = 0;
    return;
  }

  ME_GetSelectionParas(editor, &para, &para_end);

  ME_GetParaFormat(editor, para, pFmt);

  /* Invalidate values that change across the selected paragraphs. */
  while (para != para_end)
  {
    para = para->member.para.next_para;
    curFmt = &para->member.para.fmt;

#define CHECK_FIELD(m, f) \
    if (pFmt->f != curFmt->f) pFmt->dwMask &= ~(m);

    CHECK_FIELD(PFM_NUMBERING, wNumbering);
    CHECK_FIELD(PFM_STARTINDENT, dxStartIndent);
    CHECK_FIELD(PFM_RIGHTINDENT, dxRightIndent);
    CHECK_FIELD(PFM_OFFSET, dxOffset);
    CHECK_FIELD(PFM_ALIGNMENT, wAlignment);
    if (pFmt->dwMask & PFM_TABSTOPS) {
      if (pFmt->cTabCount != para->member.para.fmt.cTabCount ||
          memcmp(pFmt->rgxTabs, curFmt->rgxTabs, curFmt->cTabCount*sizeof(int)))
        pFmt->dwMask &= ~PFM_TABSTOPS;
    }

    if (pFmt->dwMask >= sizeof(PARAFORMAT2))
    {
      pFmt->dwMask &= ~((pFmt->wEffects ^ curFmt->wEffects) << 16);
      CHECK_FIELD(PFM_SPACEBEFORE, dySpaceBefore);
      CHECK_FIELD(PFM_SPACEAFTER, dySpaceAfter);
      CHECK_FIELD(PFM_LINESPACING, dyLineSpacing);
      CHECK_FIELD(PFM_STYLE, sStyle);
      CHECK_FIELD(PFM_SPACEAFTER, bLineSpacingRule);
      CHECK_FIELD(PFM_SHADING, wShadingWeight);
      CHECK_FIELD(PFM_SHADING, wShadingStyle);
      CHECK_FIELD(PFM_NUMBERINGSTART, wNumberingStart);
      CHECK_FIELD(PFM_NUMBERINGSTYLE, wNumberingStyle);
      CHECK_FIELD(PFM_NUMBERINGTAB, wNumberingTab);
      CHECK_FIELD(PFM_BORDER, wBorderSpace);
      CHECK_FIELD(PFM_BORDER, wBorderWidth);
      CHECK_FIELD(PFM_BORDER, wBorders);
    }
#undef CHECK_FIELD
  }
}

void ME_SetDefaultParaFormat(ME_TextEditor *editor, PARAFORMAT2 *pFmt)
{
    const PARAFORMAT2 *host_fmt;
    HRESULT hr;

    ZeroMemory(pFmt, sizeof(PARAFORMAT2));
    pFmt->cbSize = sizeof(PARAFORMAT2);
    pFmt->dwMask = PFM_ALL2;
    pFmt->wAlignment = PFA_LEFT;
    pFmt->sStyle = -1;
    pFmt->bOutlineLevel = TRUE;

    hr = ITextHost_TxGetParaFormat( editor->texthost, (const PARAFORMAT **)&host_fmt );
    if (SUCCEEDED(hr))
    {
        /* Just use the alignment for now */
        if (host_fmt->dwMask & PFM_ALIGNMENT)
            pFmt->wAlignment = host_fmt->wAlignment;
        ITextHost_OnTxParaFormatChange( editor->texthost, (PARAFORMAT *)pFmt );
    }
}
