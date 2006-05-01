/*
 * DNS support
 *
 * Copyright (C) 2006 Hans Leidekker
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"
#include "wine/port.h"
#include "wine/debug.h"

#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "winnls.h"
#include "windns.h"

#include "dnsapi.h"

WINE_DEFAULT_DEBUG_CHANNEL(dnsapi);

const char *dns_type_to_str( unsigned short type )
{
    switch (type)
    {
#define X(x)    case (x): return #x;
    X(DNS_TYPE_ZERO)
    X(DNS_TYPE_A)
    X(DNS_TYPE_NS)
    X(DNS_TYPE_MD)
    X(DNS_TYPE_MF)
    X(DNS_TYPE_CNAME)
    X(DNS_TYPE_SOA)
    X(DNS_TYPE_MB)
    X(DNS_TYPE_MG)
    X(DNS_TYPE_MR)
    X(DNS_TYPE_NULL)
    X(DNS_TYPE_WKS)
    X(DNS_TYPE_PTR)
    X(DNS_TYPE_HINFO)
    X(DNS_TYPE_MINFO)
    X(DNS_TYPE_MX)
    X(DNS_TYPE_TEXT)
    X(DNS_TYPE_RP)
    X(DNS_TYPE_AFSDB)
    X(DNS_TYPE_X25)
    X(DNS_TYPE_ISDN)
    X(DNS_TYPE_RT)
    X(DNS_TYPE_NSAP)
    X(DNS_TYPE_NSAPPTR)
    X(DNS_TYPE_SIG)
    X(DNS_TYPE_KEY)
    X(DNS_TYPE_PX)
    X(DNS_TYPE_GPOS)
    X(DNS_TYPE_AAAA)
    X(DNS_TYPE_LOC)
    X(DNS_TYPE_NXT)
    X(DNS_TYPE_EID)
    X(DNS_TYPE_NIMLOC)
    X(DNS_TYPE_SRV)
    X(DNS_TYPE_ATMA)
    X(DNS_TYPE_NAPTR)
    X(DNS_TYPE_KX)
    X(DNS_TYPE_CERT)
    X(DNS_TYPE_A6)
    X(DNS_TYPE_DNAME)
    X(DNS_TYPE_SINK)
    X(DNS_TYPE_OPT)
    X(DNS_TYPE_UINFO)
    X(DNS_TYPE_UID)
    X(DNS_TYPE_GID)
    X(DNS_TYPE_UNSPEC)
    X(DNS_TYPE_ADDRS)
    X(DNS_TYPE_TKEY)
    X(DNS_TYPE_TSIG)
    X(DNS_TYPE_IXFR)
    X(DNS_TYPE_AXFR)
    X(DNS_TYPE_MAILB)
    X(DNS_TYPE_MAILA)
    X(DNS_TYPE_ANY)
    X(DNS_TYPE_WINS)
    X(DNS_TYPE_WINSR)
#undef X
    default: { static char tmp[7]; sprintf( tmp, "0x%04x", type ); return tmp; }
    }
}

static int dns_strcmpX( LPCVOID str1, LPCVOID str2, BOOL wide )
{
    if (wide)
        return lstrcmpiW( (LPCWSTR)str1, (LPCWSTR)str2 );
    else
        return lstrcmpiA( (LPCSTR)str1, (LPCSTR)str2 );
}

/******************************************************************************
 * DnsRecordCompare                        [DNSAPI.@]
 *
 */
BOOL WINAPI DnsRecordCompare( PDNS_RECORD r1, PDNS_RECORD r2 )
{
    BOOL wide;
    unsigned int i;

    TRACE( "(%p,%p)\n", r1, r2 );

    if (r1->wType       != r2->wType       ||
        r1->wDataLength != r2->wDataLength ||
        r1->Flags.DW    != r2->Flags.DW    ||
        r1->dwTtl       != r2->dwTtl       ||
        r1->dwReserved  != r2->dwReserved) return FALSE;

    wide = (r1->Flags.S.CharSet == DnsCharSetUnicode) ? TRUE : FALSE;
    if (dns_strcmpX( r1->pName, r2->pName, wide )) return FALSE;

    switch (r1->wType)
    {
    case DNS_TYPE_A:
    {
        if (r1->Data.A.IpAddress != r2->Data.A.IpAddress) return FALSE;
        break;
    }
    case DNS_TYPE_SOA:
    {
        if (r1->Data.SOA.dwSerialNo   != r2->Data.SOA.dwSerialNo ||
            r1->Data.SOA.dwRefresh    != r2->Data.SOA.dwRefresh  ||
            r1->Data.SOA.dwRetry      != r2->Data.SOA.dwRetry    ||
            r1->Data.SOA.dwExpire     != r2->Data.SOA.dwExpire   ||
            r1->Data.SOA.dwDefaultTtl != r2->Data.SOA.dwDefaultTtl)
            return FALSE;
        if (dns_strcmpX( r1->Data.SOA.pNamePrimaryServer,
                         r2->Data.SOA.pNamePrimaryServer, wide ) ||
            dns_strcmpX( r1->Data.SOA.pNameAdministrator,
                         r2->Data.SOA.pNameAdministrator, wide ))
            return FALSE;
        break;
    }
    case DNS_TYPE_PTR:
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_MB:
    case DNS_TYPE_MD:
    case DNS_TYPE_MF:
    case DNS_TYPE_MG:
    case DNS_TYPE_MR:
    {
        if (dns_strcmpX( r1->Data.PTR.pNameHost,
                         r2->Data.PTR.pNameHost, wide )) return FALSE;
        break;
    }
    case DNS_TYPE_MINFO:
    case DNS_TYPE_RP:
    {
        if (dns_strcmpX( r1->Data.MINFO.pNameMailbox,
                         r2->Data.MINFO.pNameMailbox, wide ) ||
            dns_strcmpX( r1->Data.MINFO.pNameErrorsMailbox,
                         r2->Data.MINFO.pNameErrorsMailbox, wide ))
            return FALSE;
        break;
    }
    case DNS_TYPE_MX:
    case DNS_TYPE_AFSDB:
    case DNS_TYPE_RT:
    {
        if (r1->Data.MX.wPreference != r2->Data.MX.wPreference)
            return FALSE;
        if (dns_strcmpX( r1->Data.MX.pNameExchange,
                         r2->Data.MX.pNameExchange, wide ))
            return FALSE;
        break;
    }
    case DNS_TYPE_HINFO:
    case DNS_TYPE_ISDN:
    case DNS_TYPE_TEXT:
    case DNS_TYPE_X25:
    {
        if (r1->Data.TXT.dwStringCount != r2->Data.TXT.dwStringCount)
            return FALSE;
        for (i = 0; i < r1->Data.TXT.dwStringCount; i++)
        {
            if (dns_strcmpX( r1->Data.TXT.pStringArray[i],
                             r2->Data.TXT.pStringArray[i], wide ))
                return FALSE;
        }
        break;
    }
    case DNS_TYPE_NULL:
    {
        if (r1->Data.Null.dwByteCount != r2->Data.Null.dwByteCount)
            return FALSE;
        if (memcmp( r1->Data.Null.Data,
                    r2->Data.Null.Data, r1->Data.Null.dwByteCount ))
            return FALSE;
        break;
    }
    case DNS_TYPE_AAAA:
    {
        for (i = 0; i < sizeof(IP6_ADDRESS)/sizeof(DWORD); i++)
        {
            if (r1->Data.AAAA.Ip6Address.IP6Dword[i] !=
                r2->Data.AAAA.Ip6Address.IP6Dword[i]) return FALSE;
        }
        break;
    }
    case DNS_TYPE_KEY:
    {
        if (r1->Data.KEY.wFlags      != r2->Data.KEY.wFlags      ||
            r1->Data.KEY.chProtocol  != r2->Data.KEY.chProtocol  ||
            r1->Data.KEY.chAlgorithm != r2->Data.KEY.chAlgorithm)
            return FALSE;
        if (memcmp( r1->Data.KEY.Key, r2->Data.KEY.Key,
                    r1->wDataLength - sizeof(DNS_KEY_DATA) + 1 ))
            return FALSE;
        break;
    }
    case DNS_TYPE_SIG:
    {
        if (dns_strcmpX( r1->Data.SIG.pNameSigner,
                         r2->Data.SIG.pNameSigner, wide ))
            return FALSE;
        if (r1->Data.SIG.wTypeCovered  != r2->Data.SIG.wTypeCovered  ||
            r1->Data.SIG.chAlgorithm   != r2->Data.SIG.chAlgorithm   ||
            r1->Data.SIG.chLabelCount  != r2->Data.SIG.chLabelCount  ||
            r1->Data.SIG.dwOriginalTtl != r2->Data.SIG.dwOriginalTtl ||
            r1->Data.SIG.dwExpiration  != r2->Data.SIG.dwExpiration  ||
            r1->Data.SIG.dwTimeSigned  != r2->Data.SIG.dwTimeSigned  ||
            r1->Data.SIG.wKeyTag       != r2->Data.SIG.wKeyTag)
            return FALSE;
        if (memcmp( r1->Data.SIG.Signature, r2->Data.SIG.Signature,
                    r1->wDataLength - sizeof(DNS_SIG_DATAA) + 1 ))
            return FALSE;
        break;
    }
    case DNS_TYPE_ATMA:
    {
        if (r1->Data.ATMA.AddressType != r2->Data.ATMA.AddressType)
            return FALSE;
        for (i = 0; i < DNS_ATMA_MAX_ADDR_LENGTH; i++)
        {
            if (r1->Data.ATMA.Address[i] != r2->Data.ATMA.Address[i])
                return FALSE;
        }
        break;
    }
    case DNS_TYPE_NXT:
    {
        if (dns_strcmpX( r1->Data.NXT.pNameNext,
                         r2->Data.NXT.pNameNext, wide )) return FALSE;
        if (r1->Data.NXT.wNumTypes != r2->Data.NXT.wNumTypes) return FALSE;
        if (memcmp( r1->Data.NXT.wTypes, r2->Data.NXT.wTypes,
                    r1->wDataLength - sizeof(DNS_NXT_DATAA) + sizeof(WORD) ))
            return FALSE;
        break;
    }
    case DNS_TYPE_SRV:
    {
        if (dns_strcmpX( r1->Data.SRV.pNameTarget,
                         r2->Data.SRV.pNameTarget, wide )) return FALSE;
        if (r1->Data.SRV.wPriority != r2->Data.SRV.wPriority ||
            r1->Data.SRV.wWeight   != r2->Data.SRV.wWeight   ||
            r1->Data.SRV.wPort     != r2->Data.SRV.wPort)
            return FALSE;
        break;
    }
    case DNS_TYPE_TKEY:
    {
        if (dns_strcmpX( r1->Data.TKEY.pNameAlgorithm,
                         r2->Data.TKEY.pNameAlgorithm, wide ))
            return FALSE;
        if (r1->Data.TKEY.dwCreateTime    != r2->Data.TKEY.dwCreateTime     ||
            r1->Data.TKEY.dwExpireTime    != r2->Data.TKEY.dwExpireTime     ||
            r1->Data.TKEY.wMode           != r2->Data.TKEY.wMode            ||
            r1->Data.TKEY.wError          != r2->Data.TKEY.wError           ||
            r1->Data.TKEY.wKeyLength      != r2->Data.TKEY.wKeyLength       ||
            r1->Data.TKEY.wOtherLength    != r2->Data.TKEY.wOtherLength     ||
            r1->Data.TKEY.cAlgNameLength  != r2->Data.TKEY.cAlgNameLength   ||
            r1->Data.TKEY.bPacketPointers != r2->Data.TKEY.bPacketPointers)
            return FALSE;

        /* FIXME: ignoring pAlgorithmPacket field */
        if (memcmp( r1->Data.TKEY.pKey, r2->Data.TKEY.pKey,
                    r1->Data.TKEY.wKeyLength ) ||
            memcmp( r1->Data.TKEY.pOtherData, r2->Data.TKEY.pOtherData,
                    r1->Data.TKEY.wOtherLength )) return FALSE;
        break;
    }
    case DNS_TYPE_TSIG:
    {
        if (dns_strcmpX( r1->Data.TSIG.pNameAlgorithm,
                         r2->Data.TSIG.pNameAlgorithm, wide ))
            return FALSE;
        if (r1->Data.TSIG.i64CreateTime   != r2->Data.TSIG.i64CreateTime    ||
            r1->Data.TSIG.wFudgeTime      != r2->Data.TSIG.wFudgeTime       ||
            r1->Data.TSIG.wOriginalXid    != r2->Data.TSIG.wOriginalXid     ||
            r1->Data.TSIG.wError          != r2->Data.TSIG.wError           ||
            r1->Data.TSIG.wSigLength      != r2->Data.TSIG.wSigLength       ||
            r1->Data.TSIG.wOtherLength    != r2->Data.TSIG.wOtherLength     ||
            r1->Data.TSIG.cAlgNameLength  != r2->Data.TSIG.cAlgNameLength   ||
            r1->Data.TSIG.bPacketPointers != r2->Data.TSIG.bPacketPointers)
            return FALSE;

        /* FIXME: ignoring pAlgorithmPacket field */
        if (memcmp( r1->Data.TSIG.pSignature, r2->Data.TSIG.pSignature,
                    r1->Data.TSIG.wSigLength ) ||
            memcmp( r1->Data.TSIG.pOtherData, r2->Data.TSIG.pOtherData,
                    r1->Data.TSIG.wOtherLength )) return FALSE;
        break;
    }
    case DNS_TYPE_WINS:
    {
        if (r1->Data.WINS.dwMappingFlag    != r2->Data.WINS.dwMappingFlag   ||
            r1->Data.WINS.dwLookupTimeout  != r2->Data.WINS.dwLookupTimeout ||
            r1->Data.WINS.dwCacheTimeout   != r2->Data.WINS.dwCacheTimeout  ||
            r1->Data.WINS.cWinsServerCount != r2->Data.WINS.cWinsServerCount)
            return FALSE;
        if (memcmp( r1->Data.WINS.WinsServers, r2->Data.WINS.WinsServers,
                    r1->wDataLength - sizeof(DNS_WINS_DATA) + sizeof(IP4_ADDRESS) ))
            return FALSE;
        break;
    }
    case DNS_TYPE_WINSR:
    {
        if (r1->Data.WINSR.dwMappingFlag   != r2->Data.WINSR.dwMappingFlag   ||
            r1->Data.WINSR.dwLookupTimeout != r2->Data.WINSR.dwLookupTimeout ||
            r1->Data.WINSR.dwCacheTimeout  != r2->Data.WINSR.dwCacheTimeout)
            return FALSE;
        if (dns_strcmpX( r1->Data.WINSR.pNameResultDomain,
                         r2->Data.WINSR.pNameResultDomain, wide ))
            return FALSE;
        break;
    }
    default:
        FIXME( "unknown type: %s\n", dns_type_to_str( r1->wType ) );
        return FALSE;
    }
    return TRUE;
}

static LPVOID dns_strcpyX( LPCVOID src, DNS_CHARSET in, DNS_CHARSET out )
{
    switch (in)
    {
    case DnsCharSetUnicode:
    {
        switch (out)
        {
        case DnsCharSetUnicode: return dns_strdup_w( src );
        case DnsCharSetUtf8:    return dns_strdup_wu( src );
        case DnsCharSetAnsi:    return dns_strdup_wa( src );
        default:
            WARN( "unhandled target charset: %d\n", out );
            break;
        }
    }
    case DnsCharSetUtf8:
        switch (out)
        {
        case DnsCharSetUnicode: return dns_strdup_uw( src );
        case DnsCharSetUtf8:    return dns_strdup_u( src );
        case DnsCharSetAnsi:    return dns_strdup_ua( src );
        default:
            WARN( "unhandled target charset: %d\n", out );
            break;
        }
    case DnsCharSetAnsi:
        switch (out)
        {
        case DnsCharSetUnicode: return dns_strdup_aw( src );
        case DnsCharSetUtf8:    return dns_strdup_au( src );
        case DnsCharSetAnsi:    return dns_strdup_a( src );
        default:
            WARN( "unhandled target charset: %d\n", out );
            break;
        }
    default:
        WARN( "unhandled source charset: %d\n", in );
        break;
    }
    return NULL;
}

/******************************************************************************
 * DnsRecordCopyEx                         [DNSAPI.@]
 *
 */
PDNS_RECORD WINAPI DnsRecordCopyEx( PDNS_RECORD src, DNS_CHARSET in, DNS_CHARSET out )
{
    DNS_RECORD *dst;
    unsigned int i, size;

    TRACE( "(%p,%d,%d)\n", src, in, out );

    size = FIELD_OFFSET(DNS_RECORD, Data) + src->wDataLength;
    dst = dns_zero_alloc( size );
    if (!dst) return NULL;

    memcpy( dst, src, size );

    if (src->Flags.S.CharSet == DnsCharSetUtf8 ||
        src->Flags.S.CharSet == DnsCharSetAnsi ||
        src->Flags.S.CharSet == DnsCharSetUnicode) in = src->Flags.S.CharSet;

    dst->Flags.S.CharSet = out;
    dst->pName = dns_strcpyX( src->pName, in, out );
    if (!dst->pName) goto error;

    switch (src->wType)
    {
    case DNS_TYPE_HINFO:
    case DNS_TYPE_ISDN:
    case DNS_TYPE_TEXT:
    case DNS_TYPE_X25:
    {
        for (i = 0; i < src->Data.TXT.dwStringCount; i++)
        {
            dst->Data.TXT.pStringArray[i] =
                dns_strcpyX( src->Data.TXT.pStringArray[i], in, out );

            if (!dst->Data.TXT.pStringArray[i])
            {
                for (--i; i >= 0; i--)
                    dns_free( dst->Data.TXT.pStringArray[i] );
                goto error;
            }
        }
        break;
    }
    case DNS_TYPE_MINFO:
    case DNS_TYPE_RP:
    {
        dst->Data.MINFO.pNameMailbox =
            dns_strcpyX( src->Data.MINFO.pNameMailbox, in, out );
        if (!dst->Data.MINFO.pNameMailbox) goto error;

        dst->Data.MINFO.pNameErrorsMailbox =
            dns_strcpyX( src->Data.MINFO.pNameErrorsMailbox, in, out );
        if (!dst->Data.MINFO.pNameErrorsMailbox)
        {
            dns_free( dst->Data.MINFO.pNameMailbox );
            goto error;
        }
        break;
    }
    case DNS_TYPE_AFSDB:
    case DNS_TYPE_RT:
    case DNS_TYPE_MX:
    {
        dst->Data.MX.pNameExchange =
            dns_strcpyX( src->Data.MX.pNameExchange, in, out );
        if (!dst->Data.MX.pNameExchange) goto error;
        break;
    }
    case DNS_TYPE_NXT:
    {
        dst->Data.NXT.pNameNext =
            dns_strcpyX( src->Data.NXT.pNameNext, in, out );
        if (!dst->Data.NXT.pNameNext) goto error;
        break;
    }
    case DNS_TYPE_CNAME:
    case DNS_TYPE_MB:
    case DNS_TYPE_MD:
    case DNS_TYPE_MF:
    case DNS_TYPE_MG:
    case DNS_TYPE_MR:
    case DNS_TYPE_NS:
    case DNS_TYPE_PTR:
    {
        dst->Data.PTR.pNameHost =
            dns_strcpyX( src->Data.PTR.pNameHost, in, out );
        if (!dst->Data.PTR.pNameHost) goto error;
        break;
    }
    case DNS_TYPE_SIG:
    {
        dst->Data.SIG.pNameSigner =
            dns_strcpyX( src->Data.SIG.pNameSigner, in, out );
        if (!dst->Data.SIG.pNameSigner) goto error;
        break;
    }
    case DNS_TYPE_SOA:
    {
        dst->Data.SOA.pNamePrimaryServer =
            dns_strcpyX( src->Data.SOA.pNamePrimaryServer, in, out );
        if (!dst->Data.SOA.pNamePrimaryServer) goto error;

        dst->Data.SOA.pNameAdministrator =
            dns_strcpyX( src->Data.SOA.pNameAdministrator, in, out );
        if (!dst->Data.SOA.pNameAdministrator)
        {
            dns_free( dst->Data.SOA.pNamePrimaryServer );
            goto error;
        }
        break;
    }
    case DNS_TYPE_SRV:
    {
        dst->Data.SRV.pNameTarget =
            dns_strcpyX( src->Data.SRV.pNameTarget, in, out );
        if (!dst->Data.SRV.pNameTarget) goto error;
        break;
    }
    default:
        break;
    }
    return dst;

error:
    dns_free( dst->pName );
    dns_free( dst );
    return NULL;
}

/******************************************************************************
 * DnsRecordListFree                       [DNSAPI.@]
 *
 */
void WINAPI DnsRecordListFree( PDNS_RECORD list, DNS_FREE_TYPE type )
{
    DNS_RECORD *r, *next;
    unsigned int i;

    TRACE( "(%p,%d)\n", list, type );

    if (!list) return;

    switch (type)
    {
    case DnsFreeRecordList:
    {
        for (r = list; (list = r); r = next)
        {
            dns_free( r->pName );

            switch (r->wType)
            {
            case DNS_TYPE_HINFO:
            case DNS_TYPE_ISDN:
            case DNS_TYPE_TEXT:
            case DNS_TYPE_X25:
            {
                for (i = 0; i < r->Data.TXT.dwStringCount; i++)
                    dns_free( r->Data.TXT.pStringArray[i] );

                break;
            }
            case DNS_TYPE_MINFO:
            case DNS_TYPE_RP:
            {
                dns_free( r->Data.MINFO.pNameMailbox );
                dns_free( r->Data.MINFO.pNameErrorsMailbox );
                break;
            }
            case DNS_TYPE_AFSDB:
            case DNS_TYPE_RT:
            case DNS_TYPE_MX:
            {
                dns_free( r->Data.MX.pNameExchange );
                break;
            }
            case DNS_TYPE_NXT:
            {
                dns_free( r->Data.NXT.pNameNext );
                break;
            }
            case DNS_TYPE_CNAME:
            case DNS_TYPE_MB:
            case DNS_TYPE_MD:
            case DNS_TYPE_MF:
            case DNS_TYPE_MG:
            case DNS_TYPE_MR:
            case DNS_TYPE_NS:
            case DNS_TYPE_PTR:
            {
                dns_free( r->Data.PTR.pNameHost );
                break;
            }
            case DNS_TYPE_SIG:
            {
                dns_free( r->Data.SIG.pNameSigner );
                break;
            }
            case DNS_TYPE_SOA:
            {
                dns_free( r->Data.SOA.pNamePrimaryServer );
                dns_free( r->Data.SOA.pNameAdministrator );
                break;
            }
            case DNS_TYPE_SRV:
            {
                dns_free( r->Data.SRV.pNameTarget );
                break;
            }
            default:
                break;
            }

            next = r->pNext;
            dns_free( r );
        }
        break;
    }
    case DnsFreeFlat:
    case DnsFreeParsedMessageFields:
    {
        FIXME( "unhandled free type: %d\n", type );
        break;
    }
    default:
        WARN( "unknown free type: %d\n", type );
        break;
    }
}

/******************************************************************************
 * DnsRecordSetCopyEx                      [DNSAPI.@]
 *
 */
PDNS_RECORD WINAPI DnsRecordSetCopyEx( PDNS_RECORD src_set, DNS_CHARSET in, DNS_CHARSET out )
{
    DNS_RRSET dst_set;
    DNS_RECORD *src, *dst;

    TRACE( "(%p,%d,%d)\n", src_set, in, out );

    DNS_RRSET_INIT( dst_set );

    for (src = src_set; (src_set = src); src = src_set->pNext)
    {
        dst = DnsRecordCopyEx( src, in, out );
        if (!dst)
        {
            DNS_RRSET_TERMINATE( dst_set );
            DnsRecordListFree( dst_set.pFirstRR, DnsFreeRecordList );
            return NULL;
        }
        DNS_RRSET_ADD( dst_set, dst );
    }

    DNS_RRSET_TERMINATE( dst_set );
    return dst_set.pFirstRR;
}
