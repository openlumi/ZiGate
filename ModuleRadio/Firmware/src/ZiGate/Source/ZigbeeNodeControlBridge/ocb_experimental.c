/****************************************************************************
 *
 * Open Coordinator Backup (OCB) export/restore, self-contained.
 *
 * Ported from zigate-jn5169-firmware's ocb_experimental.c and custom_diag.c
 * (the OCB_TYPED_SUPPORT section) onto this repo's own, older vendor SDK.
 * See ocb_experimental.h for the wire-protocol/porting overview. This file
 * has no dependency on custom_diag.c, which does not exist here.
 *
 ****************************************************************************/

#include <jendefs.h>
#include <string.h>
#include "SerialLink.h"
#include "app_Znc_cmds.h"
#include "app_common.h"
#include "AppHardwareApi.h"
#include "AppApi.h"
#include "AHI_AES.h"
#include "PDM.h"
#include "PDM_IDs.h"
#include "pdum_apl.h"
#include "zps_gen.h"
#include "zps_apl.h"
#include "zps_apl_zdo.h"
#include "zps_apl_aib.h"
#include "zps_apl_af.h"
#include "zps_nwk_nib.h"
#include "zps_nwk_pub.h"
#include "zps_nwk_sec.h"
#include "rnd_pub.h"
#include "ocb_experimental.h"

/* OpenLumi's application calls this (and u8GetMaxApdu()) throughout
 * app_Znc_cmds.c via an implicit (undeclared) C89 call -- there is no
 * zigate_apdu_diag.h in this repo. Declare it properly here instead of
 * relying on the same implicit-int convention. Real definition lives
 * wherever the rest of this app's status frames already resolve it from
 * (pdum_gen.c-backed PDUM_u16APduGetCrtUse() in this SDK vintage). */
extern PUBLIC uint8 u8GetApduUse(void);

/* This symbol is exported by libZPSAPL_JN516x.a but omitted from the public
 * header. Confirmed identical extern declaration already used, exactly this
 * way, in this repo's own app_Znc_cmds.c. */
extern PUBLIC bool_t zps_bGetFlashCredential(uint64 u64IeeeAddr,
                                              AESSW_Block_u *puKey,
                                              uint16 *pu16Index,
                                              bool_t bTcCred,
                                              bool_t bUpdate);

/* This symbol is exported (T, not just referenced) by
 * libPDM_EEPROM_NO_RTOS_JN516x.a alongside PDM_eIncrementBitmap/PDM_eGetBitmap
 * but omitted from PDM.h. Disassembly of PDM_Bitmap.o confirms it writes the
 * {chain_count, remainder flag bytes} record state directly in one segment
 * write -- see the comment on OCBEXP_FIELD_NWK_OUT_FC below for why this
 * replaces a PDM_eIncrementBitmap() loop. */
extern PDM_teStatus ePDM_SetBitmapToValue(uint16 u16IdValue, uint32 u32Value);

extern PUBLIC bool_t bResetIssued;

#define OCB_TX_MAX                        (96U)
#define OCB_TX_LQI_RESERVE                (1U)

/* Single static buffer shared by every handler in this file (typed export
 * and experimental key export/restore alike). Safe because serial commands
 * are dispatched sequentially from a single application-task context with no
 * handler re-entrancy -- same reasoning as the source repo's custom_diag.c. */
PRIVATE uint8 s_au8OcbTx[OCB_TX_MAX + OCB_TX_LQI_RESERVE];

/* Emit the stock 8-byte E_SL_MSG_STATUS (0x8000) frame, matching the exact
 * field order used by every other command in app_Znc_cmds.c. */
PRIVATE void vOcbSendStatus(uint16 u16PacketType, uint8 u8Status)
{
    uint8 au8Status[9];
    uint8 u8Length = 0;
    ZNC_BUF_U8_UPD  ( &au8Status[ u8Length ], u8Status,             u8Length );
    ZNC_BUF_U8_UPD  ( &au8Status[ u8Length ], 0,                    u8Length ); /* seq num      */
    ZNC_BUF_U16_UPD ( &au8Status[ u8Length ], u16PacketType,        u8Length );
    ZNC_BUF_U8_UPD  ( &au8Status[ u8Length ], 0,                    u8Length ); /* request sent */
    ZNC_BUF_U8_UPD  ( &au8Status[ u8Length ], 0,                    u8Length ); /* aps seq num  */
    ZNC_BUF_U8_UPD  ( &au8Status[ u8Length ], PDUM_u8GetNpduUse(),  u8Length );
    ZNC_BUF_U8_UPD  ( &au8Status[ u8Length ], u8GetApduUse(),       u8Length );
    vSL_WriteMessage(E_SL_MSG_STATUS, u8Length, au8Status, 0);
}

/****************************************************************************/
/***        Typed OCB metadata export (0x0D18..0x0D1C)                    ***/
/****************************************************************************/

#ifdef OCB_TYPED_SUPPORT

#define OCB_DIAG_STATIC_ASSERT(cond, tag) \
    typedef char ocb_diag_static_assert_##tag[(cond) ? 1 : -1]

#ifndef ZPS_COORDINATOR
#error "OCB typed export is valid only for the generated coordinator configuration"
#endif
OCB_DIAG_STATIC_ASSERT(ZPS_MAX_CHANNEL_LIST_SIZE == 1U, ocb_one_channel_mask);
OCB_DIAG_STATIC_ASSERT(sizeof(((ZPS_tsNwkSecMaterialSet *)0)->au8Key) == 16U,
                       ocb_nwk_key_width);
OCB_DIAG_STATIC_ASSERT(OCB_CORE_RSP_LEN <= OCB_TX_MAX, ocb_core_fits);
OCB_DIAG_STATIC_ASSERT(OCB_LINK_RSP_LEN <= OCB_TX_MAX, ocb_link_fits);

/* One small bounded export snapshot prevents CORE from observing a mixture of
 * live states. No key bytes are ever copied into this object. */
typedef struct
{
    uint64 u64CoordinatorIeee;
    uint64 u64ExtPanId;
    uint64 u64TrustCenterIeee;
    uint32 u32TransactionId;
    uint32 u32SessionId;
    uint32 u32FieldBitmap;
    uint32 u32ChannelMask;
    uint32 u32NwkOutgoingCounter;
    uint32 u32Digest;
    uint16 u16PanId;
    uint8  u8Channel;
    uint8  u8UpdateId;
    uint8  u8SecurityLevel;
    uint8  u8NwkKeySequence;
    uint8  u8ApsFlags;
    uint8  u8ApsKeyType;
    uint8  u8Active;
} tsOcbExportSnapshot;

PRIVATE tsOcbExportSnapshot s_sOcbExport;

PRIVATE uint32 u32OcbFnv1a(const uint8 *pu8Data, uint8 u8Length)
{
    uint32 u32Hash = 2166136261UL;
    uint8 i;
    for (i = 0; i < u8Length; i++)
    {
        u32Hash ^= pu8Data[i];
        u32Hash *= 16777619UL;
    }
    return u32Hash;
}

PRIVATE bool_t bOcbCommonRequest(uint16 u16Len, const uint8 *pu8Rx,
                                 uint16 u16Expected, uint32 *pu32Transaction,
                                 uint32 *pu32Session)
{
    if (u16Len != u16Expected)
    {
        return FALSE;
    }
    *pu32Transaction = ZNC_RTN_U32(pu8Rx, 2);
    *pu32Session = (u16Expected >= OCB_COMMON_REQ_LEN) ?
                   ZNC_RTN_U32(pu8Rx, 6) : 0U;
    return TRUE;
}

PRIVATE uint8 u8OcbRequestStatus(const uint8 *pu8Rx, uint32 u32Transaction,
                                 uint32 u32Session)
{
    if (pu8Rx[0] != OCB_ABI_VERSION || pu8Rx[1] != OCB_SCHEMA_VERSION)
    {
        return OCB_STATUS_BAD_VERSION;
    }
    if (!s_sOcbExport.u8Active)
    {
        return OCB_STATUS_NO_SESSION;
    }
    if (s_sOcbExport.u32TransactionId != u32Transaction ||
        s_sOcbExport.u32SessionId != u32Session)
    {
        return OCB_STATUS_SESSION_MISMATCH;
    }
    return OCB_STATUS_OK;
}

PRIVATE uint8 u8OcbWritePrefix(uint32 u32Transaction, uint32 u32Session,
                               uint8 u8Status)
{
    uint8 u8Length = 0;
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], OCB_ABI_VERSION,    u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], OCB_SCHEMA_VERSION, u8Length);
    ZNC_BUF_U32_UPD (&s_au8OcbTx[u8Length], u32Transaction,     u8Length);
    ZNC_BUF_U32_UPD (&s_au8OcbTx[u8Length], u32Session,         u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], u8Status,           u8Length);
    return u8Length; /* 11 */
}

PRIVATE uint8 u8OcbSerialiseCore(uint8 u8Length)
{
    ZNC_BUF_U32_UPD (&s_au8OcbTx[u8Length], s_sOcbExport.u32FieldBitmap,       u8Length);
    ZNC_BUF_U64_UPD (&s_au8OcbTx[u8Length], s_sOcbExport.u64CoordinatorIeee,   u8Length);
    ZNC_BUF_U16_UPD (&s_au8OcbTx[u8Length], s_sOcbExport.u16PanId,             u8Length);
    ZNC_BUF_U64_UPD (&s_au8OcbTx[u8Length], s_sOcbExport.u64ExtPanId,          u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], s_sOcbExport.u8Channel,            u8Length);
    ZNC_BUF_U32_UPD (&s_au8OcbTx[u8Length], s_sOcbExport.u32ChannelMask,       u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], s_sOcbExport.u8UpdateId,           u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], s_sOcbExport.u8SecurityLevel,      u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], s_sOcbExport.u8NwkKeySequence,     u8Length);
    ZNC_BUF_U32_UPD (&s_au8OcbTx[u8Length], s_sOcbExport.u32NwkOutgoingCounter,u8Length);
    ZNC_BUF_U64_UPD (&s_au8OcbTx[u8Length], s_sOcbExport.u64TrustCenterIeee,   u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], s_sOcbExport.u8ApsFlags,           u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], s_sOcbExport.u8ApsKeyType,         u8Length);
    return u8Length;
}

PUBLIC void OCB_vHandleExportBegin(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction, u32Ignored;
    uint8 u8Length, u8Status = OCB_STATUS_OK;
    ZPS_tsNwkNib *psNib;
    ZPS_tsAplAib *psAib;
    uint32 *pu32Masks;
    uint32 u32Channel = 0;

    if (!bOcbCommonRequest(u16Len, pu8Rx, OCB_BEGIN_REQ_LEN,
                           &u32Transaction, &u32Ignored))
    {
        vOcbSendStatus(E_SL_MSG_OCB_EXPORT_BEGIN_REQ,
                       E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return;
    }
    if (pu8Rx[0] != OCB_ABI_VERSION || pu8Rx[1] != OCB_SCHEMA_VERSION)
    {
        u8Status = OCB_STATUS_BAD_VERSION;
    }
    vOcbSendStatus(E_SL_MSG_OCB_EXPORT_BEGIN_REQ, E_SL_MSG_STATUS_SUCCESS);
    if (u8Status == OCB_STATUS_OK)
    {
        memset(&s_sOcbExport, 0, sizeof(s_sOcbExport));
        psNib = ZPS_psNwkNibGetHandle(ZPS_pvAplZdoGetNwkHandle());
        psAib = ZPS_psAplAibGetAib();
        /* This SDK has no ZPS_pu32AplAibGetApsChannelMask() getter -- the AIB
         * exposes the mask directly as a field instead. The static assert on
         * ZPS_MAX_CHANNEL_LIST_SIZE == 1 below covers the same "exactly one
         * mask word" assumption the newer SDK's u8MaskCount check made. */
        pu32Masks = psAib->pau32ApsChannelMask;

        s_sOcbExport.u32TransactionId = u32Transaction;
        s_sOcbExport.u32SessionId = RND_u32GetRand(1, 0xFFFFFFFFUL);
        if (s_sOcbExport.u32SessionId == 0U) { s_sOcbExport.u32SessionId = 1U; }
        s_sOcbExport.u64CoordinatorIeee = ZPS_u64AplZdoGetIeeeAddr();
        s_sOcbExport.u16PanId = psNib->sPersist.u16VsPanId;
        s_sOcbExport.u64ExtPanId = psNib->sPersist.u64ExtPanId;
        s_sOcbExport.u8UpdateId = psNib->sPersist.u8UpdateId;
        s_sOcbExport.u8SecurityLevel = psNib->u8SecurityLevel;
        s_sOcbExport.u8NwkKeySequence = psNib->sPersist.u8ActiveKeySeqNumber;
        s_sOcbExport.u32NwkOutgoingCounter = psNib->sTbl.u32OutFC;
        s_sOcbExport.u64TrustCenterIeee = psAib->u64ApsTrustCenterAddress;
        s_sOcbExport.u8ApsFlags =
            (psAib->bApsDesignatedCoordinator ? 1U : 0U) |
            (psAib->bApsUseInsecureJoin ? 2U : 0U) |
            (psAib->bDecryptInstallCode ? 4U : 0U);
        s_sOcbExport.u8ApsKeyType = psAib->u8KeyType;
        if (eAppApiPlmeGet(PHY_PIB_ATTR_CURRENT_CHANNEL, &u32Channel) ==
            PHY_ENUM_SUCCESS)
        {
            s_sOcbExport.u8Channel = (uint8)u32Channel;
            s_sOcbExport.u32FieldBitmap |= OCB_FIELD_CHANNEL;
        }
        if (pu32Masks != NULL)
        {
            s_sOcbExport.u32ChannelMask = pu32Masks[0];
            s_sOcbExport.u32FieldBitmap |= OCB_FIELD_CHANNEL_MASK;
        }
        s_sOcbExport.u32FieldBitmap |=
            OCB_FIELD_COORD_IEEE | OCB_FIELD_PAN_ID | OCB_FIELD_EXT_PAN_ID |
            OCB_FIELD_NWK_UPDATE_ID | OCB_FIELD_SECURITY_LEVEL |
            OCB_FIELD_NWK_KEY_SEQUENCE | OCB_FIELD_NWK_OUT_COUNTER |
            OCB_FIELD_APS_TC_ADDRESS | OCB_FIELD_APS_STATE;
        s_sOcbExport.u8Active = 1U;

        /* Digest is FNV-1a over the exact 44-byte canonical CORE body,
         * beginning at field_bitmap and excluding the correlated prefix. */
        u8Length = u8OcbSerialiseCore(0U);
        s_sOcbExport.u32Digest = u32OcbFnv1a(s_au8OcbTx, u8Length);
    }

    u8Length = u8OcbWritePrefix(u32Transaction,
                                (u8Status == OCB_STATUS_OK) ?
                                    s_sOcbExport.u32SessionId : 0U,
                                u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCB_CAP_BITMAP, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length],
                    (u8Status == OCB_STATUS_OK) ?
                        s_sOcbExport.u32FieldBitmap : 0U, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCB_EXPORT_BEGIN_RSP, u8Length, s_au8OcbTx, 0);
}

PUBLIC void OCB_vHandleExportCore(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction, u32Session;
    uint8 u8Length, u8Status;
    if (!bOcbCommonRequest(u16Len, pu8Rx, OCB_COMMON_REQ_LEN,
                           &u32Transaction, &u32Session))
    {
        vOcbSendStatus(E_SL_MSG_OCB_EXPORT_CORE_REQ,
                       E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return;
    }
    u8Status = u8OcbRequestStatus(pu8Rx, u32Transaction, u32Session);
    vOcbSendStatus(E_SL_MSG_OCB_EXPORT_CORE_REQ, E_SL_MSG_STATUS_SUCCESS);
    u8Length = u8OcbWritePrefix(u32Transaction, u32Session, u8Status);
    if (u8Status == OCB_STATUS_OK)
    {
        u8Length = u8OcbSerialiseCore(u8Length);
    }
    else
    {
        memset(&s_au8OcbTx[u8Length], 0, OCB_CORE_RSP_LEN - u8Length);
        u8Length = OCB_CORE_RSP_LEN;
    }
    vSL_WriteMessage(E_SL_MSG_OCB_EXPORT_CORE_RSP, u8Length, s_au8OcbTx, 0);
}

PUBLIC void OCB_vHandleExportLinkKey(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction, u32Session;
    uint64 u64RequestedEui = 0U;
    uint8 u8Length, u8Status;
    if (!bOcbCommonRequest(u16Len, pu8Rx, OCB_LINK_REQ_LEN,
                           &u32Transaction, &u32Session))
    {
        vOcbSendStatus(E_SL_MSG_OCB_EXPORT_LINK_KEY_REQ,
                       E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return;
    }
    u64RequestedEui = ZNC_RTN_U64(pu8Rx, 10);
    u8Status = u8OcbRequestStatus(pu8Rx, u32Transaction, u32Session);
    if (u8Status == OCB_STATUS_OK) { u8Status = OCB_STATUS_FIELD_UNAVAILABLE; }
    vOcbSendStatus(E_SL_MSG_OCB_EXPORT_LINK_KEY_REQ, E_SL_MSG_STATUS_SUCCESS);
    u8Length = u8OcbWritePrefix(u32Transaction, u32Session, u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCB_FIELD_LINK_KEYS, u8Length);
    ZNC_BUF_U64_UPD(&s_au8OcbTx[u8Length], u64RequestedEui, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], 0U, u8Length); /* no key bytes */
    vSL_WriteMessage(E_SL_MSG_OCB_EXPORT_LINK_KEY_RSP, u8Length, s_au8OcbTx, 0);
}

PUBLIC void OCB_vHandleExportEnd(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction, u32Session, u32Digest = 0U;
    uint8 u8Length, u8Status;
    if (!bOcbCommonRequest(u16Len, pu8Rx, OCB_COMMON_REQ_LEN,
                           &u32Transaction, &u32Session))
    {
        vOcbSendStatus(E_SL_MSG_OCB_EXPORT_END_REQ,
                       E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return;
    }
    u8Status = u8OcbRequestStatus(pu8Rx, u32Transaction, u32Session);
    if (u8Status == OCB_STATUS_OK) { u32Digest = s_sOcbExport.u32Digest; }
    vOcbSendStatus(E_SL_MSG_OCB_EXPORT_END_REQ, E_SL_MSG_STATUS_SUCCESS);
    u8Length = u8OcbWritePrefix(u32Transaction, u32Session, u8Status);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length],
                   (u8Status == OCB_STATUS_OK) ? 1U : 0U, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32Digest, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCB_EXPORT_END_RSP, u8Length, s_au8OcbTx, 0);
    if (u8Status == OCB_STATUS_OK)
    {
        memset(&s_sOcbExport, 0, sizeof(s_sOcbExport));
    }
}

PUBLIC void OCB_vHandleStatus(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction, u32Session;
    uint8 u8Length, u8Status;
    if (!bOcbCommonRequest(u16Len, pu8Rx, OCB_COMMON_REQ_LEN,
                           &u32Transaction, &u32Session))
    {
        vOcbSendStatus(E_SL_MSG_OCB_STATUS_REQ,
                       E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return;
    }
    u8Status = u8OcbRequestStatus(pu8Rx, u32Transaction, u32Session);
    vOcbSendStatus(E_SL_MSG_OCB_STATUS_REQ, E_SL_MSG_STATUS_SUCCESS);
    u8Length = u8OcbWritePrefix(u32Transaction, u32Session, u8Status);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], s_sOcbExport.u8Active, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length],
                    (u8Status == OCB_STATUS_OK) ?
                        s_sOcbExport.u32FieldBitmap : 0U, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length],
                    (u8Status == OCB_STATUS_OK) ?
                        s_sOcbExport.u32Digest : 0U, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCB_STATUS_RSP, u8Length, s_au8OcbTx, 0);
}

#endif /* OCB_TYPED_SUPPORT */

/****************************************************************************/
/***        Experimental key export/restore (0x0D20..0x0D2A)              ***/
/****************************************************************************/

#ifdef OCB_KEY_EXPORT_RESTORE_EXPERIMENTAL

#define OCBEXP_EXPECTED_SEC_MATERIALS     (2U)
#define OCBEXP_EXPECTED_APS_KEY_ENTRIES   (1U)
#define OCBEXP_EXPECTED_MAC_TABLE         (36U)
#define OCBEXP_FLASH_TCLK_ENTRIES         (70U)

#define OCBEXP_STATIC_ASSERT(cond, tag) \
    typedef char ocbexp_static_assert_##tag[(cond) ? 1 : -1]

OCBEXP_STATIC_ASSERT(sizeof(AESSW_Block_u) == 16U, aes_key_width);
OCBEXP_STATIC_ASSERT(sizeof(((ZPS_tsNwkSecMaterialSet *)0)->au8Key) == 16U,
                     nwk_key_width);
OCBEXP_STATIC_ASSERT(sizeof(((ZPS_tsAplApsKeyDescriptorEntry *)0)->au8LinkKey) == 16U,
                     aps_key_width);
/* This repo's ZPS_tsAplApsKeyDescriptorEntry (zps_apl_aib.h) has no per-entry
 * key-type field (unlike zigate-jn5169-firmware's "legacy" 24-byte layout,
 * which pins the same 3 fields plus one more) -- confirmed struct here is
 * {u32OutgoingFrameCounter; u16ExtAddrLkup; au8LinkKey[16]}, 22 logical bytes,
 * expected to round up to 24 for uint32-aligned array storage. This assert
 * exists to fail the BUILD loudly (not silently corrupt anything) if that
 * layout assumption is wrong for this toolchain/struct packing. */
OCBEXP_STATIC_ASSERT(sizeof(ZPS_tsAplApsKeyDescriptorEntry) == 24U,
                     key_descriptor_layout);
OCBEXP_STATIC_ASSERT(OCBEXP_SECRET_CORE_RSP_LEN <= OCB_TX_MAX, core_fits);
OCBEXP_STATIC_ASSERT(OCBEXP_LINK_RSP_LEN <= OCB_TX_MAX, link_fits);

/* Dedicated ZTimer for the unlock deadline (opened in app_start.c). */
extern uint8 u8OcbUnlockTimer;

PRIVATE uint32 s_u32Challenge;
PRIVATE uint32 s_u32UnlockTransaction;
PRIVATE bool_t s_bUnlocked;

/* Streamed-restore session state. Kept intentionally tiny (no whole-image RAM
 * buffer): identity/keys are applied straight into the live NIB/AIB as
 * fields arrive; only the opt-in adopted IEEE is staged until COMMIT
 * persists it. */
PRIVATE bool_t s_bRestoreSession;
PRIVATE uint32 s_u32RestorePresent;
PRIVATE bool_t s_bAdoptIeeeStaged;
PRIVATE uint64 s_u64AdoptIeee;
/* Program-lifetime backing store for ZPS_vSetOverrideLocalIeeeAddr(), which
 * keeps the pointer (not the value). Written once at boot from PDM. */
PRIVATE uint64 s_u64OverrideIeee;

PRIVATE void vExpWipe(void *pvData, uint16 u16Length)
{
    volatile uint8 *pu8 = (volatile uint8 *)pvData;
    while (u16Length-- != 0U)
    {
        *pu8++ = 0U;
    }
}

PRIVATE bool_t bExpParse(uint16 u16Type, uint16 u16Len, uint16 u16Expected,
                         const uint8 *pu8Rx, uint32 *pu32Transaction)
{
    if (u16Len != u16Expected)
    {
        vOcbSendStatus(u16Type, E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return FALSE;
    }
    *pu32Transaction = ZNC_RTN_U32(pu8Rx, 2);
    vOcbSendStatus(u16Type, E_SL_MSG_STATUS_SUCCESS);
    return TRUE;
}

PRIVATE uint8 u8ExpPrefix(uint32 u32Transaction, uint8 u8Status)
{
    uint8 u8Length = 0;
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], OCBEXP_ABI_VERSION, u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], OCBEXP_SCHEMA_VERSION, u8Length);
    ZNC_BUF_U32_UPD (&s_au8OcbTx[u8Length], u32Transaction, u8Length);
    ZNC_BUF_U8_UPD  (&s_au8OcbTx[u8Length], u8Status, u8Length);
    return u8Length; /* 7 */
}

PRIVATE bool_t bExpVersion(const uint8 *pu8Rx)
{
    return pu8Rx[0] == OCBEXP_ABI_VERSION &&
           pu8Rx[1] == OCBEXP_SCHEMA_VERSION;
}

PRIVATE void vExpLock(void)
{
    s_bUnlocked = FALSE;
    s_u32Challenge = 0U;
    s_u32UnlockTransaction = 0U;
    ZTIMER_eStop(u8OcbUnlockTimer);
    /* Losing the unlock also abandons any in-progress restore. The already
     * applied (unpersisted) NIB/AIB changes are discarded on the next reboot. */
    s_bRestoreSession = FALSE;
    s_u32RestorePresent = 0U;
    s_bAdoptIeeeStaged = FALSE;
    s_u64AdoptIeee = 0U;
}

/* ZTimer callback: fires OCBEXP_UNLOCK_SECONDS after the deadline was last
 * (re)armed by CHALLENGE or a successful UNLOCK. */
PUBLIC void OCBEXP_vUnlockTimeout(void *pvParam)
{
    (void)pvParam;
    vExpLock();
}

PRIVATE bool_t bExpUnlocked(uint32 u32Transaction)
{
    return s_bUnlocked && s_u32UnlockTransaction == u32Transaction;
}

PRIVATE uint8 u8ExpRemainingSeconds(uint32 u32Transaction)
{
    return bExpUnlocked(u32Transaction) ? OCBEXP_UNLOCK_SECONDS : 0U;
}

PRIVATE bool_t bExpLayoutValid(ZPS_tsNwkNib *psNib, ZPS_tsAplAib *psAib)
{
    return psNib != NULL && psAib != NULL &&
           psNib->sTbl.psSecMatSet != NULL &&
           psNib->sTblSize.u8SecMatSet == OCBEXP_EXPECTED_SEC_MATERIALS &&
           psNib->sTblSize.u16MacAddTableSize == OCBEXP_EXPECTED_MAC_TABLE &&
           psAib->psAplDeviceKeyPairTable != NULL &&
           psAib->psAplDeviceKeyPairTable->psAplApsKeyDescriptorEntry != NULL &&
           psAib->psAplDeviceKeyPairTable->u16SizeOfKeyDescriptorTable ==
               OCBEXP_EXPECTED_APS_KEY_ENTRIES &&
           psAib->psAplDefaultTCAPSLinkKey != NULL &&
           psAib->pu32IncomingFrameCounter != NULL;
}

PUBLIC void OCBEXP_vHandleChallenge(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint8 u8Length;
    uint8 u8Status = OCBEXP_STATUS_OK;
    if (!bExpParse(E_SL_MSG_OCBEXP_CHALLENGE_REQ, u16Len, OCBEXP_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    if (!bExpVersion(pu8Rx))
    {
        u8Status = OCBEXP_STATUS_BAD_VERSION;
    }
    vExpLock();
    if (u8Status == OCBEXP_STATUS_OK)
    {
        s_u32Challenge = RND_u32GetRand(1U, 0xFFFFFFFFUL);
        s_u32UnlockTransaction = u32Transaction;
        ZTIMER_eStart(u8OcbUnlockTimer, ZTIMER_TIME_SEC(OCBEXP_UNLOCK_SECONDS));
    }
    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], s_u32Challenge, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], OCBEXP_UNLOCK_SECONDS, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCBEXP_LIMIT_BITMAP, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_CHALLENGE_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleUnlock(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint32 u32Nonce;
    uint32 u32Confirmation;
    uint8 u8Length;
    uint8 u8Status = OCBEXP_STATUS_LOCKED;
    if (!bExpParse(E_SL_MSG_OCBEXP_UNLOCK_REQ, u16Len, OCBEXP_UNLOCK_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    if (!bExpVersion(pu8Rx))
    {
        u8Status = OCBEXP_STATUS_BAD_VERSION;
    }
    else
    {
        u32Nonce = ZNC_RTN_U32(pu8Rx, 6);
        u32Confirmation = ZNC_RTN_U32(pu8Rx, 10);
        if (u32Transaction == s_u32UnlockTransaction &&
            u32Nonce == s_u32Challenge &&
            u32Confirmation ==
                (u32Nonce ^ u32Transaction ^ OCBEXP_CONFIRM_MAGIC))
        {
            s_bUnlocked = TRUE;
            s_u32Challenge = 0U;
            u8Status = OCBEXP_STATUS_OK;
            ZTIMER_eStart(u8OcbUnlockTimer, ZTIMER_TIME_SEC(OCBEXP_UNLOCK_SECONDS));
        }
    }
    if (u8Status != OCBEXP_STATUS_OK) { vExpLock(); }
    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length],
                   (u8Status == OCBEXP_STATUS_OK) ? OCBEXP_UNLOCK_SECONDS : 0U,
                   u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCBEXP_LIMIT_BITMAP, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_UNLOCK_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleSecretCore(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint32 u32Available = 0U;
    uint8 u8Length;
    uint8 u8Status = OCBEXP_STATUS_OK;
    uint8 u8NwkSeq = 0U;
    uint8 u8TcType = 0U;
    uint8 au8NwkKey[16];
    uint8 au8TcKey[16];
    uint32 u32NwkOut = 0U, u32TcOut = 0U, u32TcIn = 0U;
    uint8 i;
    ZPS_tsNwkNib *psNib;
    ZPS_tsAplAib *psAib;

    memset(au8NwkKey, 0, sizeof(au8NwkKey));
    memset(au8TcKey, 0, sizeof(au8TcKey));
    if (!bExpParse(E_SL_MSG_OCBEXP_SECRET_CORE_REQ, u16Len, OCBEXP_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    if (!bExpVersion(pu8Rx)) { u8Status = OCBEXP_STATUS_BAD_VERSION; }
    else if (!bExpUnlocked(u32Transaction)) { u8Status = OCBEXP_STATUS_LOCKED; }

    psNib = ZPS_psNwkNibGetHandle(ZPS_pvAplZdoGetNwkHandle());
    psAib = ZPS_psAplAibGetAib();
    if (u8Status == OCBEXP_STATUS_OK && !bExpLayoutValid(psNib, psAib))
    {
        u8Status = OCBEXP_STATUS_LAYOUT_MISMATCH;
    }
    if (u8Status == OCBEXP_STATUS_OK)
    {
        u8NwkSeq = psNib->sPersist.u8ActiveKeySeqNumber;
        if (ZPS_bNwkSecHaveNetworkKey(ZPS_pvAplZdoGetNwkHandle()))
        {
            for (i = 0; i < psNib->sTblSize.u8SecMatSet; i++)
            {
                if (psNib->sTbl.psSecMatSet[i].u8KeySeqNum == u8NwkSeq)
                {
                    memcpy(au8NwkKey, psNib->sTbl.psSecMatSet[i].au8Key, 16U);
                    u32Available |= OCBEXP_AVAIL_NWK_KEY;
                    break;
                }
            }
        }
        u32NwkOut = psNib->sTbl.u32OutFC;
        u32Available |= OCBEXP_AVAIL_NWK_OUT_COUNTER;

        memcpy(au8TcKey, psAib->psAplDefaultTCAPSLinkKey->au8LinkKey, 16U);
        u8TcType = psAib->u8KeyType;
        u32TcOut = psAib->psAplDefaultTCAPSLinkKey->u32OutgoingFrameCounter;
        /* Generated layout pins default TC key at storage[1], same as the
         * source repo's config. */
        u32TcIn = psAib->pu32IncomingFrameCounter[1];
        u32Available |= OCBEXP_AVAIL_TC_LINK_KEY |
                        OCBEXP_AVAIL_APS_OUT_COUNTER |
                        OCBEXP_AVAIL_APS_IN_COUNTER;
    }

    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32Available, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCBEXP_LIMIT_BITMAP, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8NwkSeq, u8Length);
    memcpy(&s_au8OcbTx[u8Length], au8NwkKey, 16U); u8Length += 16U;
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32NwkOut, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8TcType, u8Length);
    memcpy(&s_au8OcbTx[u8Length], au8TcKey, 16U); u8Length += 16U;
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32TcOut, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32TcIn, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_SECRET_CORE_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(au8NwkKey, sizeof(au8NwkKey));
    vExpWipe(au8TcKey, sizeof(au8TcKey));
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleLinkKey(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint32 u32Available = 0U;
    uint32 u32Outgoing = 0U, u32Incoming = 0U;
    uint64 u64Eui = 0U;
    uint16 u16CredIndex = 0xFFFFU;
    uint8 u8Kind = 0U, u8Index = 0U, u8KeyType = 0U;
    uint8 u8Status = OCBEXP_STATUS_OK, u8Length;
    uint8 au8Key[16];
    AESSW_Block_u uFlashKey;
    ZPS_tsNwkNib *psNib;
    ZPS_tsAplAib *psAib;
    ZPS_tsAplApsKeyDescriptorEntry *psKey = NULL;

    memset(au8Key, 0, sizeof(au8Key));
    memset(&uFlashKey, 0, sizeof(uFlashKey));
    if (!bExpParse(E_SL_MSG_OCBEXP_LINK_KEY_REQ, u16Len, OCBEXP_LINK_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    u8Kind = pu8Rx[6];
    u8Index = pu8Rx[7];
    if (!bExpVersion(pu8Rx)) { u8Status = OCBEXP_STATUS_BAD_VERSION; }
    else if (!bExpUnlocked(u32Transaction)) { u8Status = OCBEXP_STATUS_LOCKED; }

    psNib = ZPS_psNwkNibGetHandle(ZPS_pvAplZdoGetNwkHandle());
    psAib = ZPS_psAplAibGetAib();
    if (u8Status == OCBEXP_STATUS_OK && !bExpLayoutValid(psNib, psAib))
    {
        u8Status = OCBEXP_STATUS_LAYOUT_MISMATCH;
    }
    if (u8Status == OCBEXP_STATUS_OK && u8Kind == OCBEXP_KEY_KIND_DEFAULT_TC &&
        u8Index == 0U)
    {
        psKey = psAib->psAplDefaultTCAPSLinkKey;
        u64Eui = psAib->u64ApsTrustCenterAddress;
        u32Incoming = psAib->pu32IncomingFrameCounter[1];
        u32Available = OCBEXP_AVAIL_TC_LINK_KEY | OCBEXP_AVAIL_APS_OUT_COUNTER |
                       OCBEXP_AVAIL_APS_IN_COUNTER | OCBEXP_AVAIL_EUI;
    }
    else if (u8Status == OCBEXP_STATUS_OK &&
             u8Kind == OCBEXP_KEY_KIND_APS_TABLE &&
             u8Index < psAib->psAplDeviceKeyPairTable->u16SizeOfKeyDescriptorTable)
    {
        psKey = &psAib->psAplDeviceKeyPairTable->psAplApsKeyDescriptorEntry[u8Index];
        if (psKey->u16ExtAddrLkup < psNib->sTblSize.u16MacAddTableSize)
        {
            u64Eui = ZPS_u64NwkNibGetMappedIeeeAddr(
                         ZPS_pvAplZdoGetNwkHandle(), psKey->u16ExtAddrLkup);
        }
        u32Incoming = psAib->pu32IncomingFrameCounter[u8Index];
        u32Available = OCBEXP_AVAIL_APS_OUT_COUNTER |
                       OCBEXP_AVAIL_APS_IN_COUNTER;
        if (u64Eui != 0U && u64Eui != 0xFFFFFFFFFFFFFFFFULL)
        {
            u32Available |= OCBEXP_AVAIL_EUI;
        }
    }
    else if (u8Status == OCBEXP_STATUS_OK &&
             u8Kind == OCBEXP_KEY_KIND_FLASH_TCLK &&
             u8Index < OCBEXP_FLASH_TCLK_ENTRIES)
    {
        u64Eui = ZPS_u64GetFlashMappedIeeeAddress(u8Index);
        if (u64Eui != 0U && u64Eui != 0xFFFFFFFFFFFFFFFFULL &&
            zps_bGetFlashCredential(u64Eui, &uFlashKey, &u16CredIndex,
                                    FALSE, FALSE))
        {
            memcpy(au8Key, uFlashKey.au8, 16U);
            /* This SDK has no per-device APS key-type accessor (unlike the
             * newer SDK's ZPS_u8AplAibGetDeviceApsKeyType()) -- report the
             * single AIB-wide default instead. Reduced fidelity, not a
             * functional gap: the key bytes themselves are exact. */
            u8KeyType = psAib->u8KeyType;
            u32Available = OCBEXP_AVAIL_TC_LINK_KEY | OCBEXP_AVAIL_EUI;
        }
        else
        {
            u8Status = OCBEXP_STATUS_NOT_FOUND;
        }
    }
    else if (u8Status == OCBEXP_STATUS_OK)
    {
        u8Status = OCBEXP_STATUS_NOT_FOUND;
    }

    if (psKey != NULL)
    {
        memcpy(au8Key, psKey->au8LinkKey, 16U);
        /* Same reduced-fidelity note as above: no per-device key-type field
         * exists on this SDK's ZPS_tsAplApsKeyDescriptorEntry, so every kind
         * reports the AIB-wide default u8KeyType. */
        u8KeyType = psAib->u8KeyType;
        u32Outgoing = psKey->u32OutgoingFrameCounter;
        u32Available |= OCBEXP_AVAIL_TC_LINK_KEY;
    }

    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8Kind, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8Index, u8Length);
    ZNC_BUF_U64_UPD(&s_au8OcbTx[u8Length], u64Eui, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32Available, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8KeyType, u8Length);
    memcpy(&s_au8OcbTx[u8Length], au8Key, 16U); u8Length += 16U;
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32Outgoing, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32Incoming, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_LINK_KEY_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(au8Key, sizeof(au8Key));
    vExpWipe(&uFlashKey, sizeof(uFlashKey));
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

/* ------------------------------------------------------------------------- *
 *  Streamed restore (0x0D24..0x0D28)
 * ------------------------------------------------------------------------- */

PRIVATE uint8 u8RestoreGate(uint32 u32Transaction, const uint8 *pu8Rx,
                            bool_t bNeedSession)
{
    if (!bExpVersion(pu8Rx))                    { return OCBEXP_STATUS_BAD_VERSION; }
    if (!bExpUnlocked(u32Transaction))          { return OCBEXP_STATUS_LOCKED; }
    if (bNeedSession && !s_bRestoreSession)     { return OCBEXP_STATUS_NO_SESSION; }
    return OCBEXP_STATUS_OK;
}

/* Apply one recognised restore field into the live NIB/AIB. Unknown ids are
 * skipped (forward compatibility across firmware/PDM revisions). */
PRIVATE uint8 u8RestoreApplyField(uint16 u16FieldId, uint16 u16FieldLen,
                                  const uint8 *pu8Val, void *pvNwk,
                                  ZPS_tsNwkNib *psNib, ZPS_tsAplAib *psAib)
{
    switch (u16FieldId)
    {
    case OCBEXP_FIELD_NWK_KEY:
        if (u16FieldLen != 16U) { return OCBEXP_FIELD_BAD_LENGTH; }
        memcpy(psNib->sTbl.psSecMatSet[0].au8Key, pu8Val, 16U);
        psNib->sTbl.psSecMatSet[0].u8KeyType = ZPS_NWK_SEC_NETWORK_KEY;
        s_u32RestorePresent |= OCBEXP_PRESENT_NWK_KEY;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_NWK_KEY_SEQ:
        if (u16FieldLen != 1U) { return OCBEXP_FIELD_BAD_LENGTH; }
        psNib->sTbl.psSecMatSet[0].u8KeySeqNum = pu8Val[0];
        psNib->sPersist.u8ActiveKeySeqNumber = pu8Val[0];
        s_u32RestorePresent |= OCBEXP_PRESENT_NWK_KEY_SEQ;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_NWK_OUT_FC:
    {
        uint32 u32Target, u32Shift, u32Block, u32Steps;
        if (u16FieldLen != 4U) { return OCBEXP_FIELD_BAD_LENGTH; }
        /* Bump past the backed-up value so no peer sees a replayed counter. */
        u32Target = ZNC_RTN_U32(pu8Val, 0) + OCBEXP_NWK_OUTFC_MARGIN;
        /* Sets this session's live counter, but on its own this does NOT
         * survive a reboot. Independently re-derived (not assumed from
         * zigate-jn5169-firmware) by disassembling THIS repo's own
         * libZPSNWK_JN516x.a: vIncrementFrameCounterInPdm (called from
         * ZPS_pvNwkRestoreFrameCounter at boot) uses the exact same
         * PDM_ID_INTERNAL_NWK_OUT_FC_BITMAP (0xf106) bitmap-popcount
         * mechanism. At boot, ZPS_pvNwkRestoreFrameCounter reads
         * PDM_eGetBitmap(0xf106) and computes
         * u32OutFC = bitmap_value << g_u32NwkFcSaveCountBitShift (that
         * symbol is a plain `extern const uint32` global on this SDK, not a
         * function -- read directly, no call).
         *
         * Reaching a target bitmap value used to mean calling
         * PDM_eIncrementBitmap() that many times, which is O(N) per call
         * (full linear rescan of the record for the next free flag byte,
         * then a full segment-header rewrite) -- O(N^2) overall. HIL with a
         * frame counter in the millions (u32Steps in the thousands) took
         * over 15 minutes and never completed. Disassembling
         * libPDM_EEPROM_NO_RTOS_JN516x.a found ePDM_SetBitmapToValue(), an
         * exported-but-undeclared function (same situation as other
         * `extern`-only symbols this codebase already uses) that writes the
         * equivalent {chain_count, remainder flag bytes} state directly in
         * one PDM_eWriteSegmentHeaderAndData-equivalent call -- confirmed
         * against PDM_eGetBitmap's read path (value = chain_count*44 +
         * popcount(flags)) by reading both the write and read disassembly.
         * O(1) regardless of magnitude, so no step cap is needed. */
        psNib->sTbl.u32OutFC = u32Target;
        u32Shift = g_u32NwkFcSaveCountBitShift;
        if (u32Shift > 31U) { u32Shift = 31U; }
        u32Block = 1UL << u32Shift;
        u32Steps = (u32Target + u32Block - 1UL) / u32Block; /* ceiling */
        (void)PDM_eDeleteBitmap(PDM_ID_INTERNAL_NWK_OUT_FC_BITMAP);
        (void)PDM_eCreateBitmap(PDM_ID_INTERNAL_NWK_OUT_FC_BITMAP, 0U);
        (void)ePDM_SetBitmapToValue(PDM_ID_INTERNAL_NWK_OUT_FC_BITMAP, u32Steps);
        s_u32RestorePresent |= OCBEXP_PRESENT_NWK_OUT_FC;
        return OCBEXP_FIELD_APPLIED;
    }

    case OCBEXP_FIELD_PAN_ID:
        if (u16FieldLen != 2U) { return OCBEXP_FIELD_BAD_LENGTH; }
        ZPS_vNwkNibSetPanId(pvNwk, ZNC_RTN_U16(pu8Val, 0));
        s_u32RestorePresent |= OCBEXP_PRESENT_PAN_ID;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_EXT_PAN_ID:
    {
        uint64 u64Ext;
        if (u16FieldLen != 8U) { return OCBEXP_FIELD_BAD_LENGTH; }
        u64Ext = ZNC_RTN_U64(pu8Val, 0);
        ZPS_vNwkNibSetExtPanId(pvNwk, u64Ext);
        (void)ZPS_eAplAibSetApsUseExtendedPanId(u64Ext);
        s_u32RestorePresent |= OCBEXP_PRESENT_EXT_PAN_ID;
        return OCBEXP_FIELD_APPLIED;
    }

    case OCBEXP_FIELD_CHANNEL:
        if (u16FieldLen != 1U) { return OCBEXP_FIELD_BAD_LENGTH; }
        ZPS_vNwkNibSetChannel(pvNwk, pu8Val[0]);
        s_u32RestorePresent |= OCBEXP_PRESENT_CHANNEL;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_NWK_ADDR:
        if (u16FieldLen != 2U) { return OCBEXP_FIELD_BAD_LENGTH; }
        ZPS_vNwkNibSetNwkAddr(pvNwk, ZNC_RTN_U16(pu8Val, 0));
        s_u32RestorePresent |= OCBEXP_PRESENT_NWK_ADDR;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_NWK_UPDATE_ID:
        if (u16FieldLen != 1U) { return OCBEXP_FIELD_BAD_LENGTH; }
        ZPS_vNwkNibSetUpdateId(pvNwk, pu8Val[0]);
        s_u32RestorePresent |= OCBEXP_PRESENT_NWK_UPDATE_ID;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_TC_ADDR:
        if (u16FieldLen != 8U) { return OCBEXP_FIELD_BAD_LENGTH; }
        psAib->u64ApsTrustCenterAddress = ZNC_RTN_U64(pu8Val, 0);
        s_u32RestorePresent |= OCBEXP_PRESENT_TC_ADDR;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_TC_LINK_KEY:
        if (u16FieldLen != 16U) { return OCBEXP_FIELD_BAD_LENGTH; }
        memcpy(psAib->psAplDefaultTCAPSLinkKey->au8LinkKey, pu8Val, 16U);
        s_u32RestorePresent |= OCBEXP_PRESENT_TC_LINK_KEY;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_TC_KEY_TYPE:
        if (u16FieldLen != 1U) { return OCBEXP_FIELD_BAD_LENGTH; }
        psAib->u8KeyType = pu8Val[0];
        s_u32RestorePresent |= OCBEXP_PRESENT_TC_KEY_TYPE;
        return OCBEXP_FIELD_APPLIED;

    case OCBEXP_FIELD_ADOPT_IEEE:
        if (u16FieldLen != 8U) { return OCBEXP_FIELD_BAD_LENGTH; }
        /* Staged; persisted at COMMIT and applied by the boot hook -- see
         * OCBEXP_vApplyAdoptedIeeeAtBoot() for this port's verification
         * status and the boot-hook placement rationale. */
        s_u64AdoptIeee = ZNC_RTN_U64(pu8Val, 0);
        s_bAdoptIeeeStaged = TRUE;
        s_u32RestorePresent |= OCBEXP_PRESENT_ADOPT_IEEE;
        return OCBEXP_FIELD_APPLIED;

    default:
        return OCBEXP_FIELD_SKIPPED_UNKNOWN;
    }
}

PUBLIC void OCBEXP_vHandleRestoreBegin(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint8 u8Length, u8Status;
    if (!bExpParse(E_SL_MSG_OCBEXP_RESTORE_BEGIN_REQ, u16Len, OCBEXP_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    u8Status = u8RestoreGate(u32Transaction, pu8Rx, FALSE);
    if (u8Status == OCBEXP_STATUS_OK)
    {
        s_bRestoreSession = TRUE;
        s_u32RestorePresent = 0U;
        s_bAdoptIeeeStaged = FALSE;
        s_u64AdoptIeee = 0U;
    }
    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCBEXP_RCAP_BITMAP, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCBEXP_LIMIT_BITMAP, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_RESTORE_BEGIN_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleRestoreField(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint16 u16FieldId, u16FieldLen;
    uint8 u8Length, u8Status, u8Result = OCBEXP_FIELD_UNAVAILABLE;
    const uint8 *pu8Val;
    void *pvNwk;
    ZPS_tsNwkNib *psNib;
    ZPS_tsAplAib *psAib;

    if (u16Len < OCBEXP_RESTORE_FIELD_MIN_LEN)
    {
        vOcbSendStatus(E_SL_MSG_OCBEXP_RESTORE_CORE_REQ,
                       E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return;
    }
    u32Transaction = ZNC_RTN_U32(pu8Rx, 2);
    u16FieldId  = ZNC_RTN_U16(pu8Rx, 6);
    u16FieldLen = ZNC_RTN_U16(pu8Rx, 8);
    if ((uint32)u16Len != (uint32)OCBEXP_RESTORE_FIELD_MIN_LEN + u16FieldLen)
    {
        vOcbSendStatus(E_SL_MSG_OCBEXP_RESTORE_CORE_REQ,
                       E_SL_MSG_STATUS_INCORRECT_PARAMETERS);
        return;
    }
    vOcbSendStatus(E_SL_MSG_OCBEXP_RESTORE_CORE_REQ, E_SL_MSG_STATUS_SUCCESS);
    pu8Val = &pu8Rx[OCBEXP_RESTORE_FIELD_MIN_LEN];

    u8Status = u8RestoreGate(u32Transaction, pu8Rx, TRUE);
    if (u8Status == OCBEXP_STATUS_OK)
    {
        pvNwk = ZPS_pvAplZdoGetNwkHandle();
        psNib = ZPS_psNwkNibGetHandle(pvNwk);
        psAib = ZPS_psAplAibGetAib();
        if (!bExpLayoutValid(psNib, psAib))
        {
            u8Result = OCBEXP_FIELD_UNAVAILABLE;
        }
        else
        {
            u8Result = u8RestoreApplyField(u16FieldId, u16FieldLen, pu8Val,
                                           pvNwk, psNib, psAib);
        }
    }

    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U16_UPD(&s_au8OcbTx[u8Length], u16FieldId, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8Result, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_RESTORE_CORE_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleRestoreLink(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint64 u64Eui;
    uint8 u8Length, u8Status, u8KeyType, u8Result = OCBEXP_FIELD_UNAVAILABLE;
    uint8 au8Key[16];

    if (!bExpParse(E_SL_MSG_OCBEXP_RESTORE_LINK_REQ, u16Len,
                   OCBEXP_RESTORE_LINK_REQ_LEN, pu8Rx, &u32Transaction))
    {
        return;
    }
    u64Eui    = ZNC_RTN_U64(pu8Rx, 6);
    u8KeyType = pu8Rx[14];
    memcpy(au8Key, &pu8Rx[15], 16U);

    u8Status = u8RestoreGate(u32Transaction, pu8Rx, TRUE);
    if (u8Status == OCBEXP_STATUS_OK)
    {
        if (u64Eui == 0U || u64Eui == 0xFFFFFFFFFFFFFFFFULL)
        {
            u8Result = OCBEXP_FIELD_BAD_LENGTH;   /* invalid EUI64 */
        }
        /* ZPS_teStatus success == 0. Adds/replaces the descriptor keyed by
         * EUI, routing to the flash TCLK store as needed. Unlike
         * zigate-jn5169-firmware, this SDK has no
         * ZPS_eAplAibSetDeviceApsKeyType() to also record u8KeyType per
         * device -- there is no such field on this SDK's
         * ZPS_tsAplApsKeyDescriptorEntry (see the layout note above). The key
         * bytes themselves restore exactly; only the requested key-type
         * tagging is not separately tracked per device on this port. */
        else if (ZPS_eAplZdoAddReplaceLinkKey(u64Eui, au8Key,
                     (ZPS_teApsLinkKeyType)u8KeyType) == 0U)
        {
            s_u32RestorePresent |= OCBEXP_PRESENT_LINK_KEY;
            u8Result = OCBEXP_FIELD_APPLIED;
        }
        else
        {
            u8Result = OCBEXP_FIELD_UNAVAILABLE;
        }
    }

    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U64_UPD(&s_au8OcbTx[u8Length], u64Eui, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8Result, u8Length);
    /* APS frame counter is never restored (no flash-TCLK counter API on this
     * SDK either); it re-syncs on the next APS exchange. Flag unconditionally. */
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], 1U, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_RESTORE_LINK_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(au8Key, sizeof(au8Key));
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleValidate(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint8 u8Length, u8Status, u8MandatoryOk;
    if (!bExpParse(E_SL_MSG_OCBEXP_VALIDATE_REQ, u16Len, OCBEXP_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    u8Status = u8RestoreGate(u32Transaction, pu8Rx, TRUE);
    u8MandatoryOk = (u8Status == OCBEXP_STATUS_OK &&
                     (s_u32RestorePresent & OCBEXP_PRESENT_MANDATORY) ==
                         OCBEXP_PRESENT_MANDATORY) ? 1U : 0U;
    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], s_u32RestorePresent, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8MandatoryOk, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_VALIDATE_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleCommit(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction, u32Present;
    uint8 u8Length, u8Status;
    if (!bExpParse(E_SL_MSG_OCBEXP_COMMIT_REQ, u16Len, OCBEXP_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    u8Status = u8RestoreGate(u32Transaction, pu8Rx, TRUE);
    if (u8Status == OCBEXP_STATUS_OK &&
        (s_u32RestorePresent & OCBEXP_PRESENT_MANDATORY) !=
            OCBEXP_PRESENT_MANDATORY)
    {
        u8Status = OCBEXP_STATUS_INCOMPLETE;
    }
    u32Present = s_u32RestorePresent;

    if (u8Status == OCBEXP_STATUS_OK)
    {
        /* Opt-in adopted coordinator IEEE: persisted here, applied at the
         * next cold boot by OCBEXP_vApplyAdoptedIeeeAtBoot(). */
        if (s_bAdoptIeeeStaged)
        {
            PDM_eSaveRecordData(PDM_ID_APP_OCB_ADOPT_IEEE, &s_u64AdoptIeee,
                                sizeof(s_u64AdoptIeee));
        }
        /* Boot formed on the restored network. */
        sZllState.eState       = NOT_FACTORY_NEW;
        sZllState.eNodeState   = E_RUNNING;
        sZllState.u8DeviceType = 0U;      /* coordinator */
        sZllState.u16MyAddr    = 0x0000U;
        PDM_eSaveRecordData(PDM_ID_APP_ZLL_CMSSION, &sZllState,
                            sizeof(sZllState));
        /* Serialise NIB / AIB / key material / tables to PDM. */
        ZPS_vSaveAllZpsRecords();
    }

    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], u32Present, u8Length);
    /* Reply BEFORE arming the reboot so the host receives the result. */
    vSL_WriteMessage(E_SL_MSG_OCBEXP_COMMIT_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));

    if (u8Status == OCBEXP_STATUS_OK)
    {
        vExpLock();
        bResetIssued = TRUE;
        ZTIMER_eStart(u8IdTimer, ZTIMER_TIME_MSEC(1));
    }
}

/* Coordinator IEEE adoption boot hook.
 *
 * zigate-jn5169-firmware's SDK reliably hung boot when
 * ZPS_vSetOverrideLocalIeeeAddr() was called before ZPS_eAplAfInit(): its
 * callee chain synchronously reached a hardware MAC register write
 * (vMMAC_SetRxAddress) before the radio was clocked. That repo's fix moved
 * the call to run after ZPS_eAplAfInit() in every boot branch.
 *
 * This repo's SDK is a genuinely different, older vendor build (see the
 * top-of-file/header note). Independently re-derived via disassembly of THIS
 * repo's own libZPSNWK_JN516x.a and libZPSMAC_Mini_SOC_JN516x.a (not assumed
 * to match): here ZPS_vSetOverrideLocalIeeeAddr() -> vAppApiSetMacAddrLocation()
 * is a 2-hop chain that only copies the 8-byte IEEE value into a plain .bss
 * RAM global (sThisDeviceMacAddr) and stores the caller's pointer -- NO
 * hardware/MMIO write is reachable in that chain at all, so the specific
 * boot-hang hazard found in the other repo does not reproduce here as far as
 * static analysis can show.
 *
 * UNVERIFIED REMAINDER: sThisDeviceMacAddr is also referenced from the
 * MiniMac library, meaning something reads it later (plausibly during radio
 * bring-up) -- that consumer was not traced. It is plausible this call must
 * run BEFORE that consumer reads it (i.e. before or during ZPS_eAplAfInit(),
 * not after) for the override to actually take effect, even though nothing
 * found so far suggests calling it too early would hang the device the way
 * the other repo's SDK did. The call site below matches the other repo's
 * placement (after ZPS_eAplAfInit(), in app_start.c) as a starting point
 * because it is a known-safe boot location on this codebase; if HIL testing
 * shows an adopted IEEE staged via RESTORE_FIELD/COMMIT does not actually
 * take effect after reboot, move this call to before ZPS_eAplAfInit() instead
 * and re-test -- prefer "no effect" (silently wrong identity, caught by the
 * HIL JSON diff) over "hangs boot" as the failure mode to plan around here,
 * since disassembly found no hang-inducing hardware write on this SDK at
 * all. HIL-retest before trusting either placement. */
PUBLIC void OCBEXP_vApplyAdoptedIeeeAtBoot(void)
{
    uint64 u64Ieee = 0U;
    uint16 u16Read = 0U;
    (void)PDM_eReadDataFromRecord(PDM_ID_APP_OCB_ADOPT_IEEE, &u64Ieee,
                                  sizeof(u64Ieee), &u16Read);
    if (u16Read == sizeof(u64Ieee) &&
        u64Ieee != 0U && u64Ieee != 0xFFFFFFFFFFFFFFFFULL)
    {
        /* ZPS keeps the pointer, so the value must live for the whole program. */
        s_u64OverrideIeee = u64Ieee;
        ZPS_vSetOverrideLocalIeeeAddr(&s_u64OverrideIeee);
    }
}

PUBLIC void OCBEXP_vHandleStatus(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint8 u8Length, u8Unlocked, u8Remaining;
    if (!bExpParse(E_SL_MSG_OCBEXP_STATUS_REQ, u16Len, OCBEXP_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    u8Remaining = u8ExpRemainingSeconds(u32Transaction);
    u8Unlocked = (u8Remaining != 0U) ? 1U : 0U;
    u8Length = u8ExpPrefix(u32Transaction,
                           bExpVersion(pu8Rx) ? OCBEXP_STATUS_OK :
                                               OCBEXP_STATUS_BAD_VERSION);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length], u8Unlocked, u8Length);
    ZNC_BUF_U8_UPD(&s_au8OcbTx[u8Length],
                   u8Remaining, u8Length);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCBEXP_LIMIT_BITMAP, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_STATUS_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

PUBLIC void OCBEXP_vHandleAbort(uint16 u16Len, const uint8 *pu8Rx)
{
    uint32 u32Transaction;
    uint8 u8Length, u8Status;
    if (!bExpParse(E_SL_MSG_OCBEXP_ABORT_REQ, u16Len, OCBEXP_REQ_LEN,
                   pu8Rx, &u32Transaction))
    {
        return;
    }
    u8Status = bExpVersion(pu8Rx) ? OCBEXP_STATUS_OK :
                                    OCBEXP_STATUS_BAD_VERSION;
    vExpLock();
    u8Length = u8ExpPrefix(u32Transaction, u8Status);
    ZNC_BUF_U32_UPD(&s_au8OcbTx[u8Length], OCBEXP_LIMIT_BITMAP, u8Length);
    vSL_WriteMessage(E_SL_MSG_OCBEXP_ABORT_RSP, u8Length, s_au8OcbTx, 0);
    vExpWipe(s_au8OcbTx, sizeof(s_au8OcbTx));
}

#endif /* OCB_KEY_EXPORT_RESTORE_EXPERIMENTAL */
