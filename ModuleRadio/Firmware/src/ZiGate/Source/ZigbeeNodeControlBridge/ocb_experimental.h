/****************************************************************************
 *
 * Open Coordinator Backup (OCB) export/restore, self-contained.
 *
 * Ported from zigate-jn5169-firmware's ocb_experimental.c/custom_diag.c OCB
 * sections onto this repository's (openlumi/ZiGate) older vendor SDK, which
 * has no custom_diag.c at all. Deliberately has NO dependency on that file:
 * everything needed (status echo, TX buffer, OCB helpers) is local to this
 * module. Wire opcodes, field layouts and status codes are unchanged from
 * the source repo, so a single host script (scripts/ocb_backup.py /
 * ocb_gw.py) round-trips against either firmware -- that is the actual
 * cross-platform-dump deliverable this port exists for.
 *
 * Two pieces of this port are SDK-specific and were independently
 * re-verified against THIS repo's own libZPSNWK_JN516x.a via disassembly
 * (not assumed to match zigate-jn5169-firmware's newer/different SDK build):
 * the NWK outgoing frame counter's PDM bitmap persistence, and the
 * coordinator-IEEE-adoption boot-ordering requirement. See the comments on
 * OCBEXP_FIELD_NWK_OUT_FC's handler and OCBEXP_vApplyAdoptedIeeeAtBoot() in
 * ocb_experimental.c for the evidence.
 *
 * There is deliberately no embedded secret and no claim of authentication or
 * confidentiality. The short nonce confirmation only prevents accidental
 * invocation by software speaking the wrong protocol.
 *
 ****************************************************************************/
#ifndef OCB_EXPERIMENTAL_H_
#define OCB_EXPERIMENTAL_H_

#include <jendefs.h>

/****************************************************************************/
/***        Typed OCB metadata export (0x0D18..0x0D1C)                    ***/
/***        Always compiled in (OCB_TYPED_SUPPORT), no key material.      ***/
/****************************************************************************/

#define OCB_ABI_VERSION                 (1U)
#define OCB_SCHEMA_VERSION              (1U)
#define E_SL_MSG_OCB_EXPORT_BEGIN_REQ   (0x0D18U)
#define E_SL_MSG_OCB_EXPORT_BEGIN_RSP   (0x8D18U)
#define E_SL_MSG_OCB_EXPORT_CORE_REQ    (0x0D19U)
#define E_SL_MSG_OCB_EXPORT_CORE_RSP    (0x8D19U)
#define E_SL_MSG_OCB_EXPORT_LINK_KEY_REQ (0x0D1AU)
#define E_SL_MSG_OCB_EXPORT_LINK_KEY_RSP (0x8D1AU)
#define E_SL_MSG_OCB_EXPORT_END_REQ     (0x0D1BU)
#define E_SL_MSG_OCB_EXPORT_END_RSP     (0x8D1BU)
#define E_SL_MSG_OCB_STATUS_REQ         (0x0D1CU)
#define E_SL_MSG_OCB_STATUS_RSP         (0x8D1CU)
#define OCB_COMMON_REQ_LEN              (10U)
#define OCB_BEGIN_REQ_LEN               (6U)
#define OCB_LINK_REQ_LEN                (18U)
#define OCB_BEGIN_RSP_LEN               (19U)
#define OCB_CORE_RSP_LEN                (55U)
#define OCB_LINK_RSP_LEN                (24U)
#define OCB_END_RSP_LEN                 (16U)
#define OCB_STATUS_RSP_LEN              (20U)

#define OCB_STATUS_OK                   (0U)
#define OCB_STATUS_BAD_VERSION          (1U)
#define OCB_STATUS_BAD_LENGTH           (2U) /* reserved; outer status handles malformed length */
#define OCB_STATUS_NO_SESSION           (3U)
#define OCB_STATUS_SESSION_MISMATCH     (4U)
#define OCB_STATUS_FIELD_UNAVAILABLE    (5U)
#define OCB_STATUS_BUSY                 (6U)

/* Capability bits are deliberately narrower than BackupCapable. */
#define OCB_CAP_EXPORT_CORE             (1UL << 0)
#define OCB_CAP_STATUS_DIGEST           (1UL << 1)
#define OCB_CAP_LINK_KEYS               (1UL << 2) /* always clear */
#define OCB_CAP_RESTORE                 (1UL << 3) /* always clear */
#define OCB_CAP_PHYSICAL_UNLOCK         (1UL << 4) /* always clear */
#define OCB_CAP_BITMAP                  (OCB_CAP_EXPORT_CORE | OCB_CAP_STATUS_DIGEST)

/* Per-field validity bits in BEGIN/CORE/STATUS. A clear bit means
 * unavailable, never a synthesised default. */
#define OCB_FIELD_COORD_IEEE            (1UL << 0)
#define OCB_FIELD_PAN_ID                (1UL << 1)
#define OCB_FIELD_EXT_PAN_ID            (1UL << 2)
#define OCB_FIELD_CHANNEL               (1UL << 3)
#define OCB_FIELD_CHANNEL_MASK          (1UL << 4)
#define OCB_FIELD_NWK_UPDATE_ID         (1UL << 5)
#define OCB_FIELD_SECURITY_LEVEL        (1UL << 6)
#define OCB_FIELD_NWK_KEY_SEQUENCE      (1UL << 7)
#define OCB_FIELD_NWK_OUT_COUNTER       (1UL << 8)
#define OCB_FIELD_APS_TC_ADDRESS        (1UL << 9)
#define OCB_FIELD_APS_STATE             (1UL << 10)
#define OCB_FIELD_NETWORK_KEY           (1UL << 16) /* always clear */
#define OCB_FIELD_LINK_KEYS             (1UL << 17) /* always clear */
#define OCB_FIELD_APS_COUNTERS          (1UL << 18) /* always clear */

PUBLIC void OCB_vHandleExportBegin(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCB_vHandleExportCore(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCB_vHandleExportLinkKey(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCB_vHandleExportEnd(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCB_vHandleStatus(uint16 u16Len, const uint8 *pu8Rx);

/****************************************************************************/
/***        Experimental key export/restore (0x0D20..0x0D2A)              ***/
/***        Default-off (OCB_KEY_EXPORT_RESTORE_EXPERIMENTAL).            ***/
/****************************************************************************/

#define OCBEXP_ABI_VERSION                 (1U)
#define OCBEXP_SCHEMA_VERSION              (1U)

#define E_SL_MSG_OCBEXP_CHALLENGE_REQ      (0x0D20U)
#define E_SL_MSG_OCBEXP_CHALLENGE_RSP      (0x8D20U)
#define E_SL_MSG_OCBEXP_UNLOCK_REQ         (0x0D21U)
#define E_SL_MSG_OCBEXP_UNLOCK_RSP         (0x8D21U)
#define E_SL_MSG_OCBEXP_SECRET_CORE_REQ    (0x0D22U)
#define E_SL_MSG_OCBEXP_SECRET_CORE_RSP    (0x8D22U)
#define E_SL_MSG_OCBEXP_LINK_KEY_REQ       (0x0D23U)
#define E_SL_MSG_OCBEXP_LINK_KEY_RSP       (0x8D23U)
#define E_SL_MSG_OCBEXP_RESTORE_BEGIN_REQ  (0x0D24U)
#define E_SL_MSG_OCBEXP_RESTORE_BEGIN_RSP  (0x8D24U)
#define E_SL_MSG_OCBEXP_RESTORE_CORE_REQ   (0x0D25U)
#define E_SL_MSG_OCBEXP_RESTORE_CORE_RSP   (0x8D25U)
#define E_SL_MSG_OCBEXP_RESTORE_LINK_REQ   (0x0D26U)
#define E_SL_MSG_OCBEXP_RESTORE_LINK_RSP   (0x8D26U)
#define E_SL_MSG_OCBEXP_VALIDATE_REQ       (0x0D27U)
#define E_SL_MSG_OCBEXP_VALIDATE_RSP       (0x8D27U)
#define E_SL_MSG_OCBEXP_COMMIT_REQ         (0x0D28U)
#define E_SL_MSG_OCBEXP_COMMIT_RSP         (0x8D28U)
#define E_SL_MSG_OCBEXP_STATUS_REQ         (0x0D29U)
#define E_SL_MSG_OCBEXP_STATUS_RSP         (0x8D29U)
#define E_SL_MSG_OCBEXP_ABORT_REQ          (0x0D2AU)
#define E_SL_MSG_OCBEXP_ABORT_RSP          (0x8D2AU)

#define OCBEXP_REQ_LEN                     (6U)
#define OCBEXP_UNLOCK_REQ_LEN              (14U)
#define OCBEXP_LINK_REQ_LEN                (8U)
#define OCBEXP_CHALLENGE_RSP_LEN           (16U)
#define OCBEXP_UNLOCK_RSP_LEN              (12U)
#define OCBEXP_SECRET_CORE_RSP_LEN         (61U)
#define OCBEXP_LINK_RSP_LEN                (46U)
#define OCBEXP_STATUS_RSP_LEN              (13U)

#define OCBEXP_STATUS_OK                   (0U)
#define OCBEXP_STATUS_BAD_VERSION          (1U)
#define OCBEXP_STATUS_LOCKED               (2U)
#define OCBEXP_STATUS_NOT_FOUND            (3U)
#define OCBEXP_STATUS_LAYOUT_MISMATCH      (4U)
#define OCBEXP_STATUS_NO_SESSION           (5U)  /* restore op with no RESTORE_BEGIN */
#define OCBEXP_STATUS_INCOMPLETE           (6U)  /* VALIDATE/COMMIT before mandatory fields present */
#define OCBEXP_STATUS_BAD_FIELD            (7U)  /* recognised field id with a wrong value length */

/* No secret: host confirms deliberate use with
 * nonce XOR transaction_id XOR OCBEXP_CONFIRM_MAGIC. */
#define OCBEXP_CONFIRM_MAGIC               (0x4F434221UL) /* "OCB!" */
#define OCBEXP_UNLOCK_SECONDS              (30U)
/* The unlock deadline is a dedicated ZTimer (u8OcbUnlockTimer, opened in
 * app_start.c), NOT raw tick-timer arithmetic -- see zigate-jn5169-firmware's
 * equivalent comment/fix history; ZTimer.c reprograms the same AHI hardware
 * Tick Timer into its own periodic tick source, so a raw elapsed computation
 * would alias. */

#define OCBEXP_AVAIL_NWK_KEY               (1UL << 0)
#define OCBEXP_AVAIL_NWK_OUT_COUNTER       (1UL << 1)
#define OCBEXP_AVAIL_TC_LINK_KEY           (1UL << 2)
#define OCBEXP_AVAIL_APS_OUT_COUNTER       (1UL << 3)
#define OCBEXP_AVAIL_APS_IN_COUNTER        (1UL << 4)
#define OCBEXP_AVAIL_EUI                   (1UL << 5)

#define OCBEXP_KEY_KIND_DEFAULT_TC         (0U)
#define OCBEXP_KEY_KIND_APS_TABLE          (1U)
#define OCBEXP_KEY_KIND_FLASH_TCLK         (2U)

/* Precise blockers to production Backup/Restore capability. */
#define OCBEXP_LIMIT_NO_AUTH_OR_ENCRYPTION (1UL << 0)
#define OCBEXP_LIMIT_FLASH_TCLK_COUNTERS   (1UL << 1)
#define OCBEXP_LIMIT_NO_ATOMIC_ROLLBACK    (1UL << 2)
#define OCBEXP_LIMIT_RESTORE_UNQUALIFIED   (1UL << 3)
/* Coordinator IEEE adoption: on zigate-jn5169-firmware's SDK,
 * ZPS_vSetOverrideLocalIeeeAddr() reliably hung boot when called before
 * ZPS_eAplAfInit() (hardware MAC register write reached before the radio was
 * clocked). This repo's SDK is a genuinely different vendor build (see the
 * top-of-file note); re-verify the same call chain there before trusting this
 * on this port -- see the comment on OCBEXP_vApplyAdoptedIeeeAtBoot() below
 * for the current evidence and confidence level for THIS SDK. Until that is
 * HIL-confirmed on this port, treat this bit as "unsafe / unverified", not
 * merely a standing caution. Independent of firmware correctness, running two
 * units with the same adopted IEEE on one network is unsafe by construction. */
#define OCBEXP_LIMIT_IEEE_OVERRIDE_UNSAFE  (1UL << 4)
/* bit 5: NWK outgoing frame counter persistence. Re-derived by disassembling
 * THIS repo's own libZPSNWK_JN516x.a (not assumed from the other repo): same
 * PDM_ID_INTERNAL_NWK_OUT_FC_BITMAP (0xf106) bitmap-popcount mechanism, same
 * role for g_u32NwkFcSaveCountBitShift (here a plain linkable extern const,
 * not a function -- see zps_nwk_sec.h). See the field handler in
 * ocb_experimental.c for the fix and the disassembly evidence. Bit stays
 * clear: the counter IS restorable here too. */
#define OCBEXP_LIMIT_BITMAP                \
    (OCBEXP_LIMIT_NO_AUTH_OR_ENCRYPTION | OCBEXP_LIMIT_FLASH_TCLK_COUNTERS | \
     OCBEXP_LIMIT_NO_ATOMIC_ROLLBACK | OCBEXP_LIMIT_RESTORE_UNQUALIFIED | \
     OCBEXP_LIMIT_IEEE_OVERRIDE_UNSAFE)

/* --- Experimental streamed restore (0x0D24..0x0D28) -------------------------
 *
 * The host must CHALLENGE/UNLOCK first, exactly as for key export. Restore is a
 * field-tagged (TLV) stream so an image built by a different firmware/PDM
 * revision skips unknown field ids instead of corrupting layout:
 *
 *   RESTORE_BEGIN  (0x0D24) start a session and report restore capabilities.
 *   RESTORE_FIELD  (0x0D25) repeatable: {field_id:u16, length:u16, value[]}.
 *                          Unknown field ids are acknowledged as SKIPPED.
 *   RESTORE_LINK   (0x0D26) repeatable: one per-device link key.
 *   VALIDATE       (0x0D27) no new writes; report present-bitmap + mandatory_ok.
 *   COMMIT         (0x0D28) persist (ZPS_vSaveAllZpsRecords) and reboot.
 *
 * Fields are applied straight into the live NIB/AIB as they arrive; nothing is
 * persisted until COMMIT. ABORT (or any power cycle before COMMIT) discards the
 * in-RAM changes. There is no atomic rollback across COMMIT: keep the unit
 * powered throughout it. */

#define OCBEXP_FIELD_HDR_LEN               (4U)   /* field_id:u16 + length:u16 */
#define OCBEXP_RESTORE_FIELD_MIN_LEN       (OCBEXP_REQ_LEN + OCBEXP_FIELD_HDR_LEN) /* 10 */
#define OCBEXP_RESTORE_LINK_REQ_LEN        (31U)  /* common6 + eui8 + type1 + key16 */

/* Replay-protection headroom added to the restored NWK outgoing frame counter so
 * a re-formed coordinator never emits a frame counter a peer already accepted. */
#define OCBEXP_NWK_OUTFC_MARGIN            (0x400UL)

/* PDM_ID_INTERNAL_NWK_OUT_FC_BITMAP's persisted value is a popcount written
 * directly via ePDM_SetBitmapToValue() (see OCBEXP_FIELD_NWK_OUT_FC in
 * ocb_experimental.c) -- O(1) regardless of magnitude, so no step cap. */

/* Restore field ids (u16, big-endian on the wire). Unchanged from
 * zigate-jn5169-firmware -- this is pure wire protocol. */
#define OCBEXP_FIELD_NWK_KEY               (0x0001U) /* 16 bytes */
#define OCBEXP_FIELD_NWK_KEY_SEQ           (0x0002U) /* 1 byte  */
#define OCBEXP_FIELD_NWK_OUT_FC            (0x0003U) /* 4 bytes */
#define OCBEXP_FIELD_PAN_ID                (0x0004U) /* 2 bytes */
#define OCBEXP_FIELD_EXT_PAN_ID            (0x0005U) /* 8 bytes */
#define OCBEXP_FIELD_CHANNEL               (0x0006U) /* 1 byte  */
#define OCBEXP_FIELD_NWK_ADDR              (0x0007U) /* 2 bytes */
#define OCBEXP_FIELD_NWK_UPDATE_ID         (0x0008U) /* 1 byte  */
#define OCBEXP_FIELD_TC_ADDR               (0x0009U) /* 8 bytes */
#define OCBEXP_FIELD_TC_LINK_KEY           (0x000AU) /* 16 bytes */
#define OCBEXP_FIELD_TC_KEY_TYPE           (0x000BU) /* 1 byte  */
/* 8 bytes; applied at boot by OCBEXP_vApplyAdoptedIeeeAtBoot() -- see that
 * function for this port's current verification status on this SDK. */
#define OCBEXP_FIELD_ADOPT_IEEE            (0x000CU)

/* Per-field apply result reported in the RESTORE_FIELD/RESTORE_LINK response. */
#define OCBEXP_FIELD_APPLIED               (0U)
#define OCBEXP_FIELD_SKIPPED_UNKNOWN       (1U)
#define OCBEXP_FIELD_BAD_LENGTH            (2U)
#define OCBEXP_FIELD_UNAVAILABLE           (3U) /* recognised, but layout blocked apply */

/* Present-bitmap tracked across the session (returned by VALIDATE). */
#define OCBEXP_PRESENT_NWK_KEY             (1UL << 0)
#define OCBEXP_PRESENT_NWK_KEY_SEQ         (1UL << 1)
#define OCBEXP_PRESENT_NWK_OUT_FC          (1UL << 2)
#define OCBEXP_PRESENT_PAN_ID              (1UL << 3)
#define OCBEXP_PRESENT_EXT_PAN_ID          (1UL << 4)
#define OCBEXP_PRESENT_CHANNEL             (1UL << 5)
#define OCBEXP_PRESENT_NWK_ADDR            (1UL << 6)
#define OCBEXP_PRESENT_NWK_UPDATE_ID       (1UL << 7)
#define OCBEXP_PRESENT_TC_ADDR             (1UL << 8)
#define OCBEXP_PRESENT_TC_LINK_KEY         (1UL << 9)
#define OCBEXP_PRESENT_TC_KEY_TYPE         (1UL << 10)
#define OCBEXP_PRESENT_ADOPT_IEEE          (1UL << 11)
#define OCBEXP_PRESENT_LINK_KEY            (1UL << 12) /* at least one RESTORE_LINK applied */

/* Minimum set required before VALIDATE/COMMIT will proceed. */
#define OCBEXP_PRESENT_MANDATORY \
    (OCBEXP_PRESENT_NWK_KEY | OCBEXP_PRESENT_NWK_KEY_SEQ | OCBEXP_PRESENT_PAN_ID | \
     OCBEXP_PRESENT_EXT_PAN_ID | OCBEXP_PRESENT_CHANNEL | OCBEXP_PRESENT_NWK_ADDR)

/* Restore capabilities advertised in the RESTORE_BEGIN response (distinct from
 * the export OCBEXP_LIMIT_* bitmap). */
#define OCBEXP_RCAP_NWK_KEY                (1UL << 0)
#define OCBEXP_RCAP_IDENTITY               (1UL << 1)
#define OCBEXP_RCAP_LINK_KEYS              (1UL << 2)
#define OCBEXP_RCAP_IEEE_ADOPT             (1UL << 3)
#define OCBEXP_RCAP_BITMAP \
    (OCBEXP_RCAP_NWK_KEY | OCBEXP_RCAP_IDENTITY | OCBEXP_RCAP_LINK_KEYS | \
     OCBEXP_RCAP_IEEE_ADOPT)

PUBLIC void OCBEXP_vHandleChallenge(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleUnlock(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleSecretCore(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleLinkKey(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleRestoreBegin(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleRestoreField(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleRestoreLink(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleValidate(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleCommit(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleStatus(uint16 u16Len, const uint8 *pu8Rx);
PUBLIC void OCBEXP_vHandleAbort(uint16 u16Len, const uint8 *pu8Rx);
/* Applied at boot (app_start.c) after ZPS_eAplAfInit() when a prior restore
 * staged an adopted coordinator IEEE. No-op if none is staged. */
PUBLIC void OCBEXP_vApplyAdoptedIeeeAtBoot(void);
/* ZTimer callback (app_start.c opens u8OcbUnlockTimer against this) firing
 * OCBEXP_UNLOCK_SECONDS after the last CHALLENGE/UNLOCK; ends the unlock. */
PUBLIC void OCBEXP_vUnlockTimeout(void *pvParam);

#endif /* OCB_EXPERIMENTAL_H_ */
