/*
  Copyright (c) 2019-23 John MacCallum Permission is hereby
  granted, free of charge, to any person obtaining a copy of this
  software and associated documentation files (the "Software"), to
  deal in the Software without restriction, including without
  limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and
  to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
  OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.
*/

#include <string.h>
#include "ose_conf.h"
#include "libose/ose.h"
#include "libose/ose_context.h"
#include "libose/ose_util.h"
#include "libose/ose_stackops.h"
#include "libose/ose_assert.h"
#include "libose/ose_vm.h"
#include "libose/osevm_lib.h"
#include "libose/ose_errno.h"

#define OSE_STDLIB_ADDR_ASSIGN "/_l/ASN"
#define OSE_STDLIB_ADDR_ASSIGNSTACKTOENV "/_l/ASE"
#define OSE_STDLIB_ADDR_ASSIGNSTACKTOREGISTER "/_l/ASR"
#define OSE_STDLIB_ADDR_REPLACE "/_l/RPL"

#define OSE_STDLIB_ADDR_ADD "/_l/ADD"
#define OSE_STDLIB_ADDR_AND "/_l/AND"
#define OSE_STDLIB_ADDR_DIV "/_l/DIV"
#define OSE_STDLIB_ADDR_EQL "/_l/EQL"
#define OSE_STDLIB_ADDR_LT "/_l/LTX"
#define OSE_STDLIB_ADDR_LTE "/_l/LTE"
#define OSE_STDLIB_ADDR_MOD "/_l/MOD"
#define OSE_STDLIB_ADDR_MUL "/_l/MUL"
#define OSE_STDLIB_ADDR_NEG "/_l/NEG"
#define OSE_STDLIB_ADDR_NEQ "/_l/NEQ"
#define OSE_STDLIB_ADDR_OR "/_l/ORX"
#define OSE_STDLIB_ADDR_POW "/_l/POW"
#define OSE_STDLIB_ADDR_SUB "/_l/SUB"

#define OSE_STDLIB_ADDR_ELEMTOBLOB "/_l/2BE"
#define OSE_STDLIB_ADDR_ITEMTOBLOB "/_l/2BI"
#define OSE_STDLIB_ADDR_BLOBTOELEM "/_l/2EB"
#define OSE_STDLIB_ADDR_TOFLOAT "/_l/2FL"
#define OSE_STDLIB_ADDR_TOINT32 "/_l/2I4"
#define OSE_STDLIB_ADDR_TOSTRING "/_l/2ST"
#define OSE_STDLIB_ADDR_TOTYPE "/_l/2TY"

#define OSE_STDLIB_ADDR_DOTIMES "/_l/DOX"
#define OSE_STDLIB_ADDR_IF "/_l/IFX"
#define OSE_STDLIB_ADDR_RETURN "/_l/RET"

#define OSE_STDLIB_ADDR_APPENDBYTE "/_l/ABY"
#define OSE_STDLIB_ADDR_CONCATENATEBLOBS "/_l/CCB"
#define OSE_STDLIB_ADDR_CONCATENATEELEMS "/_l/CCE"
#define OSE_STDLIB_ADDR_CONCATENATESTRINGS "/_l/CCS"
#define OSE_STDLIB_ADDR_DECATENATEBLOBFROMEND "/_l/DBE"
#define OSE_STDLIB_ADDR_DECATENATEBLOBFROMSTART "/_l/DBS"
#define OSE_STDLIB_ADDR_DECATENATEELEMFROMEND "/_l/DEE"
#define OSE_STDLIB_ADDR_DECATENATEELEMFROMSTART "/_l/DES"
#define OSE_STDLIB_ADDR_DECATENATESTRINGFROMEND "/_l/DSE"
#define OSE_STDLIB_ADDR_DECATENATESTRINGFROMSTART "/_l/DSS"
#define OSE_STDLIB_ADDR_JOINSTRINGS "/_l/JNS"
#define OSE_STDLIB_ADDR_MOVESTRINGTOADDRESS "/_l/MSA"
#define OSE_STDLIB_ADDR_POP "/_l/POP"
#define OSE_STDLIB_ADDR_POPALL "/_l/PAL"
#define OSE_STDLIB_ADDR_POPALLBUNDLE "/_l/PAB"
#define OSE_STDLIB_ADDR_POPALLDROP "/_l/PAD"
#define OSE_STDLIB_ADDR_POPALLDROPBUNDLE "/_l/PDB"
#define OSE_STDLIB_ADDR_PUSH "/_l/PSH"
#define OSE_STDLIB_ADDR_SETTIMETAG "/_l/STI"
#define OSE_STDLIB_ADDR_SPLITSTRINGFROMEND "/_l/SSE"
#define OSE_STDLIB_ADDR_SPLITSTRINGFROMSTART "/_l/SSS"
#define OSE_STDLIB_ADDR_SWAP4BYTES "/_l/SB4"
#define OSE_STDLIB_ADDR_SWAP8BYTES "/_l/SB8"
#define OSE_STDLIB_ADDR_SWAPNBYTES "/_l/SBN"
#define OSE_STDLIB_ADDR_SWAPSTRINGTOADDRESS "/_l/SSA"
#define OSE_STDLIB_ADDR_TRIMSTRINGEND "/_l/TSE"
#define OSE_STDLIB_ADDR_TRIMSTRINGSTART "/_l/TSS"
#define OSE_STDLIB_ADDR_SETTYPETAG "/_l/TTS"
#define OSE_STDLIB_ADDR_UNPACK "/_l/UPK"
#define OSE_STDLIB_ADDR_UNPACKDROP "/_l/UPD"

#define OSE_STDLIB_ADDR_APPLY "/_l/APP"
#define OSE_STDLIB_ADDR_EXEC1 "/_l/EX1"
#define OSE_STDLIB_ADDR_EXEC2 "/_l/EX2"
#define OSE_STDLIB_ADDR_EXEC3 "/_l/EX3"
#define OSE_STDLIB_ADDR_EXEC "/_l/EXE"
#define OSE_STDLIB_ADDR_FUNCALL "/_l/FNC"
#define OSE_STDLIB_ADDR_MAP "/_l/MAP"

#define OSE_STDLIB_ADDR_GATHER "/_l/GAT"
#define OSE_STDLIB_ADDR_LOOKUP "/_l/LUP"
#define OSE_STDLIB_ADDR_LOOKUPINENV "/_l/LUE"
#define OSE_STDLIB_ADDR_MATCH "/_l/MAT"
#define OSE_STDLIB_ADDR_NTH "/_l/NTH"
#define OSE_STDLIB_ADDR_PLOOKUP "/_l/PLU"
#define OSE_STDLIB_ADDR_PLOOKUPINENV "/_l/PLE"
#define OSE_STDLIB_ADDR_PMATCH "/_l/PMT"
#define OSE_STDLIB_ADDR_ROUTE1 "/_l/RT1"
#define OSE_STDLIB_ADDR_ROUTEWITHDELEGATION "/_l/RTA"
#define OSE_STDLIB_ADDR_SELECT1 "/_l/SE1"
#define OSE_STDLIB_ADDR_SELECTWITHDELEGATION "/_l/SEA"

#define OSE_STDLIB_ADDR_VERSION "/_l/VER"

#define OSE_STDLIB_ADDR_COUNTELEMS "/_l/CTE"
#define OSE_STDLIB_ADDR_COUNTITEMS "/_l/CTI"
#define OSE_STDLIB_ADDR_GETADDRESSES "/_l/GAD"
#define OSE_STDLIB_ADDR_GETTIMETAG "/_l/GTI"
#define OSE_STDLIB_ADDR_GETTYPETAGS "/_l/GTY"
#define OSE_STDLIB_ADDR_ISADDRESSCHAR "/_l/QAC"
#define OSE_STDLIB_ADDR_ELEMISBUNDLE "/_l/QBN"
#define OSE_STDLIB_ADDR_ISBOOLTYPE "/_l/QTB"
#define OSE_STDLIB_ADDR_ISFLOATTYPE "/_l/QTF"
#define OSE_STDLIB_ADDR_ISINTEGERTYPE "/_l/QTI"
#define OSE_STDLIB_ADDR_ISKNOWNTYPETAG "/_l/QTK"
#define OSE_STDLIB_ADDR_ISNUMERICTYPE "/_l/QTN"
#define OSE_STDLIB_ADDR_ISSTRINGTYPE "/_l/QTS"
#define OSE_STDLIB_ADDR_ISUNITTYPE "/_l/QTU"
#define OSE_STDLIB_ADDR_LENGTHITEM "/_l/LNI"
#define OSE_STDLIB_ADDR_LENGTHSITEMS "/_l/LSI"
#define OSE_STDLIB_ADDR_SIZEELEM "/_l/SZE"
#define OSE_STDLIB_ADDR_SIZEITEM "/_l/SZI"
#define OSE_STDLIB_ADDR_SIZEPAYLOAD "/_l/SZP"
#define OSE_STDLIB_ADDR_SIZESELEMS "/_l/SXE"
#define OSE_STDLIB_ADDR_SIZESITEMS "/_l/SXI"
#define OSE_STDLIB_ADDR_TYPEOF0 "/_l/TO0"
#define OSE_STDLIB_ADDR_TYPEOF1 "/_l/TO1"
#define OSE_STDLIB_ADDR_TYPEOF2 "/_l/TO2"

#define OSE_STDLIB_ADDR_APPENDELEMTOREGISTER "/_l/AER"
#define OSE_STDLIB_ADDR_COPYELEMTOREGISTER "/_l/CER"
#define OSE_STDLIB_ADDR_COPYREGISTERTOELEM "/_l/CRE"
#define OSE_STDLIB_ADDR_MAKEREGISTER "/_l/MKR"
#define OSE_STDLIB_ADDR_MOVEELEMTOREGISTER "/_l/MER"
#define OSE_STDLIB_ADDR_REPLACEREGISTERWITHELEM "/_l/RRE"

#define OSE_STDLIB_ADDR_2DROP "/_l/2DR"
#define OSE_STDLIB_ADDR_2DUP "/_l/2DU"
#define OSE_STDLIB_ADDR_2OVER "/_l/2OV"
#define OSE_STDLIB_ADDR_2SWAP "/_l/2SW"
#define OSE_STDLIB_ADDR_BUNDLEALL "/_l/BDA"
#define OSE_STDLIB_ADDR_BUNDLEFROMBOTTOM "/_l/BDB"
#define OSE_STDLIB_ADDR_BUNDLEFROMTOP "/_l/BDT"
#define OSE_STDLIB_ADDR_CLEAR "/_l/CLR"
#define OSE_STDLIB_ADDR_DROP "/_l/DRP"
#define OSE_STDLIB_ADDR_DUP "/_l/DUP"
#define OSE_STDLIB_ADDR_MAKEBLOB "/_l/PUB"
#define OSE_STDLIB_ADDR_PUSHBUNDLE "/_l/MKB"
#define OSE_STDLIB_ADDR_NIP "/_l/NIP"
#define OSE_STDLIB_ADDR_OVER "/_l/OVR"
#define OSE_STDLIB_ADDR_PICKBOTTOM "/_l/PKB"
#define OSE_STDLIB_ADDR_PICK "/_l/PKJ"
#define OSE_STDLIB_ADDR_PICKMATCH "/_l/PKM"
#define OSE_STDLIB_ADDR_ROLLBOTTOM "/_l/RLB"
#define OSE_STDLIB_ADDR_ROLL "/_l/RLJ"
#define OSE_STDLIB_ADDR_ROLLMATCH "/_l/RLM"
#define OSE_STDLIB_ADDR_ROT "/_l/ROT"
#define OSE_STDLIB_ADDR_RROT "/_l/RRT"
#define OSE_STDLIB_ADDR_SWAP "/_l/SWP"
#define OSE_STDLIB_ADDR_TUCK "/_l/TUK"

#define OSEVM_ADDR_MOVEELEMTOREGISTER "/_l/PX-"
#define OSEVM_ADDR_TOTYPE "/_l/PX,"
#define OSEVM_ADDR_TOBLOB "/_l/P,b"
#define OSEVM_ADDR_TOFLOAT "/_l/P,f"
#define OSEVM_ADDR_TOINT32 "/_l/P,i"
#define OSEVM_ADDR_TOSTRING "/_l/P,s"
#ifdef OSE_PROVIDE_TYPE_DOUBLE
#define OSEVM_ADDR_TODOUBLE "/_l/P,d"
#define OSE_STDLIB_ADDR_TODOUBLE "/_l/2DL"
#endif
#define OSEVM_ADDR_FUNCALL "/_l/PX!"
#define OSEVM_ADDR_QUOTE "/_l/PX'"
#define OSEVM_ADDR_ASSIGN "/_l/PX@"
#define OSEVM_ADDR_APPENDBYTE "/_l/PX&"
#define OSEVM_ADDR_REPLACEREGISTERWITHELEM "/_l/PX<"
#define OSEVM_ADDR_APPENDELEMTOREGISTER "/_l/P<<"
#define OSEVM_ADDR_COPYREGISTERTOELEM "/_l/PX>"
#define OSEVM_ADDR_LOOKUP "/_l/PX$"

#define ose_stdlib_exec1 osevm_exec1
#define ose_stdlib_exec2 osevm_exec2
#define ose_stdlib_exec3 osevm_exec3
#define ose_stdlib_exec osevm_exec
#define ose_stdlib_if osevm_if
#define ose_stdlib_dotimes osevm_dotimes

#define ose_stdlib_copyRegisterToElem osevm_copyRegisterToElem
#define ose_stdlib_appendElemToRegister osevm_appendElemToRegister
#define ose_stdlib_replaceRegisterWithElem osevm_replaceRegisterWithElem
#define ose_stdlib_moveElemToRegister osevm_moveElemToRegister
#define ose_stdlib_copyElemToRegister osevm_copyElemToRegister
#define ose_stdlib_apply osevm_apply
#define ose_stdlib_map osevm_map
#define ose_stdlib_return osevm_return

#define ose_stdlib_version osevm_version
#define ose_stdlib_assignStackToRegister osevm_assignStackToRegister
#define ose_stdlib_assignStackToEnv osevm_assignStackToEnv
#define ose_stdlib_lookupInEnv osevm_lookupInEnv
#define ose_stdlib_plookupInEnv osevm_plookupInEnv
#define ose_stdlib_funcall osevm_funcall
#define ose_stdlib_makeRegister osevm_makeRegister

#define ose_stdlib_toType osevm_toType
#define ose_stdlib_toInt32 osevm_toInt32
#define ose_stdlib_toFloat osevm_toFloat
#define ose_stdlib_toString osevm_toString
#define ose_stdlib_toBlob osevm_toBlob
#define ose_stdlib_appendByte osevm_appendByte
#define ose_stdlib_toSymbol osevm_toSymbol
#define ose_stdlib_toDouble osevm_toDouble
#define ose_stdlib_toInt8 osevm_toInt8
#define ose_stdlib_toUInt8 osevm_toUInt8
#define ose_stdlib_toInt16 osevm_toInt16
#define ose_stdlib_toUInt16 osevm_toUInt16
#define ose_stdlib_toUInt32 osevm_toUInt32
#define ose_stdlib_toInt64 osevm_toInt64
#define ose_stdlib_toUInt64 osevm_toUInt64
#define ose_stdlib_toTimetag osevm_toTimetag
#define ose_stdlib_toTrue osevm_toTrue
#define ose_stdlib_toFalse osevm_toFalse
#define ose_stdlib_toNull osevm_toNull
#define ose_stdlib_toInfinitum osevm_toInfinitum

#define OSE_STDLIB_DEFN(name)                   \
    void ose_stdlib_##name(ose_bundle bundle)	\
    {                                           \
        ose_bundle vm_s = OSEVM_STACK(bundle);  \
        enum ose_errno e = OSE_ERR_NONE;        \
        ose_##name(vm_s);                       \
        if((e = ose_errno_get(vm_s)))           \
        {                                       \
            ose_errno_set(bundle, e);           \
            ose_errno_set(vm_s, OSE_ERR_NONE);  \
        }                                       \
    }

#define OSE_STDLIB_DEFPRED(name)                \
    void ose_stdlib_##name(ose_bundle bundle)   \
    {                                           \
        ose_bundle vm_s = OSEVM_STACK(bundle);  \
        int32_t i = ose_popInt32(vm_s);         \
        enum ose_errno e = OSE_ERR_NONE;        \
        if((e = ose_errno_get(vm_s)))           \
        {                                       \
            ose_errno_set(bundle, e);           \
            ose_errno_set(vm_s, OSE_ERR_NONE);  \
        }                                       \
        bool r = ose_##name(i);                 \
        ose_pushInt32(vm_s, r == true ? 1 : 0); \
    }

OSE_STDLIB_DEFN(2drop)
OSE_STDLIB_DEFN(2dup)
OSE_STDLIB_DEFN(2over)
OSE_STDLIB_DEFN(2swap)
OSE_STDLIB_DEFN(drop)
OSE_STDLIB_DEFN(dup)
OSE_STDLIB_DEFN(nip)
OSE_STDLIB_DEFN(rrot)
OSE_STDLIB_DEFN(over)
OSE_STDLIB_DEFN(pick)
OSE_STDLIB_DEFN(pickBottom)
OSE_STDLIB_DEFN(pickMatch)
OSE_STDLIB_DEFN(roll)
OSE_STDLIB_DEFN(rollBottom)
OSE_STDLIB_DEFN(rollMatch)
OSE_STDLIB_DEFN(rot)
OSE_STDLIB_DEFN(swap)
OSE_STDLIB_DEFN(tuck)

OSE_STDLIB_DEFN(bundleAll)
OSE_STDLIB_DEFN(bundleFromBottom)
OSE_STDLIB_DEFN(bundleFromTop)
OSE_STDLIB_DEFN(clear)
OSE_STDLIB_DEFN(clearPayload)
OSE_STDLIB_DEFN(concatenateElems)
OSE_STDLIB_DEFN(pop)
OSE_STDLIB_DEFN(popAll)
OSE_STDLIB_DEFN(popAllDrop)
OSE_STDLIB_DEFN(popAllBundle)
OSE_STDLIB_DEFN(popAllDropBundle)
OSE_STDLIB_DEFN(push)
OSE_STDLIB_DEFN(decatenateElemFromEnd)
OSE_STDLIB_DEFN(decatenateElemFromStart)
OSE_STDLIB_DEFN(unpack)
OSE_STDLIB_DEFN(unpackDrop)

OSE_STDLIB_DEFN(countElems)
OSE_STDLIB_DEFN(countItems)
/* OSE_STDLIB_DEFN(lengthAddress) */
/* OSE_STDLIB_DEFN(lengthTT) */
OSE_STDLIB_DEFN(lengthItem)
OSE_STDLIB_DEFN(lengthsItems)
/* OSE_STDLIB_DEFN(sizeAddress) */
OSE_STDLIB_DEFN(sizeElem)
OSE_STDLIB_DEFN(sizeItem)
OSE_STDLIB_DEFN(sizePayload)
OSE_STDLIB_DEFN(sizesElems)
OSE_STDLIB_DEFN(sizesItems)
/* OSE_STDLIB_DEFN(sizeTT) */
OSE_STDLIB_DEFN(getAddresses)
OSE_STDLIB_DEFN(getTypetags)

OSE_STDLIB_DEFN(setTypetag)
OSE_STDLIB_DEFN(blobToElem)
OSE_STDLIB_DEFN(blobToType)
OSE_STDLIB_DEFN(concatenateBlobs)
OSE_STDLIB_DEFN(concatenateStrings)
OSE_STDLIB_DEFN(copyAddressToString)
OSE_STDLIB_DEFN(copyPayloadToBlob)
OSE_STDLIB_DEFN(swapStringToAddress)
OSE_STDLIB_DEFN(decatenateBlobFromEnd)
OSE_STDLIB_DEFN(decatenateBlobFromStart)
OSE_STDLIB_DEFN(decatenateStringFromEnd)
OSE_STDLIB_DEFN(decatenateStringFromStart)
OSE_STDLIB_DEFN(elemToBlob)
OSE_STDLIB_DEFN(itemToBlob)
OSE_STDLIB_DEFN(joinStrings)
OSE_STDLIB_DEFN(moveStringToAddress)
OSE_STDLIB_DEFN(splitStringFromEnd)
OSE_STDLIB_DEFN(splitStringFromStart)
OSE_STDLIB_DEFN(swap4Bytes)
OSE_STDLIB_DEFN(swap8Bytes)
OSE_STDLIB_DEFN(swapNBytes)
OSE_STDLIB_DEFN(trimStringEnd)
OSE_STDLIB_DEFN(trimStringStart)
OSE_STDLIB_DEFN(match)
OSE_STDLIB_DEFN(pmatch)
OSE_STDLIB_DEFN(replace)
OSE_STDLIB_DEFN(assign)
OSE_STDLIB_DEFN(lookup)
OSE_STDLIB_DEFN(plookup)
OSE_STDLIB_DEFN(route1)
OSE_STDLIB_DEFN(routeWithDelegation)
OSE_STDLIB_DEFN(select1)
OSE_STDLIB_DEFN(selectWithDelegation)
OSE_STDLIB_DEFN(gather)
OSE_STDLIB_DEFN(nth)
OSE_STDLIB_DEFN(setTimetag)
OSE_STDLIB_DEFN(getTimetag)

OSE_STDLIB_DEFN(makeBlob)
OSE_STDLIB_DEFN(pushBundle)

OSE_STDLIB_DEFN(add)
OSE_STDLIB_DEFN(sub)
OSE_STDLIB_DEFN(mul)
OSE_STDLIB_DEFN(div)
OSE_STDLIB_DEFN(mod)
OSE_STDLIB_DEFN(pow)
OSE_STDLIB_DEFN(neg)
OSE_STDLIB_DEFN(eql)
OSE_STDLIB_DEFN(neq)
OSE_STDLIB_DEFN(lte)
OSE_STDLIB_DEFN(lt)
OSE_STDLIB_DEFN(and)
OSE_STDLIB_DEFN(or)

OSE_STDLIB_DEFPRED(isAddressChar)
OSE_STDLIB_DEFPRED(isKnownTypetag)
OSE_STDLIB_DEFPRED(isStringType)
OSE_STDLIB_DEFPRED(isIntegerType)
OSE_STDLIB_DEFPRED(isFloatType)
OSE_STDLIB_DEFPRED(isNumericType)
OSE_STDLIB_DEFPRED(isUnitType)
OSE_STDLIB_DEFPRED(isBoolType)

OSE_STDLIB_DEFN(elemIsBundle)
OSE_STDLIB_DEFN(typeof0)
OSE_STDLIB_DEFN(typeof1)
OSE_STDLIB_DEFN(typeof2)

const void *ose_stdlib_lookup_fn(ose_constbundle osevm,
                                 const char * const addr)
{
    ose_bundle vm_l = ose_enter(osevm, "/_l");
    const char * const b = ose_getBundlePtr(vm_l);
    int32_t bs = ose_readSize(vm_l);
    int32_t o = OSE_BUNDLE_HEADER_LEN;
    while(o <= bs)
    {
        if(*((int32_t *)(addr + 4)) == *((int32_t *)(b + o + 8)))
        {
            return ose_readAlignedPtr(vm_l, o + 20);
        }
        o += ose_readInt32(vm_l, o) + 4;
    }
    return NULL;
}

#ifdef OSE_LINK_MODULES
void ose_stdlib_init(ose_bundle osevm)
#else
void ose_main(ose_bundle osevm)
#endif
{
    extern struct osevm_hooks osevm_hooks;
    ose_bundle vm_l;
    ose_pushContextMessage(osevm,
                           8192,
                           OSEVM_ADDR_STDLIB);
    vm_l = ose_enter(osevm, OSEVM_ADDR_STDLIB);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ASSIGN,
                    strlen(OSE_STDLIB_ADDR_ASSIGN),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_assign);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ASSIGNSTACKTOENV,
                    strlen(OSE_STDLIB_ADDR_ASSIGNSTACKTOENV),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_assignStackToEnv);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ASSIGNSTACKTOREGISTER,
                    strlen(OSE_STDLIB_ADDR_ASSIGNSTACKTOREGISTER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_assignStackToRegister);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_REPLACE,
                    strlen(OSE_STDLIB_ADDR_REPLACE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_replace);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ADD,
                    strlen(OSE_STDLIB_ADDR_ADD),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_add);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_AND,
                    strlen(OSE_STDLIB_ADDR_AND),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_and);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DIV,
                    strlen(OSE_STDLIB_ADDR_DIV),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_div);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_EQL,
                    strlen(OSE_STDLIB_ADDR_EQL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_eql);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_LT,
                    strlen(OSE_STDLIB_ADDR_LT),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_lt);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_LTE,
                    strlen(OSE_STDLIB_ADDR_LTE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_lte);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MOD,
                    strlen(OSE_STDLIB_ADDR_MOD),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_mod);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MUL,
                    strlen(OSE_STDLIB_ADDR_MUL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_mul);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_NEG,
                    strlen(OSE_STDLIB_ADDR_NEG),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_neg);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_NEQ,
                    strlen(OSE_STDLIB_ADDR_NEQ),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_neq);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_OR,
                    strlen(OSE_STDLIB_ADDR_OR),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_or);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_POW,
                    strlen(OSE_STDLIB_ADDR_POW),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_pow);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SUB,
                    strlen(OSE_STDLIB_ADDR_SUB),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_sub);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ELEMTOBLOB,
                    strlen(OSE_STDLIB_ADDR_ELEMTOBLOB),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_elemToBlob);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ITEMTOBLOB,
                    strlen(OSE_STDLIB_ADDR_ITEMTOBLOB),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_itemToBlob);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_BLOBTOELEM,
                    strlen(OSE_STDLIB_ADDR_BLOBTOELEM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_blobToElem);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOFLOAT,
                    strlen(OSE_STDLIB_ADDR_TOFLOAT),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toFloat);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOINT32,
                    strlen(OSE_STDLIB_ADDR_TOINT32),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toInt32);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOSTRING,
                    strlen(OSE_STDLIB_ADDR_TOSTRING),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toString);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOTYPE,
                    strlen(OSE_STDLIB_ADDR_TOTYPE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toType);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DOTIMES,
                    strlen(OSE_STDLIB_ADDR_DOTIMES),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_dotimes);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_IF,
                    strlen(OSE_STDLIB_ADDR_IF),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_if);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_RETURN,
                    strlen(OSE_STDLIB_ADDR_RETURN),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_return);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_APPENDBYTE,
                    strlen(OSE_STDLIB_ADDR_APPENDBYTE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_appendByte);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_CONCATENATEBLOBS,
                    strlen(OSE_STDLIB_ADDR_CONCATENATEBLOBS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_concatenateBlobs);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_CONCATENATEELEMS,
                    strlen(OSE_STDLIB_ADDR_CONCATENATEELEMS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_concatenateElems);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_CONCATENATESTRINGS,
                    strlen(OSE_STDLIB_ADDR_CONCATENATESTRINGS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_concatenateStrings);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DECATENATEBLOBFROMEND,
                    strlen(OSE_STDLIB_ADDR_DECATENATEBLOBFROMEND),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_decatenateBlobFromEnd);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DECATENATEBLOBFROMSTART,
                    strlen(OSE_STDLIB_ADDR_DECATENATEBLOBFROMSTART),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_decatenateBlobFromStart);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DECATENATEELEMFROMEND,
                    strlen(OSE_STDLIB_ADDR_DECATENATEELEMFROMEND),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_decatenateElemFromEnd);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DECATENATEELEMFROMSTART,
                    strlen(OSE_STDLIB_ADDR_DECATENATEELEMFROMSTART),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_decatenateElemFromStart);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DECATENATESTRINGFROMEND,
                    strlen(OSE_STDLIB_ADDR_DECATENATESTRINGFROMEND),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_decatenateStringFromEnd);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DECATENATESTRINGFROMSTART,
                    strlen(OSE_STDLIB_ADDR_DECATENATESTRINGFROMSTART),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_decatenateStringFromStart);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_JOINSTRINGS,
                    strlen(OSE_STDLIB_ADDR_JOINSTRINGS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_joinStrings);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MOVESTRINGTOADDRESS,
                    strlen(OSE_STDLIB_ADDR_MOVESTRINGTOADDRESS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_moveStringToAddress);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_POP,
                    strlen(OSE_STDLIB_ADDR_POP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_pop);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_POPALL,
                    strlen(OSE_STDLIB_ADDR_POPALL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_popAll);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_POPALLBUNDLE,
                    strlen(OSE_STDLIB_ADDR_POPALLBUNDLE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_popAllBundle);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_POPALLDROP,
                    strlen(OSE_STDLIB_ADDR_POPALLDROP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_popAllDrop);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_POPALLDROPBUNDLE,
                    strlen(OSE_STDLIB_ADDR_POPALLDROPBUNDLE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_popAllDropBundle);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PUSH,
                    strlen(OSE_STDLIB_ADDR_PUSH),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_push);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SETTIMETAG,
                    strlen(OSE_STDLIB_ADDR_SETTIMETAG),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_setTimetag);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SPLITSTRINGFROMEND,
                    strlen(OSE_STDLIB_ADDR_SPLITSTRINGFROMEND),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_splitStringFromEnd);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SPLITSTRINGFROMSTART,
                    strlen(OSE_STDLIB_ADDR_SPLITSTRINGFROMSTART),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_splitStringFromStart);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SWAP4BYTES,
                    strlen(OSE_STDLIB_ADDR_SWAP4BYTES),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_swap4Bytes);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SWAP8BYTES,
                    strlen(OSE_STDLIB_ADDR_SWAP8BYTES),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_swap8Bytes);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SWAPNBYTES,
                    strlen(OSE_STDLIB_ADDR_SWAPNBYTES),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_swapNBytes);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SWAPSTRINGTOADDRESS,
                    strlen(OSE_STDLIB_ADDR_SWAPSTRINGTOADDRESS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_swapStringToAddress);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TRIMSTRINGEND,
                    strlen(OSE_STDLIB_ADDR_TRIMSTRINGEND),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_trimStringEnd);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TRIMSTRINGSTART,
                    strlen(OSE_STDLIB_ADDR_TRIMSTRINGSTART),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_trimStringStart);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SETTYPETAG,
                    strlen(OSE_STDLIB_ADDR_SETTYPETAG),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_setTypetag);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_UNPACK,
                    strlen(OSE_STDLIB_ADDR_UNPACK),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_unpack);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_UNPACKDROP,
                    strlen(OSE_STDLIB_ADDR_UNPACKDROP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_unpackDrop);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_APPLY,
                    strlen(OSE_STDLIB_ADDR_APPLY),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_apply);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_EXEC1,
                    strlen(OSE_STDLIB_ADDR_EXEC1),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_exec1);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_EXEC2,
                    strlen(OSE_STDLIB_ADDR_EXEC2),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_exec2);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_EXEC3,
                    strlen(OSE_STDLIB_ADDR_EXEC3),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_exec3);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_EXEC,
                    strlen(OSE_STDLIB_ADDR_EXEC),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_exec);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_FUNCALL,
                    strlen(OSE_STDLIB_ADDR_FUNCALL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_funcall);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MAP,
                    strlen(OSE_STDLIB_ADDR_MAP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_map);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_GATHER,
                    strlen(OSE_STDLIB_ADDR_GATHER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_gather);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_LOOKUP,
                    strlen(OSE_STDLIB_ADDR_LOOKUP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_lookup);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_LOOKUPINENV,
                    strlen(OSE_STDLIB_ADDR_LOOKUPINENV),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_lookupInEnv);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MATCH,
                    strlen(OSE_STDLIB_ADDR_MATCH),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_match);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_NTH,
                    strlen(OSE_STDLIB_ADDR_NTH),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_nth);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PLOOKUP,
                    strlen(OSE_STDLIB_ADDR_PLOOKUP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_plookup);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PLOOKUPINENV,
                    strlen(OSE_STDLIB_ADDR_PLOOKUPINENV),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_plookupInEnv);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PMATCH,
                    strlen(OSE_STDLIB_ADDR_PMATCH),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_pmatch);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ROUTE1,
                    strlen(OSE_STDLIB_ADDR_ROUTE1),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_route1);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ROUTEWITHDELEGATION,
                    strlen(OSE_STDLIB_ADDR_ROUTEWITHDELEGATION),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_routeWithDelegation);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SELECT1,
                    strlen(OSE_STDLIB_ADDR_SELECT1),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_select1);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SELECTWITHDELEGATION,
                    strlen(OSE_STDLIB_ADDR_SELECTWITHDELEGATION),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_selectWithDelegation);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_VERSION,
                    strlen(OSE_STDLIB_ADDR_VERSION),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_version);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_COUNTELEMS,
                    strlen(OSE_STDLIB_ADDR_COUNTELEMS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_countElems);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_COUNTITEMS,
                    strlen(OSE_STDLIB_ADDR_COUNTITEMS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_countItems);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_GETADDRESSES,
                    strlen(OSE_STDLIB_ADDR_GETADDRESSES),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_getAddresses);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_GETTIMETAG,
                    strlen(OSE_STDLIB_ADDR_GETTIMETAG),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_getTimetag);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_GETTYPETAGS,
                    strlen(OSE_STDLIB_ADDR_GETTYPETAGS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_getTypetags);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISADDRESSCHAR,
                    strlen(OSE_STDLIB_ADDR_ISADDRESSCHAR),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isAddressChar);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ELEMISBUNDLE,
                    strlen(OSE_STDLIB_ADDR_ELEMISBUNDLE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_elemIsBundle);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISBOOLTYPE,
                    strlen(OSE_STDLIB_ADDR_ISBOOLTYPE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isBoolType);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISFLOATTYPE,
                    strlen(OSE_STDLIB_ADDR_ISFLOATTYPE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isFloatType);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISINTEGERTYPE,
                    strlen(OSE_STDLIB_ADDR_ISINTEGERTYPE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isIntegerType);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISKNOWNTYPETAG,
                    strlen(OSE_STDLIB_ADDR_ISKNOWNTYPETAG),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isKnownTypetag);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISNUMERICTYPE,
                    strlen(OSE_STDLIB_ADDR_ISNUMERICTYPE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isNumericType);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISSTRINGTYPE,
                    strlen(OSE_STDLIB_ADDR_ISSTRINGTYPE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isStringType);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ISUNITTYPE,
                    strlen(OSE_STDLIB_ADDR_ISUNITTYPE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_isUnitType);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_LENGTHITEM,
                    strlen(OSE_STDLIB_ADDR_LENGTHITEM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_lengthItem);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_LENGTHSITEMS,
                    strlen(OSE_STDLIB_ADDR_LENGTHSITEMS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_lengthsItems);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SIZEELEM,
                    strlen(OSE_STDLIB_ADDR_SIZEELEM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_sizeElem);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SIZEITEM,
                    strlen(OSE_STDLIB_ADDR_SIZEITEM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_sizeItem);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SIZEPAYLOAD,
                    strlen(OSE_STDLIB_ADDR_SIZEPAYLOAD),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_sizePayload);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SIZESELEMS,
                    strlen(OSE_STDLIB_ADDR_SIZESELEMS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_sizesElems);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SIZESITEMS,
                    strlen(OSE_STDLIB_ADDR_SIZESITEMS),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_sizesItems);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TYPEOF0,
                    strlen(OSE_STDLIB_ADDR_TYPEOF0),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_typeof0);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TYPEOF1,
                    strlen(OSE_STDLIB_ADDR_TYPEOF1),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_typeof1);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TYPEOF2,
                    strlen(OSE_STDLIB_ADDR_TYPEOF2),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_typeof2);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_APPENDELEMTOREGISTER,
                    strlen(OSE_STDLIB_ADDR_APPENDELEMTOREGISTER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_appendElemToRegister);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_COPYELEMTOREGISTER,
                    strlen(OSE_STDLIB_ADDR_COPYELEMTOREGISTER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_copyElemToRegister);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_COPYREGISTERTOELEM,
                    strlen(OSE_STDLIB_ADDR_COPYREGISTERTOELEM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_copyRegisterToElem);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MAKEREGISTER,
                    strlen(OSE_STDLIB_ADDR_MAKEREGISTER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_makeRegister);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MOVEELEMTOREGISTER,
                    strlen(OSE_STDLIB_ADDR_MOVEELEMTOREGISTER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_moveElemToRegister);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_REPLACEREGISTERWITHELEM,
                    strlen(OSE_STDLIB_ADDR_REPLACEREGISTERWITHELEM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_replaceRegisterWithElem);

    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_2DROP,
                    strlen(OSE_STDLIB_ADDR_2DROP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_2drop);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_2DUP,
                    strlen(OSE_STDLIB_ADDR_2DUP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_2dup);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_2OVER,
                    strlen(OSE_STDLIB_ADDR_2OVER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_2over);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_2SWAP,
                    strlen(OSE_STDLIB_ADDR_2SWAP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_2swap);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_BUNDLEALL,
                    strlen(OSE_STDLIB_ADDR_BUNDLEALL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_bundleAll);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_BUNDLEFROMBOTTOM,
                    strlen(OSE_STDLIB_ADDR_BUNDLEFROMBOTTOM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_bundleFromBottom);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_BUNDLEFROMTOP,
                    strlen(OSE_STDLIB_ADDR_BUNDLEFROMTOP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_bundleFromTop);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_CLEAR,
                    strlen(OSE_STDLIB_ADDR_CLEAR),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_clear);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DROP,
                    strlen(OSE_STDLIB_ADDR_DROP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_drop);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_DUP,
                    strlen(OSE_STDLIB_ADDR_DUP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_dup);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_MAKEBLOB,
                    strlen(OSE_STDLIB_ADDR_MAKEBLOB),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_makeBlob);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PUSHBUNDLE,
                    strlen(OSE_STDLIB_ADDR_PUSHBUNDLE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_pushBundle);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_NIP,
                    strlen(OSE_STDLIB_ADDR_NIP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_nip);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_OVER,
                    strlen(OSE_STDLIB_ADDR_OVER),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_over);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PICKBOTTOM,
                    strlen(OSE_STDLIB_ADDR_PICKBOTTOM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_pickBottom);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PICK,
                    strlen(OSE_STDLIB_ADDR_PICK),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_pick);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_PICKMATCH,
                    strlen(OSE_STDLIB_ADDR_PICKMATCH),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_pickMatch);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ROLLBOTTOM,
                    strlen(OSE_STDLIB_ADDR_ROLLBOTTOM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_rollBottom);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ROLL,
                    strlen(OSE_STDLIB_ADDR_ROLL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_roll);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ROLLMATCH,
                    strlen(OSE_STDLIB_ADDR_ROLLMATCH),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_rollMatch);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_ROT,
                    strlen(OSE_STDLIB_ADDR_ROT),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_rot);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_RROT,
                    strlen(OSE_STDLIB_ADDR_RROT),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_rrot);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_SWAP,
                    strlen(OSE_STDLIB_ADDR_SWAP),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_swap);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TUCK,
                    strlen(OSE_STDLIB_ADDR_TUCK),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_tuck);

    if(osevm_hooks.MOVEELEMTOREGISTER)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_MOVEELEMTOREGISTER,
                        strlen(OSEVM_ADDR_MOVEELEMTOREGISTER),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.MOVEELEMTOREGISTER);
    }
    if(osevm_hooks.TOTYPE)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_TOTYPE,
                        strlen(OSEVM_ADDR_TOTYPE),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.TOTYPE);
    }
    if(osevm_hooks.TOBLOB)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_TOBLOB,
                        strlen(OSEVM_ADDR_TOBLOB),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.TOBLOB);
    }
    if(osevm_hooks.TOFLOAT)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_TOFLOAT,
                        strlen(OSEVM_ADDR_TOFLOAT),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.TOFLOAT);
    }
    if(osevm_hooks.TOINT32)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_TOINT32,
                        strlen(OSEVM_ADDR_TOINT32),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.TOINT32);
    }
    if(osevm_hooks.TOSTRING)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_TOSTRING,
                        strlen(OSEVM_ADDR_TOSTRING),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.TOSTRING);
    }
    if(osevm_hooks.FUNCALL)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_FUNCALL,
                        strlen(OSEVM_ADDR_FUNCALL),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.FUNCALL);
    }
    if(osevm_hooks.QUOTE)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_QUOTE,
                        strlen(OSEVM_ADDR_QUOTE),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.QUOTE);
    }
    if(osevm_hooks.ASSIGN)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_ASSIGN,
                        strlen(OSEVM_ADDR_ASSIGN),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.ASSIGN);
    }
    if(osevm_hooks.APPENDBYTE)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_APPENDBYTE,
                        strlen(OSEVM_ADDR_APPENDBYTE),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.APPENDBYTE);
    }
    if(osevm_hooks.REPLACEREGISTERWITHELEM)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_REPLACEREGISTERWITHELEM,
                        strlen(OSEVM_ADDR_REPLACEREGISTERWITHELEM),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.REPLACEREGISTERWITHELEM);
    }
    if(osevm_hooks.APPENDELEMTOREGISTER)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_APPENDELEMTOREGISTER,
                        strlen(OSEVM_ADDR_APPENDELEMTOREGISTER),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.APPENDELEMTOREGISTER);
    }
    if(osevm_hooks.COPYREGISTERTOELEM)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_COPYREGISTERTOELEM,
                        strlen(OSEVM_ADDR_COPYREGISTERTOELEM),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.COPYREGISTERTOELEM);
    }
    if(osevm_hooks.LOOKUP)
    {
        ose_pushMessage(vm_l,
                        OSEVM_ADDR_LOOKUP,
                        strlen(OSEVM_ADDR_LOOKUP),
                        1,
                        OSETT_ALIGNEDPTR,
                        osevm_hooks.LOOKUP);
    }
#ifdef OSE_PROVIDE_TYPE_SYMBOL
#define OSEVM_ADDR_TOSYMBOL "/_l/P,S"
#define OSE_STDLIB_ADDR_TOSYMBOL "/_l/2SY"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOSYMBOL,
                    strlen(OSEVM_ADDR_TOSYMBOL),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOSYMBOL);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOSYMBOL,
                    strlen(OSE_STDLIB_ADDR_TOSYMBOL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toSymbol);
#endif
#ifdef OSE_PROVIDE_TYPE_DOUBLE
#define OSEVM_ADDR_TODOUBLE "/_l/P,d"
#define OSE_STDLIB_ADDR_TODOUBLE "/_l/2DL"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TODOUBLE,
                    strlen(OSEVM_ADDR_TODOUBLE),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TODOUBLE);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TODOUBLE,
                    strlen(OSE_STDLIB_ADDR_TODOUBLE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toDouble);
#endif
#ifdef OSE_PROVIDE_TYPE_INT8
#define OSEVM_ADDR_TOINT8 "/_l/P,c"
#define OSE_STDLIB_ADDR_TOINT8 "/_l/2I1"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOINT8,
                    strlen(OSEVM_ADDR_TOINT8),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOINT8);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOINT8,
                    strlen(OSE_STDLIB_ADDR_TOINT8),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toInt8);
#endif
#ifdef OSE_PROVIDE_TYPE_UINT8
#define OSEVM_ADDR_TOUINT8 "/_l/P,C"
#define OSE_STDLIB_ADDR_TOUINT8 "/_l/2U1"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOUINT8,
                    strlen(OSEVM_ADDR_TOUINT8),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOUINT8);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOUINT8,
                    strlen(OSE_STDLIB_ADDR_TOUINT8),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toUInt8);
#endif
#ifdef OSE_PROVIDE_TYPE_INT16
#define OSEVM_ADDR_TOINT16 "/_l/P,u"
#define OSE_STDLIB_ADDR_TOINT16 "/_l/2I2"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOINT16,
                    strlen(OSEVM_ADDR_TOINT16),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOINT16);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOINT16,
                    strlen(OSE_STDLIB_ADDR_TOINT16),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toInt16);
#endif
#ifdef OSE_PROVIDE_TYPE_UINT16
#define OSEVM_ADDR_TOUINT16 "/_l/P,U"
#define OSE_STDLIB_ADDR_TOUINT16 "/_l/2U2"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOUINT16,
                    strlen(OSEVM_ADDR_TOUINT16),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOUINT16);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOUINT16,
                    strlen(OSE_STDLIB_ADDR_TOUINT16),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toUInt16);
#endif
#ifdef OSE_PROVIDE_TYPE_UINT32
#define OSEVM_ADDR_TOUINT32 "/_l/P,k"
#define OSE_STDLIB_ADDR_TOUINT32 "/_l/2U4"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOUINT32,
                    strlen(OSEVM_ADDR_TOUINT32),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOUINT32);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOUINT32,
                    strlen(OSE_STDLIB_ADDR_TOUINT32),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toUInt32);
#endif
#ifdef OSE_PROVIDE_TYPE_INT64
#define OSEVM_ADDR_TOINT64 "/_l/P,h"
#define OSE_STDLIB_ADDR_TOINT64 "/_l/2I8"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOINT64,
                    strlen(OSEVM_ADDR_TOINT64),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOINT64);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOINT64,
                    strlen(OSE_STDLIB_ADDR_TOINT64),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toInt64);
#endif
#ifdef OSE_PROVIDE_TYPE_UINT64
#define OSEVM_ADDR_TOUINT64 "/_l/P,H"
#define OSE_STDLIB_ADDR_TOUINT64 "/_l/2U8"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOUINT64,
                    strlen(OSEVM_ADDR_TOUINT64),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOUINT64);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOUINT64,
                    strlen(OSE_STDLIB_ADDR_TOUINT64),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toUInt64);
#endif
#ifdef OSE_PROVIDE_TYPE_TIMETAG
#define OSEVM_ADDR_TOTIMETAG "/_l/P,t"
#define OSE_STDLIB_ADDR_TOTIMETAG "/_l/2TT"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOTIMETAG,
                    strlen(OSEVM_ADDR_TOTIMETAG),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOTIMETAG);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOTIMETAG,
                    strlen(OSE_STDLIB_ADDR_TOTIMETAG),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toTimetag);
#endif
#ifdef OSE_PROVIDE_TYPE_TRUE
#define OSEVM_ADDR_TOTRUE "/_l/P,T"
#define OSE_STDLIB_ADDR_TOTRUE "/_l/2TR"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOTRUE,
                    strlen(OSEVM_ADDR_TOTRUE),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOTRUE);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOTRUE,
                    strlen(OSE_STDLIB_ADDR_TOTRUE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toTrue);
#endif
#ifdef OSE_PROVIDE_TYPE_FALSE
#define OSEVM_ADDR_TOFALSE "/_l/P,F"
#define OSE_STDLIB_ADDR_TOFALSE "/_l/2FA"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOFALSE,
                    strlen(OSEVM_ADDR_TOFALSE),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOFALSE);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOFALSE,
                    strlen(OSE_STDLIB_ADDR_TOFALSE),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toFalse);
#endif
#ifdef OSE_PROVIDE_TYPE_NULL
#define OSEVM_ADDR_TONULL "/_l/P,N"
#define OSE_STDLIB_ADDR_TONULL "/_l/2NU"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TONULL,
                    strlen(OSEVM_ADDR_TONULL),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TONULL);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TONULL,
                    strlen(OSE_STDLIB_ADDR_TONULL),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toNull);
#endif
#ifdef OSE_PROVIDE_TYPE_INFINITUM
#define OSEVM_ADDR_TOINFINITUM "/_l/P,I"
#define OSE_STDLIB_ADDR_TOINFINITUM "/_l/2IF"
    ose_pushMessage(vm_l,
                    OSEVM_ADDR_TOINFINITUM,
                    strlen(OSEVM_ADDR_TOINFINITUM),
                    1,
                    OSETT_ALIGNEDPTR,
                    osevm_hooks.TOINFINITUM);
    ose_pushMessage(vm_l,
                    OSE_STDLIB_ADDR_TOINFINITUM,
                    strlen(OSE_STDLIB_ADDR_TOINFINITUM),
                    1,
                    OSETT_ALIGNEDPTR,
                    ose_stdlib_toInfinitum);
#endif
}
