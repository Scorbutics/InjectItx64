#ifndef _LDR_DLL_LOAD_REASON_H
#define _LDR_DLL_LOAD_REASON_H

typedef enum _LDR_DLL_LOAD_REASON {
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency = 1,
    LoadReasonDynamicForwarderDependency = 2,
    LoadReasonDelayloadDependency = 3,
    LoadReasonDynamicLoad = 4,
    LoadReasonAsImageLoad = 5,
    LoadReasonAsDataLoad = 6,
    LoadReasonUnknown = -1,
} LDR_DLL_LOAD_REASON;

#endif // _LDR_DLL_LOAD_REASON_H
