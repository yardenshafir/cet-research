#define UNICODE
#include <windows.h>
#include <wchar.h>
#include <stdio.h>

typedef struct _XSAVE_CPU_INFO
{
    /* 0x0000 */ unsigned char Processor;
    /* 0x0002 */ unsigned short Family;
    /* 0x0004 */ unsigned short Model;
    /* 0x0006 */ unsigned short Stepping;
    /* 0x0008 */ unsigned short ExtendedModel;
    /* 0x000c */ unsigned long ExtendedFamily;
    /* 0x0010 */ unsigned __int64 MicrocodeVersion;
    /* 0x0018 */ unsigned long Reserved;
    /* 0x001c */ long __PADDING__[1];
} XSAVE_CPU_INFO, *PXSAVE_CPU_INFO; /* size: 0x0020 */

typedef struct _XSAVE_CPU_ERRATA
{
    /* 0x0000 */ unsigned long NumberOfErrata;
    /* 0x0008 */ struct _XSAVE_CPU_INFO Errata[1];
} XSAVE_CPU_ERRATA, *PXSAVE_CPU_ERRATA; /* size: 0x0028 */

typedef struct _XSAVE_SUPPORTED_CPU
{
    /* 0x0000 */ struct _XSAVE_CPU_INFO CpuInfo;
    union
    {
        /* 0x0020 */ struct XSAVE_CPU_ERRATA* CpuErrata;
        /* 0x0020 */ unsigned __int64 Unused;
    }; /* size: 0x0008 */
} XSAVE_SUPPORTED_CPU, *PXSAVE_SUPPORTED_CPU; /* size: 0x0028 */

typedef struct _XSAVE_VENDOR
{
    /* 0x0000 */ unsigned long VendorId[3];
    /* 0x0010 */ struct _XSAVE_SUPPORTED_CPU SupportedCpu;
} XSAVE_VENDOR, *PXSAVE_VENDOR; /* size: 0x0038 */

typedef struct _XSAVE_VENDORS
{
    /* 0x0000 */ unsigned long NumberOfVendors;
    /* 0x0008 */ struct _XSAVE_VENDOR Vendor[1];
} XSAVE_VENDORS, *PXSAVE_VENDORS; /* size: 0x0040 */

typedef struct _XSAVE_FEATURE
{
    /* 0x0000 */ unsigned long FeatureId;
    union
    {
        /* 0x0008 */ struct _XSAVE_VENDORS* Vendors;
        /* 0x0008 */ unsigned __int64 Unused;
    }; /* size: 0x0008 */
} XSAVE_FEATURE, *PXSAVE_FEATURE; /* size: 0x0010 */

typedef struct _XSAVE_POLICY
{
    /* 0x0000 */ unsigned long Version;
    /* 0x0004 */ unsigned long Size;
    /* 0x0008 */ unsigned long Flags;
    /* 0x000c */ unsigned long MaxSaveAreaLength;
    /* 0x0010 */ unsigned __int64 FeatureBitmask;
    /* 0x0018 */ unsigned long NumberOfFeatures;
    /* 0x0020 */ struct _XSAVE_FEATURE Features[1];
} XSAVE_POLICY, *PXSAVE_POLICY; /* size: 0x0030 */

PCHAR featureName[] =
{
    "XSTATE_LEGACY_FLOATING_POINT",
    "XSTATE_LEGACY_SSE",
    "XSTATE_AVX",
    "XSTATE_MPX_BNDREGS",
    "XSTATE_MPX_BNDCSR",
    "XSTATE_AVX512_KMASK",
    "XSTATE_AVX512_ZMM_H",
    "XSTATE_AVX512_ZMM",
    "XSTATE_IPT",
    "XSTATE_PKRU",
    "XSTATE_UNKNOWN",
    "XSTATE_CET_U",
};

int main()
{
    UINT res;
    WCHAR filePath[MAX_PATH];
    HMODULE handle;
    HRSRC resource;
    HGLOBAL hResource;
    PXSAVE_POLICY policy;
    PXSAVE_VENDORS xsaveVendors;
    PXSAVE_CPU_INFO cpuInfo;
    PXSAVE_CPU_ERRATA cpuErrata;

    //
    // Build the path and load hwpolicy.sys
    //
    res = GetSystemDirectory(filePath, sizeof(filePath));
    if (res == 0)
    {
        printf("Failed to get system directory. Error: %d\n", GetLastError());
        return 1;
    }
    wcscat_s(filePath, _countof(filePath), L"\\drivers\\hwpolicy.sys");
    handle = LoadLibraryEx(filePath, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (handle == NULL)
    {
        printf("Failed loading hwpolicy.sys. Error: %d\n", GetLastError()); 
        return 1;
    }

    //
    // Load the resource that contains the errata information
    //
    resource = FindResource(handle, MAKEINTRESOURCE(1), MAKEINTRESOURCE(101));
    if (resource == NULL)
    {
        printf("Failed finding resource. Error: %d\n", GetLastError());
        return 1;
    }
    hResource = LoadResource(handle, resource);
    if (hResource == NULL)
    {
        printf("Failed loading resource. Error: %d\n", GetLastError());
        return 1;
    }

    policy = (PXSAVE_POLICY)LockResource(hResource);

    printf("Xsave policy: %p\n", policy);
    printf("Version: 0x%x\n", policy->Version);
    printf("Size: 0x%x\n", policy->Size);
    printf("Flags: 0x%x\n", policy->Flags);
    printf("MaxSaveAreaLength: 0x%x\n", policy->MaxSaveAreaLength);
    printf("FeatureBitmask: 0x%llx\n", policy->FeatureBitmask);
    printf("NumberOfFeatures: %d\n", policy->NumberOfFeatures);

    printf("\nFeatures:\n");
    for (ULONG i = 0; i < policy->NumberOfFeatures; i++)
    {
        printf("\tFeatureId: %d (%s)\n",
                policy->Features[i].FeatureId,
                policy->Features[i].FeatureId < _countof(featureName) ?
                featureName[policy->Features[i].FeatureId] :
                "UNKNOWN");

        if (policy->Features[i].Unused == 0)
        {
            continue;
        }

        printf("\tVendors:\n");
        xsaveVendors = (PXSAVE_VENDORS)(policy->Features[i].Unused + (ULONG_PTR)policy);
        printf("\tNumber of vendors: %d\n", xsaveVendors->NumberOfVendors);
        for (ULONG j = 0; j < xsaveVendors->NumberOfVendors; j++)
        {
            printf("\t\tVendor Id: %s\n", (PCHAR)xsaveVendors->Vendor[j].VendorId);
            printf("\t\tCpu Info:\n");
            cpuInfo = &xsaveVendors->Vendor[j].SupportedCpu.CpuInfo;
            printf("\t\t\tProcessor: %x\n", cpuInfo->Processor);
            printf("\t\t\tFamily: %x\n", cpuInfo->Family);
            printf("\t\t\tModel: %x\n", cpuInfo->Model);
            printf("\t\t\tStepping: %x\n", cpuInfo->Stepping);
            printf("\t\t\tExtended model: %x\n", cpuInfo->ExtendedModel);
            printf("\t\t\tExtended family: %x\n", cpuInfo->ExtendedFamily);
            printf("\t\t\tMicrocode version: %llx\n", cpuInfo->MicrocodeVersion);
            printf("\n");

            if (xsaveVendors->Vendor[j].SupportedCpu.Unused == 0)
            {
                continue;
            }

            printf("\t\tCpu Errata:\n");
            cpuErrata = (PXSAVE_CPU_ERRATA)(xsaveVendors->Vendor[j].SupportedCpu.Unused + (ULONG_PTR)policy);
            printf("\t\tNumber of errata: %d\n", cpuErrata->NumberOfErrata);

            for (ULONG n = 0; n <cpuErrata->NumberOfErrata; n++)
            {
                cpuInfo = &cpuErrata->Errata[n];
                printf("\t\t\tProcessor: %x\n", cpuInfo->Processor);
                printf("\t\t\tFamily: %x\n", cpuInfo->Family);
                printf("\t\t\tModel: %x\n", cpuInfo->Model);
                printf("\t\t\tStepping: %x\n", cpuInfo->Stepping);
                printf("\t\t\tExtended model: %x\n", cpuInfo->ExtendedModel);
                printf("\t\t\tExtended family: %x\n", cpuInfo->ExtendedFamily);
                printf("\t\t\tMicrocode version: %llx\n", cpuInfo->MicrocodeVersion);
                printf("\n");
            }

            printf("\n");
        }
    }

    UnlockResource(hResource);
    FreeLibrary(handle);

    return 0;
}