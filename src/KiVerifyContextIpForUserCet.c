struct _UNWIND_STATE
{
  PVOID ImageBase;
  PIMAGE_LOAD_CONFIG_DIRECTORY64 LoadConfig;
  BOOLEAN CheckedLoadConfig;
} UNWIND_STATE, *PUNWIND_STATE;


NTSTATUS
KiVerifyContextIpForUserCet (
    _In_ PETHREAD Thread, 
    _In_ PCONTEXT Context, 
    _In_ PKCONTINUE_TYPE ContinueType, 
    _In_ BOOLEAN RelaxedMode,
    _Inout_ ULONG_PTR ShadowStack
    )
{
    ULONG64 userRip;
    ULONG_PTR shadowStack;
    UKCONTINUE_TYPE continueType;
    NTSTATUS status;
    BOOLEAN loadConfigChecked;
    UNWIND_STATE unwindState;

    //
    // Deny if the target Rip a kernel address or below 0x10000
    //
    userRip = Context->Rip;
    if ((userRip >= MM_USER_PROBE_ADDRESS) ||
        (userRip < MM_ALLOCATION_GRANULARITY))
    {
        return STATUS_SET_CONTEXT_DENIED;
    }
    //
    // Ignore if target Rip is the previous address in user space
    // (such as the initial thread start address)
    //
    trapFrame = PspGetBaseTrapFrame(Thread);
    if (userRip == trapFrame->Rip)
    {
        return STATUS_SUCCESS;
    }

    shadowStack = *ShadowStack;
    continueType = *ContinueType;
    if (continueType == KCONTINUE_LONGJUMP)
    {
        return RtlVerifyUserUnwindTarget(userRip, KCONTINUE_LONGJUMP, 0);
    }
    else if ((continueType != KCONTINUE_UNWIND) && 
             (continueType != KCONTINUE_RESUME) && 
             (continueType != KCONTINUE_SET))
    {
        return STATUS_INVALID_PARAMETER;
    }
    //
    // Get address of shadow stack if one was not provided by caller.
    // If no shadow stack exists, allow any Rip.
    //
    if (shadowStack == NULL)
    {
        shadowStack = __readmsr(MSR_IA32_PL3_SSP);
        if (shadowStack == NULL)
        {
            return STATUS_SUCCESS;
        }
    }

    if ((continueType == KCONTINUE_UNWIND) && 
        (userRip == PsNtdllExports.RtlUserThreadStart))
    {
        *ContinueType = KCONTINUE_RESUME;
        continueType = KCONTINUE_RESUME;
    }
    RtlZeroMemory(&unwindState, sizeof(unwindState));
    if (continueType == KCONTINUE_UNWIND)
    {
        status = RtlVerifyUserUnwindTarget(userRip, KCONTINUE_UNWIND, &unwindState);
        if (NT_SUCCESS(status))
        {
            return status;
        }
    }
    //
    // This code will run when RelaxedMode is enabled and continueType is
    // either KCONTINUE_SET or KCONTINUE_UNWIND if RtlVerifyUserUnwindTarget failed
    //
    if ((RelaxedMode) && (*ContinueType != KCONTINUE_RESUME))
    {
        if (!unwindState.CheckedLoadConfig)
        {
            status = RtlGetImageBaseAndLoadConfig(userRip, &unwindState.ImageBase, &unwindState.LoadConfig);
            loadConfigChecked = NT_SUCCESS(status) ? 1: unwindState.CheckedLoadConfig;
            unwindState.CheckedLoadConfig = loadConfigChecked;
        }
        if ( loadConfigChecked )
        {
            if ( unwindState.ImageBase )
            {
                //
                // Check if there is a EhContinuationTable in the LoadConfig.
                // If it exists it would be after the XFG data
                // This code is actually just a "probe" to see if there is a point in checking the EhCont flag,
                // and will throw STATUS_ACCESS_VIOLATION if it fails.
                //
                __try
                {
                    ProbeForRead(unwindState.LoadConfig, 
                                 offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationCount),
                                 RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationCount));

                    //
                    // So this code is meant as a "whitelist" for older binaries that don't fully support CET.
                    // There are some FPs with processes using NtSetContextThread to targets that CET does not expect.
                    // For newer processes that were compiled recently with the correct flags,
                    // this will create an EX_CONTINUATION_TABLE that will contain those targets.
                    // But for older processes Windows supports "relaxed mode" CET.
                    // If "relaxed mode" is set for the process, any module that does not have an EX_CONTINUATION_TABLE
                    // will be allowed to set the context to any address.
                    //
                    if ((unwindState.LoadConfig) &&
                        (unwindState.LoadConfig->Size >= RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardEHContinuationCount)) &&
                        ((unwindState.LoadConfig->GuardFlags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT) != 0))
                    {
                        goto CheckAddressInShadowStack;
                    }
                }
                __except
                {
                    goto CheckAddressInShadowStack;
                }
                return STATUS_SUCCESS;
            }
            return STATUS_SUCCESS;
        }
    }
CheckAddressInShadowStack:
    //
    // Iterate over shadow stack and check if target Rip is in it.
    // If thread is terminating, only try to find the target Rip
    // in the current page of the shadow stack. 
    //
    __try
    {
        do
        {
            if (*shadowStack == userRip)
            {
                *ShadowStack = shadowStack + sizeof(userRip);
                return STATUS_SUCCESS;
            }
            shadowStack += sizeof(userRip);
        } while (!(PAGE_ALIGNED(shadowStack)) || !(Thread->Terminated));

        return STATUS_THREAD_IS_TERMINATING;
    }
    __except
    {
        return STATUS_SET_CONTEXT_DENIED;
    }
}