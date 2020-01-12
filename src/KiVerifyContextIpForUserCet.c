NTSTATUS
KiVerifyContextIpForUserCet (
    _In_ PETHREAD Thread,
    _In_ PCONTEXT Context,
    _In_ PKCONTINUE_TYPE ContinueType,
    _Inout_ PULONG_PTR ShadowStack
    )
{
    ULONG64 userRip;
    PKSTACK_CONTROL stackControl;
    ULONG_PTR shadowStack;
    KCONTINUE_TYPE continueType;
    PKTRAP_FRAME trapFrame;

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

    //
    // Handle Rip validation for each KCONTINUE_TYPE
    //
    shadowStack = *ShadowStack;
    continueType = *ContinueType;
    switch (continueType)
    {
    case KCONTINUE_UNWIND:
    case KCONTINUE_RESUME:
    case KCONTINUE_SET:

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

        //
        // Iterate over shadow stack and check if target Rip is in it.
        // If thread is terminating, only try to find the target Rip
        // in the current page of the shadow stack. 
        //
        __try
        {
            do
            {
                shadowStack += sizeof(userRip);
                if (*shadowStack == userRip)
                {
                    *ShadowStack = shadowStack + sizeof(userRip);
                    return STATUS_SUCCESS;
                }
            } while (!(PAGE_ALIGNED(shadowStack)) || !(Thread->Terminated));

            return STATUS_THREAD_IS_TERMINATING;
        }
        //
        // If target Rip was not found and this is an unwind, try to verify
        // Rip in the exception table unwind. 
        //
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            if (continueType == KCONTINUE_UNWIND)
            {
                return RtlVerifyUserUnwindTarget(userRip, KCONTINUE_UNWIND);
            }

            return STATUS_SET_CONTEXT_DENIED;
        }
        //
        // If this is a long jump, try to verify Rip in the longjmp table.
        //
    case KCONTINUE_LONGJUMP:
        return RtlVerifyUserUnwindTarget(userRip, KCONTINUE_LONGJUMP);

    default:
        return STATUS_INVALID_PARAMETER;
    }
}