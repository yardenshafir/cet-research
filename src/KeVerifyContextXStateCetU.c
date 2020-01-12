NTSTATUS
KeVerifyContextXStateCetU (
    _In_ PKTHREAD Thread,
    _In_ PCONTEXT ContextRecord,
    _Outptr_ PULONG_PTR ShadowStack
    )
{
    PXSAVE_CET_U_FORMAT cetData;
    PXSAVE_AREA_HEADER xsaveData;
    NTSTATUS status;

    if (!BooleanFlagOn(Context->Context.ContextFlags, CONTEXT_XSTATE))
    {
        return STATUS_SUCCESS;
    }

    //
    // Get the address of the CET state from the supplied context
    //
    cetData = (PXSAVE_CET_U_FORMAT)RtlLocateExtendedFeature2((PCONTEXT_EX)(Context + 1),
                                                             XSTATE_CET_U,
                                                             &SharedUserData.XState,
                                                             NULL);
    if (cetData == NULL)
    {
        return STATUS_SUCCESS;
    }

    *ShadowStack = __readmsr(MSR_IA32_PL3_SSP);

    //
    // Check if the context contains values for CET registers.
    // If it doesn't, it means CET registers will not be set, and 
    // will disable CET if it was previously enabled.
    //
    xsaveData = (PXSAVE_AREA_HEADER)RTL_CONTEXT_CHUNK(Context, XState);

    if (Thread->CetUserShadowStack != FALSE)
    {
        if (!BooleanFlagOn(xsaveData->Mask, XSTATE_MASK_CET_U))
        {
            //
            // If the thread has CET enabled but the new context doesn't have
            // CET registers in it, set the CET registers in the context to
            // the current CET values.
            //
            SetFlag(xsaveData->Mask, XSTATE_MASK_CET_U);
            cetData->Ia32CetUMsr = MSR_IA32_CET_SHSTK_EN;
            cetData->Ia32Pl3SspMsr = *ShadowStack;
            return STATUS_SUCCESS;
        }

        //
        // Verify that the new Ssp value is inside the shadow stack
        //
        status = KiVerifyContextXStateCetUEnabled(cetData, *ShadowStack);
        if (NT_SUCCESS(status))
        {
            return STATUS_SUCCESS;
        }

        return status;
    }

    //
    // If the thread doesn't have CET enabled and the new context doesn't
    // have CET registers, or the CET mask is set but the CET registers 
    // don't hold any value, allow because the CET state will not change.
    //
    if (!(BooleanFlagOn(xsaveData->Mask, XSTATE_MASK_CET_U)) ||
        ((cetData->Ia32CetUMsr == 0) &&
        (cetData->Ia32Pl3SspMsr == NULL)))
    {
        return STATUS_SUCCESS;
    }

    return STATUS_SET_CONTEXT_DENIED;
}