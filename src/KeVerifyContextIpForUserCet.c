NTSTATUS
KeVerifyContextIpForUserCet (
    _In_ PETHREAD Thread,
    _In_ PCONTEXT Context,
    _In_ PKCONTINUE_TYPE ContinueType,
    _Inout_ PULONG_PTR ShadowStack
    )
{
    PEPROCESS process;
    NTSTATUS status;
    BOOLEAN cetRelaxedMode;
    ULONG64 userRip;
    BOOLEAN notRelaxed;
    KCONTINUE_TYPE continueType;

    //
    // No need to do anything if shadow stack is not enabled
    //
    if (!Thread->Tcb.CetShadowStack)
    {
        return STATUS_SUCCESS;
    }

    //
    // No need to do anything if UserCetSetContextIpValidation is not
    // set in this process or if Rip is not being modified
    //
    process = Thread->Tcb.ApcState.Process;
    if (!(process->MitigationFlags2Values.UserCetSetContextIpValidation) ||
        !(BooleanFlagOn(Context->ContextFlags, CONTEXT_CONTROL)))
    {
        return STATUS_SUCCESS;
    }

    //
    // Verify the new Rip target
    //
    cetRelaxedMode = process->MitigationFlags2Values.UserCetSetContextIpValidationRelaxedMode & 1 != 0;
    status = KiVerifyContextIpForUserCet(Thread, Context, ContinueType, cetRelaxedMode, ShadowStack);

    //
    // Log failure if needed and fake success
    //
    if ( status == STATUS_SET_CONTEXT_DENIED )
    {
        userRip = Context->Rip;
        continueType = *ContinueType;
        notRelaxed = CetRelaxedMode ^ 1;
        if (!(process->MitigationFlags2Values.AuditUserCetSetContextIpValidation))
        {
            KiLogUserCetSetContextIpValidationFailure(2, continueType, userRip, notRelaxed);
            return status;
        }
        KiLogUserCetSetContextIpValidationFailure(1, continueType, userRip, notRelaxed);
    }
    return status;
}