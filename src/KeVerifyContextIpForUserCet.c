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
    status = KiVerifyContextIpForUserCet(Thread, Context, ContinueType, ShadowStack);

    //
    // Audit failure if requested and fake success
    //
    if ((status == STATUS_SET_CONTEXT_DENIED) &&
        (process->MitigationFlags2Values.AuditUserCetSetContextIpValidation))
    {
        KiLogUserCetSetContextIpValidationAudit(*ContinueType);
        status = STATUS_SUCCESS;
    }
    return status;
}