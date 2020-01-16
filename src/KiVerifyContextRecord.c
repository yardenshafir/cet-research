NTSTATUS
KiVerifyContextRecord (
    _In_ PKTHREAD TargetThread,
    _In_ PCONTEXT ContextFrame
    _In_ PKCONTINUE_ARGUMENT ContinueArgument,
    _Outptr_ PULONG_PTR ShadowStack
    )
{
    PKPROCESS process;

    process = Thread->Tcb.Process;

    //
    // If control registers (RIP/RSP) aren't beind modified, no checks to do
    //
    if (!BooleanFlagOn(ContextFrame->ContextFlags, CONTEXT_CONTROL))
    {
        return STATUS_SUCCESS;
    }

    //
    // If this is a non-wow64 process trying to set CS to a value other than KGDT64_R3_CODE,
    // Or this is a pico process trying to set CS to a value other than KGDT64_R3_CODE or 
    // KGDT64_R3_CMCODE, Force CS to be KGDT64_R3_CODE.
    //
    if ((PsWow64GetProcessMachine(process) != IMAGE_FILE_MACHINE_I386) &&
        ((process->PicoContext == NULL) ||
        (ContextFrame->SegCs != (KGDT64_R3_CMCODE | RPL_MASK))))
    {
        ContextFrame->SegCs = KGDT64_R3_CODE | RPL_MASK;
    }

    //
    // New context structure is not supported
    //
    if (!ARGUMENT_PRESENT(ContinueArgument))
    {
        return STATUS_SUCCESS;
    }

    //
    // Verify new RIP value in the shadow stack
    //
    status = KeVerifyContextIpForUserCet(TargetThread,
                                         ContextFrame,
                                         ContinueArgument,
                                         ShadowStack);
    if (NT_SUCCESS(status))
    {
        return STATUS_SUCCESS;
    }

    return status;
}
