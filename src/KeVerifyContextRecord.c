NTSTATUS
KeVerifyContextRecord (
    _In_ PKTHREAD TargetThread,
    _In_ PCONTEXT ContextFrame
    _In_ PKCONTINUE_ARGUMENT ContinueArgument,
    _Outptr_ PULONG_PTR ShadowStack
    )
{
    PKPROCESS targetProcess;
    ULONG_PTR userStack;
    PTEB userTeb;
    PEWOW64PROCESS wow64Process;
    USHORT wowMachine;

    targetProcess = TargetThread->Process;
    if (targetProcess->CheckStackExtents != FALSE)
    {
        if (BooleanFlagOn(ContextFrame->ContextFlags, CONTEXT_CONTROL))
        {
            userStack = ContextFrame->Rsp;
            userTeb = TargetThread->Teb;

            //
            // Get the stack limits from the process' TEB and
            // check if the new stack pointer is inside the native stack
            //
            if (!RtlGuardIsValidStackPointer(userStack, userTeb))
            {
                //
                // New stack pointer is not inside the native stack.
                // Check if this is a wow64 process, and if it is
                // check if the new stack pointer is inside the wow64 stack.
                //
                wowMachine = PsWow64GetProcessMachine(targetProcess);
                if ((wowMachine != IMAGE_FILE_MACHINE_I386) &&
                    (wowMachine != IMAGE_FILE_MACHINE_ARMNT))
                {
                    return STATUS_INVALID_PARAMETER;
                }

                if ((userStack >= (_4GB - 1)) ||
                    !(RtlGuardIsValidWow64StackPointer(userStack, userTeb)))
                {
                    return STATUS_INVALID_PARAMETER;
                }

                //
                // Call KiVerifyContextRecord to validate the new values of CS and RIP
                //
                status = KiVerifyContextRecord(TargetThread,
                                               ContextFrame,
                                               ContinueArgument,
                                               ShadowStack);
            }
        }
    }

    //
    // If this is a non-wow64 process trying to set its CS to something
    // other than KGDT64_R3_CODE, force it to be KGDT64_R3_CODE.
    //
    if ((BooleanFlagOn(ContextFrame->ContextFlags, CONTEXT_CONTROL)) &&
        (PsWow64GetProcessMachine(targetProcess) != IMAGE_FILE_MACHINE_I386))
    {
        ContextFrame->SegCs = KGDT64_R3_CODE | RPL_MASK;
    }

    return STATUS_SUCCESS;
}