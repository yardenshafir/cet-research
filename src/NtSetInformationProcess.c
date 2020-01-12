NTSTATUS
NTAPI
NtSetInformationProcess (
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
    )
{
    PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION targetInfo;
    ULONG targetsSize;
    PPROCESS_DYNAMIC_EH_CONTINUATION_TARGET targetsArray;
    PPROCESS_DYNAMIC_EH_CONTINUATION_TARGET ehTargets;
    PEPROCESS targetProcess;
    NTSTATUS status;
    KPROCESSOR_MODE previousMode = ExGetPreviousMode();
    ULONG i;
    ULONG targetsProcessed;

    //
    // Handle the dynamic exception handlers information class
    //
    if (ProcessInformationClass == ProcessDynamicEHContinuationTargets)
    {
        //
        // Validate the data is the right size
        //
        if (ProcessInformationLength != sizeof(targetInfo))
        {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        //
        // Make a local copy of the data to avoid races
        //
        __try
        {
            targetInfo = *(PPROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION)ProcessInformation;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }

        //
        // Check how many targets there are
        //
        targetsSize = sizeof(PROCESS_DYNAMIC_EH_CONTINUATION_TARGET) *
            targetInfo.NumberOfTargets;
        if (targetsSize == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }

        //
        // Make sure there are targets
        //
        targetsArray = targetInfo.Targets;
        if (targetsArray == NULL)
        {
            return STATUS_INVALID_PARAMETER;
        }

        //
        // Probe that the targets are all in writeable UM memory
        //
        __try
        {
            ProbeForWrite(targetsArray, targetsSize, 8);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }

        //
        // These fields aren't used yet
        //
        if ((targetInfo.Reserved != 0) || (targetInfo.Reserved2 != 0))
        {
            return STATUS_INVALID_PARAMETER;
        }

        //
        // Only user-mode code should be setting dynamic EH targets
        //
        if (previousMode != UserMode)
        {
            return STATUS_ACCESS_DENIED;
        }

        //
        // Make sure the caller has a full process write handle to the target
        //
        targetProcess = NULL;
        status = ObReferenceObjectByHandle(ProcessHandle,
                                           GENERIC_WRITE & ~SYNCHRONIZE,
                                           (POBJECT_TYPE)PsProcessType,
                                           UserMode,
                                           (PVOID*)&targetProcess,
                                           NULL);
        if (!NT_SUCCESS(status))
        {
            goto Cleanup;
        }

        //
        // Don't allow the current process to add targets to itself
        //
        if (targetProcess == PsGetCurrentProcess())
        {
            status = STATUS_ACCESS_DENIED;
            goto Cleanup;
        }

        //
        // Don't allow setting EH handlers if the target process doesn't have CET
        //
        if (targetProcess->MitigationFlags2Values.CetUserShadowStacks == FALSE)
        {
            status = STATUS_NOT_SUPPORTED;
            goto Cleanup;
        }

        //
        // Allocate a kernel copy of the targets
        //
        ehTargets = ExAllocatePoolWithQuotaTag(PagedPool |
                                               POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
                                               targetsSize,
                                               'NHED');
        if (ehTargets == NULL)
        {
            status = STATUS_NO_MEMORY;
            goto Cleanup;
        }

        //
        // Copy them in the array
        //
        RtlCopyMemory(ehTargets, targetsArray, targetsSize);

        //
        // Process each target in the array
        //
        targetsProcessed = 0;
        status = PspProcessDynamicEHContinuationTargets(targetProcess,
                                                        ehTargets,
                                                        targetInfo.NumberOfTargets,
                                                        &targetsProcessed);

        //
        // Write out the flags back in the original user buffer, which will
        // basically fill set DYNAMIC_EH_CONTINUATION_TARGET_PROCESSED so the
        // caller knows what wasn't processed
        //
        __try
        {
            for (i = 0; i < targetsProcessed; i++)
            {
                targetsArray[i].Flags = ehTargets[i].Flags;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
        }

    Cleanup:
        //
        // Dereference the target process if needed
        //
        if (targetProcess != NULL)
        {
            ObDereferenceObject(targetProcess);
        }

        //
        // Free the EH target array if needed
        //
        if (ehTargets != NULL)
        {
            ExFreePoolWithTag(ehTargets, 'NHED');
        }
    }

    //
    // Return back to caller
    //
    return status;
}