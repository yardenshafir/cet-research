NTSTATUS
KiVerifyContextXStateCetUEnabled (
    _In_ PXSAVE_CET_U_FORMAT CetData,
    _In_ ULONG_PTR ShadowStack
    )
{
    MEMORY_REGION_INFORMATION regionInfo;
    ULONG_PTR shadowStackEnd;
    ULONG_PTR newShadowStack;

    //
    // If the value for the MSR mask is not 1 (CET enabled), deny the new context
    //
    if (CetData->Ia32CetUMsr != MSR_IA32_CET_SHSTK_EN)
    {
        return STATUS_SET_CONTEXT_DENIED;
    }

    //
    // Deny the context if the new Ssp value is not 8-byte aligned
    //
    newShadowStack = CetData->Ia32Pl3SspMsr;
    if ((newShadowStack & 7) != 0)
    {
        return STATUS_SET_CONTEXT_DENIED;
    }

    //
    // Check if the new Ssp is lower than the current Ssp, 
    // so it will point to uninitialized memory
    //
    if (newShadowStack < ShadowStack)
    {
        return STATUS_SET_CONTEXT_DENIED;
    }

    //
    // Get the end address of the shadow stack
    //
    ZwQueryVirtualMemory(NtCurrentProcess(),
                         ShadowStack,
                         MemoryRegionInformation,
                         &regionInfo,
                         sizeof(regionInfo),
                         NULL);
    shadowStackEnd = MemoryInformation.AllocationBase +
        MemoryInformation.RegionSize -
        PAGE_SIZE;

    //
    // Check if the new Ssp is higher than the end address of 
    // the shadiw stack, so outside the stack bounds
    //
    if (newShadowStack >= shadowStackEnd)
    {
        return STATUS_SET_CONTEXT_DENIED;
    }

    return STATUS_SUCCESS;
}