INT
RtlpTargetCompare (
    _In_opt_ PVOID Context,
    _In_ PCVOID Key,
    _In_ PCVOID Datum
    )
{
    ULONG_PTR rva1;
    ULONG_PTR rva2;
    UNREFERENCED_PARAMETER(Context);
    
    //
    // Return if the compared RVA comes before (-1), after (+1), or identical (0)
    //
    rva1 = *(PULONG_PTR)Key;
    rva2 = *(PULONG_PTR)Datum;
    return (INT)(rva1 - rva2);
}

NTSTATUS
RtlVerifyUserUnwindTarget (
    _In_ PVOID TargetRip,
    _In_ KCONTINUE_TYPE ContinueType
    )
{
    PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig;
    INVERTED_FUNCTION_TABLE_ENTRY userFunctionTable;
    ULONGLONG imageSize;
    NTSTATUS status;
    ULONG guardFlags;
    SIZE_T configSize;
    PVOID table;
    ULONGLONG count;
    ULONG rva;
    SIZE_T metaSize;
    BOOLEAN found;
    PVOID entry;
    
    //
    // First, do a quick lookup in the user function table, which should almost always work
    //
    found = RtlpLookupUserFunctionTableInverted(TargetRip, &userFunctionTable);
    if (found == FALSE)
    {
        //
        // This module might not have any exception/unwind data, so do a slow VAD lookup instead
        //
        status = MmGetImageBase(TargetRip, &userFunctionTable.ImageBase, &imageSize);
        if (!NT_SUCCESS(status))
        {
            //
            // There does not appear to be a valid module loaded at this address.
            // The only other possibility is that this is JIT, which we'll handle at the end.
            //
            userFunctionTable.ImageBase = NULL;
        }
        else
        {
            //
            // The VAD lookup can theoretically return a >= 4GB-sized module. This is not expected
            // and not supported for actual PE images.
            //
            if (imageSize >= MAXULONG)
            {
                return STATUS_INTEGER_OVERFLOW;
            }
            //
            // To simplify the code, capture the size in the same structure that the user function
            // table lookup would've returned.
            //
            userFunctionTable.SizeOfImage = (ULONG)imageSize;
        }
    }
    
    //
    // Did we find a loaded module at this address?
    //
    if (userFunctionTable.ImageBase != NULL)
    {
        //
        // We're going to touch user-mode data, so enter an exception handler context
        //
        __try
        {
            //
            // Kind of an arbitrary probe of 64 bytes, since the call below will call
            // RtlImageNtHeaderEx which does a proper probe of the whole header already.
            //
            ProbeForRead(userFunctionTable.ImageBase, 64, 1);
            
            //
            // Get the Image Load Config Directory. Note that this is a user-mode pointer
            //
            loadConfig = LdrImageDirectoryEntryToLoadConfig(userFunctionTable.ImageBase);
            
            //
            // For longjmp, use the longjump table, otherwise, for unwind, use the dynamic
            // exception handler continuation table.
            //
            if (ContinueType == KCONTINUE_LONGJUMP)
            {
                guardFlags = IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT;
                configSize = RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64,
                                                      GuardLongJumpTargetTable);
            }
            else
            {
                guardFlags = IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT;
                configSize = RTL_SIZEOF_THROUGH_FIELD(IMAGE_LOAD_CONFIG_DIRECTORY64,
                                                      GuardEHContinuationTable);
            }
            //
            // Probe the configuration directory, as LdrImageDirectoryEntryToLoadConfig only
            // probes the first 4 bytes to account for the "Size" field.
            //
            // This probe will also raise if loadConfig is NULL (unless this is NTVDM on 32-bit).
            //
            ProbeForRead(loadConfig, configSize, 1);
            
            //
            // Make sure there's a load configuration directory, that it's large enough to have
            // one of the two tables we care about, and that the guard flags indicate that the
            // table we care about is actually present.
            //
            if ((loadConfig == NULL) ||
                (loadConfig->Size < configSize) ||
                !(guardFlags & loadConfig->GuardFlags))
            {
                //
                // We return success here, because this means that the binary is not compatible
                // with CET. As such, for compatibility, allow this jump target.
                //
                return STATUS_SUCCESS;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            //
            // Something's wrong with the user address space, bail out
            //
            return GetExceptionCode();
        }
        
        //
        // Use the correct table and count (longjmp vs. unwind)
        //
        if (ContinueType == KCONTINUE_LONGJUMP)
        {
            table = (PVOID)loadConfig->GuardLongJumpTargetTable;
            count = loadConfig->GuardLongJumpTargetCount;
        }
        else
        {
            table = (PVOID)loadConfig->GuardEHContinuationTable;
            count = loadConfig->GuardEHContinuationCount;
        }
        
        //
        // More than 4 billion entries are not allowed
        //
        if (count >= MAXULONG)
        {
            return STATUS_INTEGER_OVERFLOW;
        }
        
        //
        // If the table is empty, then there can't be any valid targets in this image...
        //
        if (count != 0)
        {
            //
            // PE Images are always <= 4GB, so compute the 32-bit RVA
            //
            rva = (ULONG)((ULONG_PTR)TargetRip - (ULONG_PTR)userFunctionTable.ImageBase);
            
            //
            // The guard tables can have n-bytes of metadata, indicated by the upper nibble
            //
            metaSize = loadConfig->GuardFlags >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
            
            //
            // Search through the guard table for this RVA
            //
            entry = bsearch_s(&rva, table, count, metaSize + sizeof(rva), RtlpTargetCompare, NULL);
            if (entry != NULL)
            {
                //
                // The entry was found, so this is a valid target
                //
                return STATUS_SUCCESS;
            }
        }
    }
    
    //
    // Either there's no valid image mapped at this address, or there is, but its relevant guard
    // table does not contain the target RIP requested (as a reminder, if there's no table, then
    // the target _is_ allowed, for compatibility reasons).
    //
    // In this case, for exception unwinding (and obviously not longjmp), check if there is a
    // JIT-ted (dynamic) exception handler continuation target registered at this target.
    //
    if (ContinueType == KCONTINUE_UNWIND)
    {
        found = RtlpFindDynamicEHContinuationTarget(TargetRip);
        if (found != FALSE)
        {
            return STATUS_SUCCESS;
        }
    }
    
    //
    // Otherwise, we either didn't find a dynamic handler, or this wasn't an unwind to begin with,
    // so fail the request.
    //
    return STATUS_SET_CONTEXT_DENIED;
}
