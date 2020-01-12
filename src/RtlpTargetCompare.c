INT
RtlpTargetCompare (
    void* Context,
    const void* Key,
    const void* Datum
    )
{
    ULONG_PTR rva1;
    ULONG_PTR rva2;
    UNREFERENCED_PARAMETER(Context);
    rva1 = *(PULONG_PTR)Key;
    rva2 = *(PULONG_PTR)Datum;
    return (INT)(rva1 - rva2);
}