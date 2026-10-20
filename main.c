/*
 * winzrt — kernel memory R/W driver (WDM, x64, Windows 10/11)
 *
 * IOCTL protokolu (METHOD_BUFFERED):
 *   IOCTL_WINZRT_READ    in: WINZRT_RW            out: ham veri (Size bayt)
 *   IOCTL_WINZRT_WRITE   in: WINZRT_RW + veri     out: -
 *   IOCTL_WINZRT_MODULE  in: WINZRT_MODULE_REQ    out: WINZRT_MODULE_RESP
 *
 * Okuma/yazma MmCopyVirtualMemory ile yapilir — hedef surece stack attach
 * edilmez, I/O manager'in kopya yolu kullanilir (yavas ama guvenli).
 * Modul tabani PEB Ldr listesi attach + __try ile gezilir.
 */
#include <ntddk.h>

#define DEVICE_NAME   L"\\Device\\winzrt"
#define SYMLINK_NAME  L"\\DosDevices\\winzrt"

#define WINZRT_MAX_COPY    (1u * 1024u * 1024u)   // tek islemde tavan: 1 MB
#define WINZRT_MAX_MODULES 512u                   // Ldr listesi siniri

#define IOCTL_WINZRT_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINZRT_WRITE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINZRT_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* usermode ile birebir ayni olmali — pack 8, 24+24+4+4 */
typedef struct _WINZRT_RW {
    ULONG64 Pid;
    ULONG64 Address;
    ULONG   Size;
    ULONG   Pad;
} WINZRT_RW;

typedef struct _WINZRT_MODULE_REQ {
    ULONG64 Pid;
    WCHAR   Name[260];
} WINZRT_MODULE_REQ;

typedef struct _WINZRT_MODULE_RESP {
    ULONG64 Base;
} WINZRT_MODULE_RESP;

/* PEB / LDR — x64 layout, Ldr 0x18, InMemoryOrderLinks 0x10, DllBase 0x30 */
typedef struct _PEB_LDR_DATA_I {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA_I, *PPEB_LDR_DATA_I;

typedef struct _PEB_I {
    UCHAR           Reserved1[2];
    UCHAR           BeingDebugged;
    UCHAR           Reserved2[1];
    PVOID           Reserved3[2];
    PPEB_LDR_DATA_I Ldr;                    /* +0x18 */
} PEB_I, *PPEB_I;

typedef struct _LDR_ENTRY_I {
    LIST_ENTRY    InLoadOrderLinks;         /* +0x00 */
    LIST_ENTRY    InMemoryOrderLinks;       /* +0x10 */
    LIST_ENTRY    InInitializationOrderLinks;
    PVOID         DllBase;                  /* +0x30 */
    PVOID         EntryPoint;
    ULONG         SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_ENTRY_I, *PLDR_ENTRY_I;

NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize);

NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);

/* --- dogrulama: fail closed ------------------------------------------- */

static NTSTATUS ValidateRw(const WINZRT_RW* req, ULONG64 limit)
{
    if (req->Pid == 0 || req->Address == 0)
        return STATUS_INVALID_PARAMETER;

    /* non-canonical adres araligi (bit 63:47 sign-extend olmali) */
    if (req->Address >= 0x0000800000000000ULL &&
        req->Address <  0xFFFF000000000000ULL)
        return STATUS_INVALID_ADDRESS;

    if (req->Size == 0 || req->Size > WINZRT_MAX_COPY)
        return STATUS_INVALID_BUFFER_SIZE;

    if ((ULONG64)req->Size > limit)
        return STATUS_BUFFER_TOO_SMALL;

    return STATUS_SUCCESS;
}

/* --- modul tabani: attach + PEB Ldr tarama ---------------------------- */

static NTSTATUS GetModuleBase(ULONG64 pid, const WCHAR* name, ULONG64* outBase)
{
    PEPROCESS proc = NULL;
    KAPC_STATE apc;
    SIZE_T walked = 0;
    NTSTATUS status;

    *outBase = 0;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(status))
        return status;

    KeStackAttachProcess(proc, &apc);

    __try {
        PPEB_I peb = (PPEB_I)PsGetProcessPeb(proc);
        if (peb != NULL && peb->Ldr != NULL) {
            PPEB_LDR_DATA_I ldr = peb->Ldr;
            PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
            UNICODE_STRING want;

            RtlInitUnicodeString(&want, name);

            for (PLIST_ENTRY e = head->Flink;
                 e != head && walked < WINZRT_MAX_MODULES;
                 e = e->Flink, ++walked)
            {
                PLDR_ENTRY_I ent = CONTAINING_RECORD(
                    e, LDR_ENTRY_I, InMemoryOrderLinks);

                if (ent->BaseDllName.Buffer != NULL &&
                    ent->BaseDllName.Length > 0 &&
                    RtlEqualUnicodeString(&ent->BaseDllName, &want, TRUE))
                {
                    *outBase = (ULONG64)ent->DllBase;
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        *outBase = 0;
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    return (*outBase != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* --- IOCTL handler ----------------------------------------------------- */

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    const ULONG code  = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {

    case IOCTL_WINZRT_READ: {
        WINZRT_RW req;
        PEPROCESS proc = NULL;
        SIZE_T copied = 0;

        if (buf == NULL || inLen < sizeof(WINZRT_RW)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(&req, buf, sizeof(req));   // header'i once al, cunku SystemBuffer'in uzerine veri yazilacak

        status = ValidateRw(&req, outLen);
        if (!NT_SUCCESS(status))
            break;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.Pid, &proc);
        if (!NT_SUCCESS(status))
            break;

        status = MmCopyVirtualMemory(
            proc,            (PVOID)(ULONG_PTR)req.Address,
            PsGetCurrentProcess(), buf,
            (SIZE_T)req.Size, KernelMode, &copied);

        ObDereferenceObject(proc);

        if (NT_SUCCESS(status) && copied != (SIZE_T)req.Size)
            status = STATUS_PARTIAL_COPY;

        info = (ULONG_PTR)copied;
        break;
    }

    case IOCTL_WINZRT_WRITE: {
        WINZRT_RW req;
        PEPROCESS proc = NULL;
        SIZE_T copied = 0;

        if (buf == NULL || inLen < sizeof(WINZRT_RW)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(&req, buf, sizeof(req));

        if (inLen < sizeof(WINZRT_RW) + (SIZE_T)req.Size) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = ValidateRw(&req, inLen - sizeof(WINZRT_RW));
        if (!NT_SUCCESS(status))
            break;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.Pid, &proc);
        if (!NT_SUCCESS(status))
            break;

        status = MmCopyVirtualMemory(
            PsGetCurrentProcess(), (UCHAR*)buf + sizeof(WINZRT_RW),
            proc, (PVOID)(ULONG_PTR)req.Address,
            (SIZE_T)req.Size, KernelMode, &copied);

        ObDereferenceObject(proc);

        if (NT_SUCCESS(status) && copied != (SIZE_T)req.Size)
            status = STATUS_PARTIAL_COPY;

        break;
    }

    case IOCTL_WINZRT_MODULE: {
        WINZRT_MODULE_REQ req;
        WINZRT_MODULE_RESP resp = { 0 };
        WCHAR name[260];

        if (buf == NULL || inLen < sizeof(WINZRT_MODULE_REQ) ||
            outLen < sizeof(WINZRT_MODULE_RESP)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(&req, buf, sizeof(req));

        if (req.Pid == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlCopyMemory(name, req.Name, sizeof(req.Name));
        name[259] = L'\0';                      // her durumda sonlandir

        status = GetModuleBase(req.Pid, name, &resp.Base);
        if (!NT_SUCCESS(status))
            break;

        RtlCopyMemory(buf, &resp, sizeof(resp));
        info = sizeof(resp);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* --- unload ------------------------------------------------------------ */

static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlink;

    UNREFERENCED_PARAMETER(DriverObject);

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (DriverObject->DeviceObject != NULL)
        IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[winzrt] unloaded\n");
}

/* --- entry ------------------------------------------------------------- */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING devName, symlink;
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;
    ULONG i;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symlink, SYMLINK_NAME);

    status = IoCreateDevice(
        DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status))
        return status;

    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
        DriverObject->MajorFunction[i] = DispatchCreateClose;

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[winzrt] loaded\n");
    return STATUS_SUCCESS;
}
