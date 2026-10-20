/*
 * winzrt — kernel memory R/W driver (KMDF, data pointer hook mekanizmasi)
 *
 * Mekanizma: driver icinde bir MEM_OBJECT'e bakan data pointer slotu
 * (g_HookSlot) tutulur. Okuma/yazma IOCTL'lari slotu atomik olarak hedef
 * adrese cevirir (InterlockedExchangePointer) ve erisimi slotun Buffer
 * alanina yapar — yani R/W, hook'lanan veri isaretcisinden akar.
 * Slot her islemden sonra park nesnesine geri alinir; detach sonrasi
 * asla user adres tutmaz.
 *
 * IOCTL protokolu (METHOD_BUFFERED):
 *   IOCTL_WINZRT_READ    in: WINZRT_RW            out: ham veri (Size bayt)
 *   IOCTL_WINZRT_WRITE   in: WINZRT_RW + veri     out: -
 *   IOCTL_WINZRT_MODULE  in: WINZRT_MODULE_REQ    out: WINZRT_MODULE_RESP
 */
#include <ntifs.h>     // ntddk ustunde dosya/surec API'leri — KMDF wdf.h ile uyumlu
#include <wdf.h>

// admin + SYSTEM disinda kimse acamaz — stringi kendimiz tasiyoruz,
// Wdmsec.lib bagimliligi yok
DECLARE_CONST_UNICODE_STRING(g_Sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

#define DEVICE_NAME   L"\\Device\\winzrt"
#define SYMLINK_NAME  L"\\DosDevices\\winzrt"

#define WINZRT_MAX_COPY    (1u * 1024u * 1024u)   // tek islemde tavan: 1 MB
#define WINZRT_MAX_MODULES 512u                   // Ldr listesi siniri
#define WINZRT_MIN_ADDR    0x1000ULL              // sayfa altindaki adres yok

#define IOCTL_WINZRT_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINZRT_WRITE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINZRT_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* usermode ile birebir ayni olmali — pack 8, 24 bayt */
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

/*
 * Hook'lanan nesne. Slot bu yapinin Buffer alanina denk gelecek adrese
 * cevrilir: slot = address - FIELD_OFFSET(MEM_OBJECT, Buffer).
 * Boylece Buffer[0] hedef adresin ilk bayti olur.
 */
#define MEM_SHADOW      0x40
#define MEM_OBJECT_MAGIC 0x5A52545757524E4BULL   // "KNWRTRZa"

typedef struct _MEM_OBJECT {
    ULONG64 Magic;                  /* +0x00 sabit imza — park nesnesi dogrulamasi */
    ULONG64 Base;                   /* +0x08 retarget edilen adres */
    ULONG64 Size;                   /* +0x10 pencere */
    UCHAR   Buffer[MEM_SHADOW];     /* +0x18 erisim cipleri — R/W bu alana iner */
} MEM_OBJECT;

/* PEB / LDR — x64 layout, Ldr 0x18, InMemoryOrderLinks 0x10, DllBase 0x30 */
typedef struct _PEB_LDR_DATA_I {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
} PEB_LDR_DATA_I, *PPEB_LDR_DATA_I;

typedef struct _PEB_I {
    UCHAR           Reserved1[2];
    UCHAR           BeingDebugged;
    UCHAR           Reserved2[1];
    PVOID           Reserved3[2];
    PPEB_LDR_DATA_I Ldr;                    /* +0x18 */
} PEB_I, *PPEB_I;

typedef struct _LDR_ENTRY_I {
    LIST_ENTRY     InLoadOrderLinks;        /* +0x00 */
    LIST_ENTRY     InMemoryOrderLinks;      /* +0x10 */
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;                 /* +0x30 */
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_ENTRY_I, *PLDR_ENTRY_I;

NTKERNELAPI PVOID PsGetProcessPeb(PEPROCESS Process);

/* --- hook'lanan data pointer slotu ------------------------------------- */

static PVOID volatile g_HookSlot;        // tek entry point — sadece burasi cevrilir
static MEM_OBJECT     g_RestObject;      // park nesnesi — slot burada dinlenir

/* --- dogrulama: fail closed ------------------------------------------- */

static NTSTATUS ValidateRw(const WINZRT_RW* req, ULONG64 limit)
{
    if (req->Pid == 0 || req->Address < WINZRT_MIN_ADDR)
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

/* --- hook'u kullanarak okuma/yazma ------------------------------------- */

static NTSTATUS HookedCopy(
    PEPROCESS target,
    ULONG64  address,
    PVOID    buffer,        // read: cikti, write: kaynak (ikisi de kernel tampon)
    SIZE_T   size,
    BOOLEAN  write)
{
    KAPC_STATE apc;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID slotTarget = (PVOID)(ULONG_PTR)(address - FIELD_OFFSET(MEM_OBJECT, Buffer));

    KeStackAttachProcess(target, &apc);

    __try {
        /* data pointer hook: slotu hedef adrese cevir */
        InterlockedExchangePointer(&g_HookSlot, slotTarget);

        /* erisim slotun uzerinden — Buffer[0] hedef adresin ilk bayti */
        if (write)
            RtlCopyMemory(((MEM_OBJECT*)g_HookSlot)->Buffer, buffer, size);
        else
            RtlCopyMemory(buffer, ((MEM_OBJECT*)g_HookSlot)->Buffer, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();        // sayfa hatasi yutulur, surucu yasar
    }

    /* slotu park nesnesine geri al — detach sonrasi user adres kalmasin */
    InterlockedExchangePointer(&g_HookSlot, &g_RestObject);

    KeUnstackDetachProcess(&apc);
    return status;
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

/* --- KMDF IOCTL handler ------------------------------------------------ */

static VOID EvtIoDeviceControl(
    WDFQUEUE   Queue,
    WDFREQUEST Request,
    size_t     OutputBufferLength,
    size_t     InputBufferLength,
    ULONG      IoControlCode)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    PVOID inBuf = NULL;
    size_t inSize = 0;

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {

    case IOCTL_WINZRT_READ: {
        WINZRT_RW req;
        PVOID outBuf = NULL;
        size_t outSize = 0;
        PEPROCESS proc = NULL;

        status = WdfRequestRetrieveInputBuffer(
            Request, sizeof(WINZRT_RW), &inBuf, &inSize);
        if (!NT_SUCCESS(status))
            break;

        RtlCopyMemory(&req, inBuf, sizeof(req));   // header'i once al, cunku buffer uzerine veri yazilacak

        // cikti tamponu en az req.Size kadar olmali — kucukse WDF zaten BUFFER_TOO_SMALL doner
        status = WdfRequestRetrieveOutputBuffer(
            Request, (SIZE_T)req.Size, &outBuf, &outSize);
        if (!NT_SUCCESS(status))
            break;

        status = ValidateRw(&req, (ULONG64)outSize);
        if (!NT_SUCCESS(status))
            break;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.Pid, &proc);
        if (!NT_SUCCESS(status))
            break;

        status = HookedCopy(proc, req.Address, outBuf, (SIZE_T)req.Size, FALSE);

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_WINZRT_WRITE: {
        WINZRT_RW req;
        PEPROCESS proc = NULL;

        status = WdfRequestRetrieveInputBuffer(
            Request, sizeof(WINZRT_RW), &inBuf, &inSize);
        if (!NT_SUCCESS(status))
            break;

        RtlCopyMemory(&req, inBuf, sizeof(req));

        if (req.Size > WINZRT_MAX_COPY) {          // ikinci retrieve oncesi tavan kontrolu
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        // header + veri birlikte gelmeli
        status = WdfRequestRetrieveInputBuffer(
            Request, sizeof(WINZRT_RW) + (SIZE_T)req.Size, &inBuf, &inSize);
        if (!NT_SUCCESS(status))
            break;

        status = ValidateRw(&req, inSize - sizeof(WINZRT_RW));
        if (!NT_SUCCESS(status))
            break;

        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.Pid, &proc);
        if (!NT_SUCCESS(status))
            break;

        status = HookedCopy(proc, req.Address,
                            (UCHAR*)inBuf + sizeof(WINZRT_RW),
                            (SIZE_T)req.Size, TRUE);

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_WINZRT_MODULE: {
        WINZRT_MODULE_REQ req;
        WINZRT_MODULE_RESP resp = { 0 };
        PVOID outBuf = NULL;
        size_t outSize = 0;
        WCHAR name[260];

        status = WdfRequestRetrieveInputBuffer(
            Request, sizeof(WINZRT_MODULE_REQ), &inBuf, &inSize);
        if (!NT_SUCCESS(status))
            break;

        status = WdfRequestRetrieveOutputBuffer(
            Request, sizeof(WINZRT_MODULE_RESP), &outBuf, &outSize);
        if (!NT_SUCCESS(status))
            break;

        RtlCopyMemory(&req, inBuf, sizeof(req));

        if (req.Pid == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlCopyMemory(name, req.Name, sizeof(req.Name));
        name[259] = L'\0';                          // her durumda sonlandir

        status = GetModuleBase(req.Pid, name, &resp.Base);
        if (!NT_SUCCESS(status))
            break;

        RtlCopyMemory(outBuf, &resp, sizeof(resp));
        info = sizeof(resp);
        break;
    }

    default:
        break;                                      // status hala STATUS_INVALID_DEVICE_REQUEST
    }

    WdfRequestCompleteWithInformation(Request, status, info);
}

/* --- entry: legacy (non-PnP) control driver --------------------------- */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    UNICODE_STRING deviceName, symlink;
    NTSTATUS status;

    /* park nesnesini hazirla, slotu uzerine birak */
    RtlZeroMemory(&g_RestObject, sizeof(g_RestObject));
    g_RestObject.Magic = MEM_OBJECT_MAGIC;
    g_RestObject.Size  = MEM_SHADOW;
    InterlockedExchangePointer(&g_HookSlot, &g_RestObject);

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverPoolTag = 'wzrW';

    status = WdfDriverCreate(DriverObject, RegistryPath,
                             &attributes, &config, &driver);
    if (!NT_SUCCESS(status))
        return status;

    deviceInit = WdfControlDeviceInitAllocate(driver, &g_Sddl);
    if (deviceInit == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    status = WdfDeviceCreateSymbolicLink(device, &symlink);
    if (!NT_SUCCESS(status))
        return status;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
        return status;

    WdfControlFinishInitializing(device);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[winzrt] loaded (kmdf, dp-hook)\n");
    return STATUS_SUCCESS;
}
