# spooofer

Vou te dar o caminho completo, na ordem, com tudo pronto para copiar e colar. Duas coisas antes de começar, para você não se perder depois:

1. **Você vai compilar um driver de kernel.** Não precisa entender o código, mas precisa copiar exatamente como está. Um caractere trocado gera erro de compilação.
2. **Com test signing ligado, o Valorant provavelmente vai acusar erro `VAN`.** O código já inclui um módulo que mascara isso (Parte 4), mas se ele não pegar na sua build do Windows, o spoof funciona e o jogo reclama. Explico o que fazer na Parte 11.

Tempo estimado: 1h30 a 2h, contando downloads.

```mermaid
flowchart LR
    A[Instalar VS + WDK] --> B[Criar projeto] --> C[Colar código] --> D[Compilar] --> E[Snapshot do HWID] --> F[Rodar instalador] --> G[Reiniciar] --> H[Conferir HWID] --> I[Abrir o jogo]
```

---

# PARTE 0 — O que você precisa ter

- Windows 10 ou 11, 64 bits, com conta de Administrador.
- ~15 GB livres (Visual Studio é grande).
- **Ponto de restauração do sistema ativo** (recomendo criar um manualmente antes: Menu Iniciar → "Criar um ponto de restauração").
- Acesso à BIOS, caso algo dê errado no boot.

---

# PARTE 1 — Criar as pastas

Abra o PowerShell **como Administrador** (Menu Iniciar → digite `powershell` → clique direito → Executar como administrador) e cole:

```powershell
New-Item -ItemType Directory C:\spoofer -Force
New-Item -ItemType Directory C:\spoofer\driver -Force
New-Item -ItemType Directory C:\spoofer\src -Force
New-Item -ItemType Directory C:\spoofer\backup -Force
```

No final você deve ter `C:\spoofer\driver`, `C:\spoofer\src` e `C:\spoofer\backup`.

---

# PARTE 2 — Instalar o Visual Studio e o WDK

1. Baixe o **Visual Studio 2022 Community**: https://visualstudio.microsoft.com/pt-br/downloads/
2. No instalador, marque **"Desenvolvimento para desktop com C++"**. Avance e instale.
3. Depois de instalar o VS, baixe o **WDK** (Windows Driver Kit) na mesma versão do SDK: https://learn.microsoft.com/pt-br/windows-hardware/drivers/download-the-wdk
4. Rode o instalador do WDK. Ele instala o SDK e as extensões de driver no VS automaticamente.

Feche tudo ao terminar. **Não abra o VS antes de o WDK estar instalado** — a extensão só aparece depois.

---

# PARTE 3 — Criar o projeto

1. Abra o Visual Studio → **Criar novo projeto**.
2. Procure por **"Empty WDM Driver"** → selecione → **Avançar**.
3. Nome do projeto: **`spoofer`** (exatamente assim, minúsculo).
4. Local: `C:\spoofer\src`
5. Criar.

Agora, no **Gerenciador de Soluções** (painel da direita):

6. Clique com o botão direito em `Driver.c` → **Excluir**.
7. Clique com o botão direito em `spoofer.inf` → **Excluir** (mas anote: o arquivo fica na pasta `C:\spoofer\src\spoofer.inf` — vamos recriar).
8. Barra de ferramentas superior: troque **Debug** por **Release** e **x64** por **x64** (já vem x64, confirme).
9. Botão direito no projeto `spoofer` → **Propriedades** → **Driver Settings** → **General** → em *Target OS Version* selecione **Windows 10 or higher** → OK.

---

# PARTE 4 — Colar o código

## 4.1 O arquivo do driver

Botão direito no projeto → **Adicionar** → **Novo Item** → **Arquivo C++ (.cpp)** → nome `spoofer.c` (com `.c`, não `.cpp`) → Adicionar.

Apague o conteúdo e cole **tudo** isto:

```c
// spoofer.c — driver unico: dispositivo de controle + filtro de disco/volume + spoof
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntddstor.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <wdmsec.h>

#pragma comment(lib, "wdmsec.lib")
#pragma warning(disable: 4100 4189)

#define SPOOFER_DEV   L"\\Device\\Spoofer"
#define SPOOFER_LINK  L"\\DosDevices\\Spoofer"
#define SPOOF_PARAMS  L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\spoofer\\Parameters"
#define MAXS 48
#define MINV(a,b) ((a) < (b) ? (a) : (b))

#define IOCTL_APPLY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESTORE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_QUERY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum { KIND_CONTROL = 1, KIND_FILTER = 2 } DEVKIND;

typedef struct _PROFILE {
    BOOLEAN Active;
    CHAR  DiskSerial[24];
    CHAR  NvmeSerial[24];
    ULONG VolumeSerial;
    WCHAR MachineGuid[MAXS];
    WCHAR HwProfileGuid[MAXS];
    WCHAR BiosSerial[MAXS];
    WCHAR SysSerial[MAXS];
    WCHAR SysUuid[40];
    WCHAR BoardSerial[MAXS];
    WCHAR SysVendor[MAXS];
    WCHAR SysProduct[MAXS];
} PROFILE;

typedef struct _DEXT {
    DEVKIND Kind;
    PDEVICE_OBJECT Self;
    PDEVICE_OBJECT Lower;
} DEXT;

static PROFILE  g_P;
static ERESOURCE g_Lock;
static BOOLEAN  g_SmbiosDone = FALSE;
static PUCHAR   g_CiOptions = NULL;
static PDEVICE_OBJECT g_CtlDev = NULL;

static NTSTATUS DispatchAny(PDEVICE_OBJECT, PIRP);
static NTSTATUS AddDevice(PDRIVER_OBJECT, PDEVICE_OBJECT);
static VOID     Unload(PDRIVER_OBJECT);
static VOID     LoadProfile(VOID);
static VOID     SpoofSmbios(VOID);
static VOID     SpoofRegistry(VOID);
static VOID     DseClear(VOID);
static VOID     DseRestore(VOID);

// ---------------- utilitarios ----------------
static ULONG StrLenA(PCSTR s) { ULONG n = 0; if (!s) return 0; while (s[n]) n++; return n; }

static VOID W2A(PWSTR w, PCHAR a, ULONG aChars)
{
    ULONG i;
    for (i = 0; i + 1 < aChars && w[i]; i++) a[i] = (CHAR)w[i];
    a[i] = 0;
}

// ---------------- leitura do perfil no registro ----------------
static NTSTATUS ReadReg(PCWSTR Value, PVOID Out, ULONG OutLen, PULONG TypeOut)
{
    UNICODE_STRING u, vn;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;
    NTSTATUS st;
    UCHAR buf[600];
    ULONG len = 0;
    PKEY_VALUE_PARTIAL_INFORMATION kv = (PKEY_VALUE_PARTIAL_INFORMATION)buf;

    RtlInitUnicodeString(&u, SPOOF_PARAMS);
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&h, KEY_READ, &oa);
    if (!NT_SUCCESS(st)) return st;

    RtlInitUnicodeString(&vn, Value);
    st = ZwQueryValueKey(h, &vn, KeyValuePartialInformation, buf, sizeof(buf), &len);
    ZwClose(h);
    if (!NT_SUCCESS(st)) return st;
    if (kv->DataLength > OutLen) return STATUS_BUFFER_TOO_SMALL;

    RtlCopyMemory(Out, kv->Data, kv->DataLength);
    if (TypeOut) *TypeOut = kv->Type;
    return STATUS_SUCCESS;
}

static VOID ReadRegStr(PCWSTR Value, PWSTR Out, ULONG OutChars)
{
    WCHAR tmp[256];
    ULONG t = 0;
    Out[0] = 0;
    if (!NT_SUCCESS(ReadReg(Value, tmp, sizeof(tmp) - sizeof(WCHAR), &t))) return;
    if (t != REG_SZ) return;
    tmp[255] = 0;
    RtlStringCchCopyW(Out, OutChars, tmp);
}

static ULONG ReadRegDword(PCWSTR Value, ULONG Default)
{
    ULONG v = 0, t = 0;
    if (!NT_SUCCESS(ReadReg(Value, &v, sizeof(v), &t))) return Default;
    if (t != REG_DWORD) return Default;
    return v;
}

static VOID LoadProfile(VOID)
{
    WCHAR tmp[MAXS];
    RtlZeroMemory(&g_P, sizeof(g_P));
    g_P.Active = (ReadRegDword(L"Active", 0) != 0);
    if (!g_P.Active) return;

    ReadRegStr(L"DiskSerial", tmp, MAXS);      W2A(tmp, g_P.DiskSerial, 24);
    ReadRegStr(L"NvmeSerial", tmp, MAXS);      W2A(tmp, g_P.NvmeSerial, 24);
    g_P.VolumeSerial = ReadRegDword(L"VolumeSerial", 0x1234ABCD);
    ReadRegStr(L"MachineGuid", g_P.MachineGuid, MAXS);
    ReadRegStr(L"HwProfileGuid", g_P.HwProfileGuid, MAXS);
    ReadRegStr(L"BiosSerial", g_P.BiosSerial, MAXS);
    ReadRegStr(L"SysSerial", g_P.SysSerial, MAXS);
    ReadRegStr(L"SysUuid", g_P.SysUuid, 40);
    ReadRegStr(L"BoardSerial", g_P.BoardSerial, MAXS);
    ReadRegStr(L"SysVendor", g_P.SysVendor, MAXS);
    ReadRegStr(L"SysProduct", g_P.SysProduct, MAXS);
}

// ---------------- SMBIOS ----------------
typedef struct { UCHAR Type; UCHAR Len; USHORT Handle; } SMBIOS_HDR;

static VOID FixSum(PUCHAR s)
{
    UCHAR sum = 0;
    UCHAR i;
    s[4] = 0;
    for (i = 0; i < s[1]; i++) sum += s[i];
    s[4] = (UCHAR)(0x100 - sum);
}

static VOID ReplaceStr(PUCHAR s, UCHAR idx, PCSTR nw)
{
    PUCHAR p;
    SIZE_T oldLen, newLen;
    UCHAR i;
    if (!idx || idx >= s[1] || !nw) return;
    p = s + s[1];
    for (i = 1; i < idx; i++) p += StrLenA((PCSTR)p) + 1;
    oldLen = StrLenA((PCSTR)p);
    newLen = StrLenA(nw);
    if (newLen > oldLen) return;
    RtlCopyMemory(p, nw, newLen);
    RtlFillMemory(p + newLen, oldLen - newLen, ' ');
}

static VOID SpoofSmbios(VOID)
{
    PUCHAR base, ep = NULL, tbl, s;
    PHYSICAL_ADDRESS pa;
    ULONG tableLen = 0, o;
    UCHAR uuid[16];

    base = MmMapIoSpaceEx(0xF0000, 0x10000, PAGE_READWRITE | PAGE_NOCACHE);
    if (!base) return;

    for (o = 0; o < 0xFFF0; o += 16)
        if (base[o]=='_' && base[o+1]=='S' && base[o+2]=='M' && base[o+3]=='3' && base[o+4]=='_')
            { ep = base + o; break; }

    pa.QuadPart = 0;
    if (ep) {
        ULONGLONG a = 0;
        RtlCopyMemory(&a, ep + 0x10, sizeof(a));
        RtlCopyMemory(&tableLen, ep + 0x0C, sizeof(ULONG));
        pa.QuadPart = a;
    } else {
        for (o = 0; o < 0xFFF0; o += 16)
            if (base[o]=='_' && base[o+1]=='S' && base[o+2]=='M' && base[o+3]=='_')
                { ep = base + o; break; }
        if (!ep) { MmUnmapIoSpace(base, 0x10000); return; }
        {
            ULONG a32 = 0;
            RtlCopyMemory(&a32, ep + 0x18, sizeof(a32));
            pa.QuadPart = a32;
        }
        tableLen = (ULONG)ep[0x16] * 16;
    }
    if (!tableLen || tableLen > 0x20000) tableLen = 0x10000;

    tbl = MmMapIoSpaceEx(pa, tableLen, PAGE_READWRITE | PAGE_NOCACHE);
    if (!tbl) { MmUnmapIoSpace(base, 0x10000); return; }

    // UUID: string hex de 32 chars -> 16 bytes
    RtlZeroMemory(uuid, 16);
    for (o = 0; o < 32 && g_P.SysUuid[o]; o++) {
        UCHAR c = (UCHAR)g_P.SysUuid[o];
        UCHAR v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        uuid[o / 2] = (o & 1) ? (UCHAR)(uuid[o/2] | v) : (UCHAR)(v << 4);
    }

    s = tbl;
    while (s + 4 < tbl + tableLen && s[0] != 0x7F) {
        SMBIOS_HDR* h = (SMBIOS_HDR*)s;
        if (h->Len < 4) break;

        switch (h->Type) {
        case 0:
            ReplaceStr(s, s[0x07], (PCSTR)g_P.BiosSerial);
            break;
        case 1:
            ReplaceStr(s, s[0x04], (PCSTR)g_P.SysVendor);
            ReplaceStr(s, s[0x05], (PCSTR)g_P.SysProduct);
            ReplaceStr(s, s[0x07], (PCSTR)g_P.SysSerial);
            if (h->Len > 0x18) {
                RtlCopyMemory(s + 0x08, uuid, 16);
                s[0x08 + 7] = (UCHAR)((s[0x08 + 7] & 0x0F) | 0x40);
            }
            break;
        case 2:
            ReplaceStr(s, s[0x07], (PCSTR)g_P.BoardSerial);
            break;
        case 17:
            ReplaceStr(s, s[0x11], (PCSTR)g_P.DiskSerial);
            break;
        default:
            break;
        }
        FixSum(s);

        {
            PUCHAR p = s + h->Len;
            while (*p || *(p + 1)) p++;
            s = p + 2;
        }
    }

    MmUnmapIoSpace(tbl, tableLen);
    MmUnmapIoSpace(base, 0x10000);
}

// ---------------- registro ----------------
static NTSTATUS WriteSz(PCWSTR Path, PCWSTR Value, PCWSTR Data)
{
    UNICODE_STRING u, vn, vd;
    OBJECT_ATTRIBUTES oa;
    HANDLE h;
    NTSTATUS st;

    RtlInitUnicodeString(&u, Path);
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&h, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(st)) return st;
    RtlInitUnicodeString(&vn, Value);
    RtlInitUnicodeString(&vd, Data);
    st = ZwSetValueKey(h, &vn, 0, REG_SZ, vd.Buffer, vd.MaximumLength);
    ZwClose(h);
    return st;
}

static VOID SpoofRegistry(VOID)
{
    WriteSz(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography",
            L"MachineGuid", g_P.MachineGuid);
    WriteSz(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
            L"HwProfileGuid", g_P.HwProfileGuid);
}

// ---------------- mascara de test signing ----------------
typedef struct _MOD_INFO {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrder;
    USHORT InitOrder;
    USHORT LoadCount;
    USHORT OffsetToName;
    UCHAR  FullPath[256];
} MOD_INFO, *PMOD_INFO;

typedef struct _MODS { ULONG Count; MOD_INFO List[1]; } MODS, *PMODS;

extern NTSTATUS NTAPI ZwQuerySystemInformation(ULONG, PVOID, ULONG, PULONG);

static ULONG CiStrLen(PCSTR s) { ULONG n = 0; while (s[n]) n++; return n; }

static PUCHAR FindCiOptions(VOID)
{
    ULONG size = 0x20000;
    PMODS mods = NULL;
    PUCHAR base = NULL;
    ULONG imgSize = 0;
    NTSTATUS st;
    ULONG i;

    mods = ExAllocatePoolWithTag(NonPagedPoolNx, size, 'mSfV');
    if (!mods) return NULL;
    st = ZwQuerySystemInformation(11, mods, size, &size);
    if (!NT_SUCCESS(st)) { ExFreePool(mods); return NULL; }

    for (i = 0; i < mods->Count; i++) {
        PCSTR n = (PCSTR)mods->List[i].FullPath;
        ULONG l = CiStrLen(n);
        if (l >= 6) {
            PCSTR t = n + l - 6;
            if ((t[0]|0x20)=='c' && (t[1]|0x20)=='i' && t[2]=='.' &&
                (t[3]|0x20)=='d' && (t[4]|0x20)=='l' && (t[5]|0x20)=='l') {
                base = (PUCHAR)mods->List[i].ImageBase;
                imgSize = mods->List[i].ImageSize;
                break;
            }
        }
    }
    ExFreePool(mods);
    if (!base || imgSize < 0x1000) return NULL;

    {
        PUCHAR p = base, end = base + imgSize - 16;
        for (; p < end; p++) {
            if (p[0] == 0x48 && p[1] == 0x8D && p[2] == 0x0D) {
                PUCHAR cand = p + 7 + *(INT32*)(p + 3);
                ULONG v = *(ULONG*)cand;
                if (v <= 0x1FF && (v & 0x2)) return cand;
            }
        }
    }
    return NULL;
}

static VOID WpOff(VOID)  { _writecr0(__readcr0() & ~0x10000); }
static VOID WpOn(VOID)   { _writecr0(__readcr0() | 0x10000); }

static VOID DseClear(VOID)
{
    KIRQL old;
    if (!g_CiOptions) g_CiOptions = FindCiOptions();
    if (!g_CiOptions) return;
    old = KeRaiseIrqlToDpcLevel();
    WpOff();
    *(ULONG*)g_CiOptions &= ~0x2;
    WpOn();
    KeLowerIrql(old);
}

static VOID DseRestore(VOID)
{
    KIRQL old;
    if (!g_CiOptions) return;
    old = KeRaiseIrqlToDpcLevel();
    WpOff();
    *(ULONG*)g_CiOptions |= 0x2;
    WpOn();
    KeLowerIrql(old);
}

// ---------------- patches de storage ----------------
static VOID PatchStorage(PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PSTORAGE_PROPERTY_QUERY q = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;
    PVOID out = Irp->AssociatedIrp.SystemBuffer;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG sl;

    if (!q || !out) return;
    if (outLen < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return;

    if (q->PropertyId == StorageDeviceProperty) {
        PSTORAGE_DEVICE_DESCRIPTOR d = (PSTORAGE_DEVICE_DESCRIPTOR)out;
        if (!d->SerialNumberOffset || d->SerialNumberOffset >= outLen) return;
        sl = StrLenA(g_P.DiskSerial) + 1;
        if ((ULONG)d->Size + sl > outLen) return;
        RtlCopyMemory((PUCHAR)out + d->Size, g_P.DiskSerial, sl);
        d->SerialNumberOffset = d->Size;
        d->Size = (ULONG)(d->Size + sl);
    } else if (q->PropertyId == StorageDeviceProtocolSpecificProperty) {
        PSTORAGE_PROTOCOL_DATA_DESCRIPTOR pd = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)out;
        PUCHAR id;
        if (pd->ProtocolSpecificData.ProtocolType != ProtocolTypeNvme) return;
        if (pd->ProtocolSpecificData.DataType != NVMeDataTypeIdentify) return;
        if ((ULONG)pd->ProtocolSpecificData.ProtocolDataOffset + 24 > outLen) return;
        id = (PUCHAR)out + pd->ProtocolSpecificData.ProtocolDataOffset;
        RtlFillMemory(id + 4, 20, ' ');
        RtlCopyMemory(id + 4, g_P.NvmeSerial, MINV(StrLenA(g_P.NvmeSerial), 20));
    }
}

static VOID PatchAta(PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PATA_PASS_THROUGH_EX a = (PATA_PASS_THROUGH_EX)Irp->AssociatedIrp.SystemBuffer;
    PUCHAR id;

    if (!a) return;
    if (a->CurrentTaskFile[6] != 0xEC) return;
    if (a->DataTransferLength < 512) return;
    if ((ULONG)a->DataBufferOffset + 512 > sp->Parameters.DeviceIoControl.OutputBufferLength) return;
    id = (PUCHAR)a + a->DataBufferOffset;
    RtlFillMemory(id + 20, 20, ' ');
    RtlCopyMemory(id + 20, g_P.DiskSerial, MINV(StrLenA(g_P.DiskSerial), 20));
}

static NTSTATUS PatchDone(PDEVICE_OBJECT DevObj, PIRP Irp, PVOID Ctx)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    if (NT_SUCCESS(Irp->IoStatus.Status)) {
        if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY)
            PatchStorage(Irp);
        else
            PatchAta(Irp);
    }
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_SUCCESS;
}

static NTSTATUS VolDone(PDEVICE_OBJECT DevObj, PIRP Irp, PVOID Ctx)
{
    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->AssociatedIrp.SystemBuffer)
        ((PFILE_FS_VOLUME_INFORMATION)Irp->AssociatedIrp.SystemBuffer)->VolumeSerialNumber = g_P.VolumeSerial;
    if (Irp->PendingReturned) IoMarkIrpPending(Irp);
    return STATUS_SUCCESS;
}

// ---------------- dispatch ----------------
static NTSTATUS DispatchAny(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    DEXT* e = (DEXT*)DevObj->DeviceExtension;
    NTSTATUS st = STATUS_SUCCESS;

    if (e && e->Kind == KIND_FILTER) {
        if (sp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
            ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
            if (g_P.Active && (code == IOCTL_STORAGE_QUERY_PROPERTY || code == IOCTL_ATA_PASS_THROUGH)) {
                IoCopyCurrentIrpStackLocationToNext(Irp);
                IoSetCompletionRoutine(Irp, PatchDone, NULL, TRUE, TRUE, TRUE);
                return IoCallDriver(e->Lower, Irp);
            }
        } else if (sp->MajorFunction == IRP_MJ_QUERY_VOLUME_INFORMATION) {
            if (g_P.Active && sp->Parameters.QueryVolume.FsInformationClass == FileFsVolumeInformation) {
                IoCopyCurrentIrpStackLocationToNext(Irp);
                IoSetCompletionRoutine(Irp, VolDone, NULL, TRUE, TRUE, TRUE);
                return IoCallDriver(e->Lower, Irp);
            }
        } else if (sp->MajorFunction == IRP_MJ_PNP && sp->MinorFunction == IRP_MN_REMOVE_DEVICE) {
            IoSkipCurrentIrpStackLocation(Irp);
            st = IoCallDriver(e->Lower, Irp);
            IoDetachDevice(e->Lower);
            IoDeleteDevice(DevObj);
            return st;
        } else if (sp->MajorFunction == IRP_MJ_POWER) {
            PoStartNextPowerIrp(Irp);
            IoSkipCurrentIrpStackLocation(Irp);
            return PoCallDriver(e->Lower, Irp);
        }
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(e->Lower, Irp);
    }

    switch (sp->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    case IRP_MJ_DEVICE_CONTROL:
        switch (sp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_APPLY:
            ExAcquireResourceExclusiveLite(&g_Lock, TRUE);
            LoadProfile();
            if (g_P.Active) {
                if (!g_SmbiosDone) { SpoofSmbios(); g_SmbiosDone = TRUE; }
                SpoofRegistry();
                DseClear();
            }
            ExReleaseResourceLite(&g_Lock);
            break;
        case IOCTL_RESTORE:
            g_P.Active = FALSE;
            DseRestore();
            break;
        case IOCTL_QUERY:
            if (sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(PROFILE)) {
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &g_P, sizeof(PROFILE));
                Irp->IoStatus.Information = sizeof(PROFILE);
            } else st = STATUS_BUFFER_TOO_SMALL;
            break;
        default:
            st = STATUS_INVALID_DEVICE_REQUEST;
        }
        break;
    case IRP_MJ_PNP:
        break;
    case IRP_MJ_POWER:
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = STATUS_SUCCESS;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    default:
        break;
    }

    Irp->IoStatus.Status = st;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static NTSTATUS AddDevice(PDRIVER_OBJECT Drv, PDEVICE_OBJECT Pdo)
{
    PDEVICE_OBJECT fdo = NULL;
    DEXT* e;
    NTSTATUS st;

    st = IoCreateDevice(Drv, sizeof(DEXT), NULL, Pdo->DeviceType,
                        Pdo->Characteristics, FALSE, &fdo);
    if (!NT_SUCCESS(st)) return st;

    e = (DEXT*)fdo->DeviceExtension;
    e->Kind = KIND_FILTER;
    e->Self = fdo;
    fdo->Flags |= Pdo->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);

    e->Lower = IoAttachDeviceToDeviceStack(fdo, Pdo);
    if (!e->Lower) { IoDeleteDevice(fdo); return STATUS_NO_SUCH_DEVICE; }

    fdo->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static VOID Unload(PDRIVER_OBJECT Drv)
{
    UNICODE_STRING link;
    RtlInitUnicodeString(&link, SPOOFER_LINK);
    IoDeleteSymbolicLink(&link);
    if (g_CtlDev) { IoDeleteDevice(g_CtlDev); g_CtlDev = NULL; }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT Drv, PUNICODE_STRING RegPath)
{
    NTSTATUS st;
    UNICODE_STRING name, link;
    DECLARE_CONST_UNICODE_STRING(sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    ULONG i;

    UNREFERENCED_PARAMETER(RegPath);

    ExInitializeResourceLite(&g_Lock);
    RtlZeroMemory(&g_P, sizeof(g_P));

    RtlInitUnicodeString(&name, SPOOFER_DEV);
    RtlInitUnicodeString(&link, SPOOFER_LINK);

    st = IoCreateDeviceSecure(Drv, sizeof(DEXT), &name, FILE_DEVICE_UNKNOWN,
                              FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, NULL, &g_CtlDev);
    if (!NT_SUCCESS(st)) return st;
    ((DEXT*)g_CtlDev->DeviceExtension)->Kind = KIND_CONTROL;

    st = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(g_CtlDev); return st; }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        Drv->MajorFunction[i] = DispatchAny;

    Drv->DriverExtension->AddDevice = AddDevice;
    Drv->DriverUnload = Unload;

    g_CtlDev->Flags &= ~DO_DEVICE_INITIALIZING;

    LoadProfile();
    if (g_P.Active) {
        SpoofSmbios();
        g_SmbiosDone = TRUE;
        SpoofRegistry();
        DseClear();
    }
    return STATUS_SUCCESS;
}
```

## 4.2 O arquivo INF

No Gerenciador de Soluções, botão direito no projeto → **Adicionar** → **Novo Item** → **Arquivo de texto** → nome `spoofer.inf` → Adicionar. Cole:

```inf
[Version]
Signature="$WINDOWS NT$"
Class=System
ClassGuid={4D36E97D-E325-11CE-BFC1-08002BE10318}
Provider=%PROV%
CatalogFile=spoofer.cat
DriverVer=11/26/2026,1.0.0.0

[DestinationDirs]
DefaultDestDir=12

[Manufacturer]
%PROV%=Venice,NTamd64

[Venice.NTamd64]
%DEVICE%=Install, root\spoofer

[Install.NT]
CopyFiles=@spoofer.sys

[Install.NT.Services]
AddService=spoofer,0x00000002,Service

[Service]
ServiceType=1
StartType=0
ErrorControl=1
ServiceBinary=%12%\spoofer.sys
Group=Boot Bus Extender

[Strings]
PROV="Venice"
DEVICE="Venice HWID Spoofer"
```

**Confira**: o arquivo está em `C:\spoofer\src\spoofer.inf` e o `spoofer.c` está no projeto. Se o VS criou um `spoofer.inf` duplicado, deixe só o seu.

---

# PARTE 5 — Compilar

1. Menu **Compilar** → **Compilar Solução** (ou Ctrl+Shift+B).
2. Deve terminar com `0 Erro(s)`. Avisos pode ignorar.
3. O arquivo gerado está em `C:\spoofer\src\x64\Release\spoofer\spoofer.sys`.

Copie o `.sys` para a pasta de instalação e o `.inf` também:

```powershell
Copy-Item C:\spoofer\src\x64\Release\spoofer\spoofer.sys C:\spoofer\driver\ -Force
Copy-Item C:\spoofer\src\spoofer.inf C:\spoofer\driver\ -Force
```

Se der erro de compilação, o mais comum é: `wdmsec.h` não encontrado (WDK não instalado ou SDK diferente do WDK) ou `MinGW`/`clang` selecionado em vez de MSVC. Revise a Parte 2.

---

# PARTE 6 — Os scripts

## 6.1 `C:\spoofer\hwid-dump.ps1`

```powershell
$out = @()
$out += "== UUID ==";      $out += (Get-CimInstance Win32_ComputerSystemProduct).UUID
$out += "== BIOS serial =="; $out += (Get-CimInstance Win32_BIOS).SerialNumber
$out += "== Disco ==";     $out += (Get-Disk | ForEach-Object { "$($_.Number)|$($_.SerialNumber)" })
$out += "== Volume ==";    $out += (Get-Volume | ForEach-Object { "$($_.DriveLetter)|$($_.UniqueId)" })
$out += "== MAC ==";       $out += (Get-NetAdapter | ForEach-Object { $_.MacAddress })
$out += "== MachineGuid =="; $out += (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
$out += "== HVCI ==";      $out += ((Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard).SecurityServicesRunning -join ',')
$out += "== TESTSIGN ==";  $out += ((bcdedit /enum "{current}") -match 'testsigning' -join '')
$txt = $out -join "`n"
Write-Host $txt
if ($args.Count -gt 0) { $txt | Set-Content -Path $args[0] -Encoding UTF8 }
```

## 6.2 `C:\spoofer\profile.ps1`

```powershell
param([switch]$Write)
$hx = '0123456789ABCDEF'
$lt = 'ABCDEFGHJKLMNPQRSTVWXYZ'
function R([int]$n,[string]$c){ -join (1..$n | ForEach-Object { $c[(Get-Random -Max $c.Length)] }) }
$p = [ordered]@{
    DiskSerial    = (R 6 $lt) + (R 8)
    NvmeSerial    = (R 10)
    VolumeSerial  = (Get-Random -Minimum 0x10000000 -Maximum 0xEFFFFFFF)
    MachineGuid   = [guid]::NewGuid().ToString()
    HwProfileGuid = '{' + [guid]::NewGuid().ToString() + '}'
    BiosSerial    = (R 10)
    SysSerial     = (R 10)
    SysVendor     = 'ASUSTeK COMPUTER INC.'
    SysProduct    = 'PRIME B650M-A WIFI'
    BoardSerial   = (R 12)
}
$b = New-Object byte[] 16; (New-Object Random).NextBytes($b)
$b[7] = ($b[7] -band 0x0F) -bor 0x40
$p.SysUuid = -join ($b | ForEach-Object { $_.ToString('X2') })

if ($Write) {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Services\spoofer\Parameters'
    New-Item $k -Force | Out-Null
    foreach ($n in $p.Keys) {
        $t = if ($p[$n] -is [int]) { 'DWord' } else { 'String' }
        Set-ItemProperty $k -Name $n -Value $p[$n] -Type $t
    }
    Set-ItemProperty $k -Name Active -Value 1 -Type DWord
    $p | ConvertTo-Json | Set-Content C:\spoofer\backup\spoof.json -Encoding UTF8
}
$p
```

## 6.3 `C:\spoofer\install.ps1`

```powershell
#requires -RunAsAdministrator
param([switch]$NoReboot)
$ErrorActionPreference = 'Stop'
$root = 'C:\spoofer'
$sys  = Join-Path $root 'driver\spoofer.sys'
$inf  = Join-Path $root 'driver\spoofer.inf'
$subj = 'CN=Venice Spoofer Dev'
function Step($n,$t){ Write-Host "`n[$n] $t" -ForegroundColor Cyan }

Step 1 'Verificando arquivos'
if (-not (Test-Path $sys)) { throw "Falta $sys — compile primeiro (Parte 5)." }
if (-not (Test-Path $inf)) { throw "Falta $inf." }

Step 2 'Ponto de restauracao'
try { Enable-ComputerRestore -Drive C:\ ; Checkpoint-Computer -Description 'Antes do spoofer' -RestorePointType MODIFY_SETTINGS } catch { Write-Warning 'Ponto de restauracao nao criado.' }

Step 3 'Backup do HWID original'
& (Join-Path $root 'hwid-dump.ps1') (Join-Path $root 'backup\orig.txt')

Step 4 'Estado atual'
$sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
$hvci = (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard).SecurityServicesRunning -contains 2
Write-Host "SecureBoot=$sb  HVCI=$hvci"
if ($hvci) {
    Write-Warning 'Desativando Memory Integrity (obrigatorio para driver de teste).'
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
    New-Item $k -Force | Out-Null
    Set-ItemProperty $k -Name Enabled -Value 0 -Type DWord
}

Step 5 'Certificado'
$c = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $subj -and $_.NotAfter -gt (Get-Date).AddDays(30) } | Select-Object -First 1
if (-not $c) {
    $c = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subj `
        -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm sha256 `
        -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(5)
}
$cer = Join-Path $env:TEMP 'spoofer-dev.cer'
Export-Certificate -Cert $c -FilePath $cer -Type CERT | Out-Null
certutil -addstore -f Root $cer | Out-Null
certutil -addstore -f TrustedPublisher $cer | Out-Null

Step 6 'Assinando o driver'
$st = (Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' |
       Sort-Object FullName -Descending | Select-Object -First 1).FullName
if (-not $st) { throw 'signtool nao encontrado. WDK instalado?' }
& $st sign /v /n $subj /fd sha256 /tr http://timestamp.digicert.com /td sha256 $sys
if ($LASTEXITCODE -ne 0) { throw 'Assinatura falhou.' }

Step 7 'Gerando perfil de spoof'
& (Join-Path $root 'profile.ps1') -Write | Out-Null

Step 8 'Ligando test signing'
bcdedit /set testsigning on | Out-Null

Step 9 'Instalando driver'
$r = pnputil /add-driver $inf /install 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Warning "pnputil falhou, usando sc.exe. Detalhe: $r"
    Copy-Item $sys "$env:SystemRoot\System32\drivers\spoofer.sys" -Force
    sc.exe create spoofer type= kernel start= boot group= "Boot Bus Extender" binPath= "$env:SystemRoot\System32\drivers\spoofer.sys"
}
sc.exe config spoofer start= boot group= "Boot Bus Extender" | Out-Null

Step 10 'Registrando filtro de disco/volume'
foreach ($g in '{4d36e967-e325-11ce-bfc1-08002be10318}','{71a27cdd-812a-11d0-bec7-08002be2092f}') {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$g"
    $cur = @((Get-ItemProperty $k -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters) | Where-Object { $_ }
    if ($cur -notcontains 'spoofer') {
        Set-ItemProperty $k -Name UpperFilters -Value ($cur + 'spoofer') -Type MultiString
    }
}

Step 11 'Conferindo'
bcdedit /enum "{current}" | Select-String 'testsigning'
Get-Item $sys | Select-Object Name, Length, LastWriteTime
Write-Host "`nInstalado. REINICIE o computador." -ForegroundColor Green
if (-not $NoReboot) { Start-Sleep 4; Restart-Computer }
```

## 6.4 `C:\spoofer\uninstall.ps1`

```powershell
#requires -RunAsAdministrator
param([switch]$NoReboot)
$ErrorActionPreference = 'Continue'
$root = 'C:\spoofer'

Write-Host 'Restaurando HWID original...'
$o = Get-Content (Join-Path $root 'backup\orig.txt') -ErrorAction SilentlyContinue
if ($o) {
    $guid = ($o | Select-String '^== MachineGuid ==$' -Context 0,1).Context.PostContext
    if ($guid) { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -Value $guid.Trim() }
}

Write-Host 'Removendo driver...'
sc.exe stop spoofer | Out-Null
sc.exe delete spoofer | Out-Null
Remove-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\spoofer' -Recurse -Force -ErrorAction SilentlyContinue

foreach ($g in '{4d36e967-e325-11ce-bfc1-08002be10318}','{71a27cdd-812a-11d0-bec7-08002be2092f}') {
    $k = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$g"
    $cur = @((Get-ItemProperty $k -Name UpperFilters -ErrorAction SilentlyContinue).UpperFilters) | Where-Object { $_ -and $_ -ne 'spoofer' }
    Set-ItemProperty $k -Name UpperFilters -Value $cur -Type MultiString
}

bcdedit /set testsigning off | Out-Null
Write-Host 'Desinstalado. Reinicie.' -ForegroundColor Green
if (-not $NoReboot) { Start-Sleep 4; Restart-Computer }
```

---

# PARTE 7 — Tirar o snapshot do HWID

No PowerShell **como Administrador**:

```powershell
cd C:\spoofer
Set-ExecutionPolicy Bypass -Scope Process -Force
.\hwid-dump.ps1 C:\spoofer\backup\antes.txt
```

Vai aparecer uma lista de UUID, serial de disco, MAC, MachineGuid. Guarde. **Esses são os valores originais** — sem eles você não compara nada depois.

---

# PARTE 8 — Rodar o instalador

```powershell
.\install.ps1
```

Vai pedir confirmação e reiniciar sozinho no final. Se aparecer aviso vermelho sobre `pnputil`, ele cai no plano B (`sc.exe`) — normal, siga em frente.

Se o script parar com erro, leia a mensagem: quase sempre é "falta `spoofer.sys`" (Parte 5 não foi feita) ou `signtool nao encontrado` (WDK não instalado).

---

# PARTE 9 — Depois do reboot: conferir

1. Abra o PowerShell **como Administrador**.
2. `cd C:\spoofer`
3. `Set-ExecutionPolicy Bypass -Scope Process -Force`
4. `.\hwid-dump.ps1 C:\spoofer\backup\depois.txt`
5. `Compare-Object (Get-Content C:\spoofer\backup\antes.txt) (Get-Content C:\spoofer\backup\depois.txt)`

O que **precisa** aparecer diferente: UUID, serial de disco, MachineGuid. Se algum não mudou, o módulo correspondente não carregou — confira com `sc query spoofer` (deve dizer `RUNNING`).

Confira também:

```powershell
bcdedit /enum "{current}" | Select-String testsigning   # deve mostrar "on"
sc query spoofer                                        # deve mostrar RUNNING
```

---

# PARTE 10 — Testar no jogo

Abra o Valorant. Leitura dos erros:

| Erro | Significado | O que fazer |
|---|---|---|
| `VAN9003` | Secure Boot desligado | Ligue Secure Boot na BIOS (o spoof continua funcionando) |
| `VAN9001` | TPM desligado | Ligue o fTPM/PTT na BIOS |
| Erro de assinatura / "integridade" | Módulo de máscara não pegou na sua build | Veja Parte 12 |
| BSOD no boot | Filtro de disco mal registrado | Veja Parte 11 |
| Jogo abre e o HWID está diferente | **Funcionou** | Nada |

---

# PARTE 11 — Se o Windows não iniciar

1. Reinicie e entre no **Modo de Segurança** (F8 ou desligar 3x durante o boot).
2. Em Segurança, PowerShell admin:
   ```powershell
   sc.exe delete spoofer
   reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v UpperFilters /f
   ```
   Isso apaga o `UpperFilters` inteiro — depois você precisa re-adicionar os originais (`disk`, `partmgr`, `fvevol`, `rdyboost`, `volsnap`) via `reg add ... /t REG_MULTI_SZ /d "disk\0partmgr\0fvevol\0rdyboost\0volsnap"`.
3. `bcdedit /set testsigning off` e reinicie.

Antes de reinstalar, use **Restauração do Sistema** com o ponto "Antes do spoofer".

---

# PARTE 12 — Se o jogo reclamar de assinatura

O driver tem um módulo que localiza o valor `g_CiOptions` na `ci.dll` em memória e apaga o bit de test signing, fazendo o Windows reportar "tudo assinado". Ele tenta por padrão de bytes e só aceita se o valor parecer plausível.

Se não pegou, confira:

```powershell
# deve estar vazio se a máscara funcionou
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
```

1. O driver está `RUNNING`? (`sc query spoofer`) Se não, o boot falhou antes dele.
2. `g_CiOptions` pode ter mudado de padrão na sua build do Windows. Atualize o Windows e recompile; ou aguarde — o padrão é atualizado conforme builds novas saem.
3. Enquanto isso, o spoof em si continua válido: o jogo reclama do **ambiente**, não do HWID.

---

# PARTE 13 — Desinstalar

```powershell
cd C:\spoofer
.\uninstall.ps1
```

Ele restaura o `MachineGuid`, remove o driver, tira o filtro e desliga o test signing. Reinicie.

---

## Resumo do que cada peça faz

| Arquivo | Função |
|---|---|
| `spoofer.c` | Driver: troca serial de disco/NVMe/volume, UUID e serial de BIOS/placa, MachineGuid, e mascara o test signing |
| `spoofer.inf` | Registra o driver como boot-start e como filtro de disco |
| `install.ps1` | Cria certificado, assina, liga test signing, instala e gera o perfil |
| `profile.ps1` | Sorteia valores plausíveis |
| `hwid-dump.ps1` | Fotografa o HWID para comparar antes/depois |
| `uninstall.ps1` | Reverte tudo |

Se quiser, no próximo passo eu detalho como fazer o **enroll do certificado na `db` do UEFI** para dispensar a máscara, ou como trocar o perfil sem reinstalar tudo (só rodar `profile.ps1 -Write` e reiniciar).
