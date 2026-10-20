#pragma once
// memory.hpp — winzrt usermode kitapapigi (header-only, x64)
// Derleme: C++17, gerekli: kernel32, Advapi32 gerekmez (toolhelp kernel32).

#include <Windows.h>
#include <TlHelp32.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// IOCTL'ler main.c ile birebir ayni olmali
#define IOCTL_WINZRT_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINZRT_WRITE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINZRT_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
struct WinzrtRw {
    std::uint64_t pid;
    std::uint64_t address;
    std::uint32_t size;
    std::uint32_t pad;
};
static_assert(sizeof(WinzrtRw) == 24, "protokol kirildi");

struct WinzrtModuleReq {
    std::uint64_t pid;
    wchar_t       name[260];
};
struct WinzrtModuleResp {
    std::uint64_t base;
};
#pragma pack(pop)

class Memory {
public:
    explicit Memory(const std::wstring& processName)
        : m_pid(FindProcessId(processName))
    {
        if (m_pid == 0)
            throw std::runtime_error("process not found: " + ToNarrow(processName));

        m_device = CreateFileW(L"\\\\.\\winzrt",
                               GENERIC_READ | GENERIC_WRITE,
                               0, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (m_device == INVALID_HANDLE_VALUE)
            throw std::runtime_error("winzrt driver not loaded (sc start winzrt?)");
    }

    ~Memory() {
        if (m_device != INVALID_HANDLE_VALUE)
            CloseHandle(m_device);
    }

    Memory(const Memory&) = delete;
    Memory& operator=(const Memory&) = delete;

    // --- modul -----------------------------------------------------------
    std::uint64_t GetModuleBase(const std::wstring& moduleName) const {
        WinzrtModuleReq req{};
        WinzrtModuleResp resp{};
        DWORD ret = 0;

        req.pid = m_pid;
        wcsncpy_s(req.name, moduleName.c_str(), _TRUNCATE);

        if (!DeviceIoControl(m_device, IOCTL_WINZRT_MODULE,
                             &req, sizeof(req),
                             &resp, sizeof(resp),
                             &ret, nullptr) || ret != sizeof(resp))
            throw std::runtime_error("module not found: " + ToNarrow(moduleName));

        return resp.base;
    }

    // --- okuma / yazma ---------------------------------------------------
    template <typename T>
    T read(std::uint64_t address) const {
        static_assert(std::is_trivially_copyable_v<T>, "T trivial olmali");
        T value{};
        ReadRaw(address, &value, sizeof(T));
        return value;
    }

    template <typename T>
    void write(std::uint64_t address, const T& value) {
        static_assert(std::is_trivially_copyable_v<T>, "T trivial olmali");
        WriteRaw(address, &value, sizeof(T));
    }

    void ReadRaw(std::uint64_t address, void* buffer, std::size_t size) const {
        WinzrtRw req{ m_pid, address, static_cast<std::uint32_t>(size), 0 };
        DWORD ret = 0;

        if (!DeviceIoControl(m_device, IOCTL_WINZRT_READ,
                             &req, sizeof(req),
                             buffer, static_cast<DWORD>(size),
                             &ret, nullptr) || ret != size)
            throw std::runtime_error("read failed @ 0x" + Hex(address));
    }

    void WriteRaw(std::uint64_t address, const void* buffer, std::size_t size) {
        std::vector<std::uint8_t> packet(sizeof(WinzrtRw) + size);
        auto* hdr = reinterpret_cast<WinzrtRw*>(packet.data());
        *hdr = WinzrtRw{ m_pid, address, static_cast<std::uint32_t>(size), 0 };
        std::memcpy(packet.data() + sizeof(WinzrtRw), buffer, size);

        DWORD ret = 0;
        if (!DeviceIoControl(m_device, IOCTL_WINZRT_WRITE,
                             packet.data(), static_cast<DWORD>(packet.size()),
                             nullptr, 0, &ret, nullptr))
            throw std::runtime_error("write failed @ 0x" + Hex(address));
    }

    // --- yardimci --------------------------------------------------------
    std::uint64_t pid() const { return m_pid; }

    static DWORD FindProcessId(const std::wstring& name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32W entry{ sizeof(entry) };
        DWORD pid = 0;

        if (Process32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return pid;
    }

private:
    static std::string ToNarrow(const std::wstring& s) {
        if (s.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string out(static_cast<std::size_t>(len > 0 ? len - 1 : 0), '\0');
        if (len > 1)
            WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), len, nullptr, nullptr);
        return out;
    }

    static std::string Hex(std::uint64_t v) {
        char b[24];
        snprintf(b, sizeof(b), "%llX", static_cast<unsigned long long>(v));
        return b;
    }

    HANDLE m_device = INVALID_HANDLE_VALUE;
    DWORD  m_pid    = 0;
};
