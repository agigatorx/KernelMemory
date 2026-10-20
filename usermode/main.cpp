// main.cpp — winzrt usage ornegi
// Derleme (x64, C++17):
//   cl /std:c++17 /W4 /EHsc main.cpp
// Calistir: admin, driver yuklu olmali (sc start winzrt), hedef acik olmali.

#include <Windows.h>
#include <iostream>
#include <iomanip>

#include "memory.hpp"

int main() {
    // hedefi ac — notepad.exe
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi{};
    CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", nullptr,
                   nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    if (pi.hThread) CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    Sleep(500);                       // PEB Ldr listesi dolana kadar bekle

    try {
        Memory mem(L"notepad.exe");
        std::cout << "[+] pid: " << std::dec << mem.pid() << '\n';

        // modul tabani (PEB Ldr üzerinden, driver tarafinda)
        const auto base = mem.GetModuleBase(L"notepad.exe");
        std::cout << "[+] notepad.exe base: 0x" << std::hex << base << '\n';

        // PE dogrulamasi: MZ imzasi
        const auto mz = mem.read<std::uint16_t>(base);
        std::cout << "[+] MZ: 0x" << std::setw(4) << std::setfill('0') << mz << '\n';
        if (mz != 0x5A4D) {
            std::cerr << "[-] MZ yok, base yanlis\n";
            return 1;
        }

        // NT imzasi + OptionalHeader ImageBase (PE32+: e_lfanew +0x30)
        const auto e_lfanew = mem.read<std::uint32_t>(base + 0x3C);
        const auto nt = mem.read<std::uint32_t>(base + e_lfanew);
        std::cout << "[+] NT sig: 0x" << std::setw(8) << std::setfill('0') << nt << '\n';

        const auto imageBase = mem.read<std::uint64_t>(base + e_lfanew + 0x30);
        std::cout << "[+] OptionalHeader.ImageBase: 0x" << imageBase << '\n';

        // yazma testi: okunan baytlari aynen geri yaz (notepad'e zararsiz)
        std::uint8_t header[16];
        mem.ReadRaw(base, header, sizeof(header));
        mem.WriteRaw(base, header, sizeof(header));
        std::cout << "[+] write test: 16 bayt aynen geri yazildi (no-op)\n";

        // read<T> / write<T> ornegi: bir sayiyi oku, ayni degeri yaz
        const auto value = mem.read<std::uint32_t>(base + e_lfanew + 0x10);  // TimeDateStamp
        std::cout << "[+] TimeDateStamp: 0x" << std::setw(8) << std::setfill('0')
                  << std::hex << value << '\n';
        mem.write<std::uint32_t>(base + e_lfanew + 0x10, value);

        std::cout << "[+] bitti, notepad hala ayakta\n";
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << '\n';
        return 1;
    }
    return 0;
}
