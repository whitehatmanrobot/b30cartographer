#pragma warning(disable:4005) // macro redefinition
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#define UNICODE
#define SECURITY_WIN32
#define _AMD64_
// Move NT-specific headers before <windows.h> to reduce conflicts
#include <ntstatus.h>
#include <winternl.h>
#include <winbase.h>
// Undefine conflicting macros before NTSTATUS includes (in case of overlaps)
#undef STATUS_WAIT_0
#undef STATUS_ABANDONED_WAIT_0
#undef STATUS_USER_APC
#undef STATUS_TIMEOUT
#undef STATUS_PENDING
#undef DBG_EXCEPTION_HANDLED
#undef DBG_CONTINUE
#undef STATUS_SEGMENT_NOTIFICATION
#undef STATUS_FATAL_APP_EXIT
#undef DBG_REPLY_LATER
#undef DBG_TERMINATE_THREAD
#undef DBG_TERMINATE_PROCESS
#undef DBG_CONTROL_C
#undef DBG_PRINTEXCEPTION_C
#undef DBG_RIPEXCEPTION
#undef DBG_CONTROL_BREAK
#undef DBG_COMMAND_EXCEPTION
#undef DBG_PRINTEXCEPTION_WIDE_C
#undef STATUS_GUARD_PAGE_VIOLATION
#undef STATUS_DATATYPE_MISALIGNMENT
#undef STATUS_BREAKPOINT
#undef STATUS_SINGLE_STEP
#undef STATUS_LONGJUMP
#undef STATUS_UNWIND_CONSOLIDATE
#undef DBG_EXCEPTION_NOT_HANDLED
#undef STATUS_ACCESS_VIOLATION
#undef STATUS_IN_PAGE_ERROR
#undef STATUS_INVALID_HANDLE
#undef STATUS_INVALID_PARAMETER
#undef STATUS_NO_MEMORY
#undef STATUS_ILLEGAL_INSTRUCTION
#undef STATUS_NONCONTINUABLE_EXCEPTION
#undef STATUS_INVALID_DISPOSITION
#undef STATUS_ARRAY_BOUNDS_EXCEEDED
#undef STATUS_FLOAT_DENORMAL_OPERAND
#undef STATUS_FLOAT_DIVIDE_BY_ZERO
#undef STATUS_FLOAT_INEXACT_RESULT
#undef STATUS_FLOAT_INVALID_OPERATION
#undef STATUS_FLOAT_OVERFLOW
#undef STATUS_FLOAT_STACK_CHECK
#undef STATUS_FLOAT_UNDERFLOW
#undef STATUS_INTEGER_DIVIDE_BY_ZERO
#undef STATUS_INTEGER_OVERFLOW
#undef STATUS_PRIVILEGED_INSTRUCTION
#undef STATUS_STACK_OVERFLOW
#undef STATUS_DLL_NOT_FOUND
#undef STATUS_ORDINAL_NOT_FOUND
#undef STATUS_ENTRYPOINT_NOT_FOUND
#undef STATUS_CONTROL_C_EXIT
#undef STATUS_DLL_INIT_FAILED
#undef STATUS_CONTROL_STACK_VIOLATION
#undef STATUS_FLOAT_MULTIPLE_FAULTS
#undef STATUS_FLOAT_MULTIPLE_TRAPS
#undef STATUS_REG_NAT_CONSUMPTION
#undef STATUS_HEAP_CORRUPTION
#undef STATUS_STACK_BUFFER_OVERRUN
#undef STATUS_INVALID_CRUNTIME_PARAMETER
#undef STATUS_ASSERTION_FAILURE
#undef STATUS_ENCLAVE_VIOLATION
#undef STATUS_INTERRUPTED
#undef STATUS_THREAD_NOT_RUNNING
#undef STATUS_ALREADY_REGISTERED
#undef STATUS_SXS_EARLY_DEACTIVATION
#undef STATUS_SXS_INVALID_DEACTIVATION
#include <windows.h>
#include <commdlg.h>
#include <gdiplus.h>
#include <vector>
#include <string>
#include <shellapi.h>
#include <shlobj.h>
#include <memory>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <algorithm>
#include <commctrl.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <limits>
#include <imagehlp.h>
#include <ShellScalingApi.h>
#include <wincrypt.h>
#include <aclapi.h>
#include <mutex>
#include <map>
#include <set>
#include <cstdint>
#include <functional>
#include <optional>
#include <random>
#include <tlhelp32.h>
#include <psapi.h>
#include <restartmanager.h>
#include <cmath>
#include <regex>
#include <iostream>
#include <thread>
#include <atomic>
#include <wtsapi32.h>
#include <versionhelpers.h>
#include <array>
#include <utility>
#include <bcrypt.h>
#include <sddl.h>
#include <security.h>
#include <wincodec.h>
#include <mscat.h>
#include <mssip.h>
#include <strsafe.h>
#include <objbase.h>
#include <t2embapi.h>
static std::wstring logFilePath;
static std::mutex logMutex;
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "Shcore.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Rstrtmgr.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
using namespace Gdiplus;
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferLength,
    PULONG ReturnLength
    );
template <typename T>
void delete_object(T* obj) { delete obj; }
template <typename T, typename Deleter>
class unique_resource {
    T res{};
    bool valid{ false };
    Deleter del;
public:
    unique_resource() = default;
    explicit unique_resource(T r, Deleter d = Deleter{}) noexcept : res(r), valid(r != T{}), del(std::move(d)) {}
    ~unique_resource() noexcept { reset(); }
    unique_resource(const unique_resource&) = delete;
    unique_resource& operator=(const unique_resource&) = delete;
    unique_resource(unique_resource&& other) noexcept : res(other.res), valid(other.valid), del(std::move(other.del)) {
        other.valid = false;
        other.res = T{};
    }
    unique_resource& operator=(unique_resource&& other) noexcept {
        if (this != &other) {
            reset();
            res = other.res;
            valid = other.valid;
            del = std::move(other.del);
            other.valid = false;
            other.res = T{};
        }
        return *this;
    }
    T get() const noexcept { return res; }
    T release() noexcept {
        valid = false;
        return std::exchange(res, T{});
    }
    void reset(T r = T{}) noexcept {
        if (valid && res != T{}) del(res);
        res = r;
        valid = (r != T{});
    }
    void disableCleanup() noexcept { valid = false; }
};
using unique_handle = unique_resource<HANDLE, decltype(&CloseHandle)>;
using unique_hmodule = unique_resource<HMODULE, decltype(&FreeLibrary)>;
using unique_mapview = unique_resource<LPVOID, decltype(&UnmapViewOfFile)>;
template <typename T>
constexpr T IntToPtr(uintptr_t Value) { return reinterpret_cast<T>(Value); }
template <typename T>
constexpr T MyMakeIntResource(ULONG_PTR id) { return reinterpret_cast<T>(id); }
static constexpr WORD MyMakeLangId(WORD p, WORD s) {
    return static_cast<WORD>((static_cast<unsigned>(s) << 10) | p);
}
constexpr const wchar_t* HOVER_PROP = L"HoverState";
constexpr WORD RT_ICON_ID = 3;
constexpr WORD RT_GROUP_ICON_ID = 14;
constexpr WORD RT_MANIFEST_ID = 24;
constexpr uintptr_t IDC_LOAD_EXE = 1001;
constexpr uintptr_t IDC_LOAD_IMAGE = 1002;
constexpr uintptr_t IDC_REPLACE = 1003;
constexpr uintptr_t IDC_EXIT = 1004;
constexpr uintptr_t IDC_EXE_PREVIEW = 1005;
constexpr uintptr_t IDC_IMAGE_PREVIEW = 1006;
constexpr uintptr_t IDC_LABEL_EXE = 1007;
constexpr uintptr_t IDC_LABEL_IMAGE = 1008;
constexpr uintptr_t IDC_STATUS_LABEL = 1011;
constexpr uintptr_t IDC_TITLE_LABEL = 1012;
constexpr uintptr_t IDC_PROGRESS_BAR = 1013;
constexpr uintptr_t IDC_CHECKSUM_LABEL = 1014;
constexpr uintptr_t IDC_SECTION_COUNT = 1015;
constexpr uintptr_t IDC_OVERLAY_SIZE = 1016;
constexpr uintptr_t IDC_LOG_WINDOW = 1017;
constexpr uintptr_t IDC_MANIFEST_LABEL = 1018;
constexpr uintptr_t IDC_DEBUG_INFO = 1019;
constexpr uintptr_t IDC_ICON_INFO = 1020;
constexpr uintptr_t IDC_INSTALLER_TYPE = 1021;
constexpr uintptr_t IDC_ADVANCED_HASH_LABEL = 1022;
constexpr uintptr_t IDC_KERNEL_PATCH_STATUS = 1023;
constexpr uintptr_t IDC_MORPH_ATTACK_INFO = 1024;
constexpr uintptr_t IDC_RESIGN_STATUS = 1025;
constexpr uintptr_t IDC_ADVANCED_PANEL = 1026;
constexpr uintptr_t IDC_EXTRA_LOG = 1027;
constexpr uintptr_t IDC_EXTRA_STATUS = 1028;
constexpr uintptr_t IDC_EXTRA_PROGRESS = 1029;
constexpr WORD IDI_ICONCHANGEREXE = 101;
constexpr UINT WM_OPERATION_COMPLETE = WM_USER + 1;
constexpr const char* NSIS_SIGNATURE = "Nullsoft Install System";
constexpr const char* INNO_SIGNATURE = "Inno Setup Setup Data";
constexpr const char* INSTALLSHIELD_SIGNATURE = "InstallShield";
constexpr const char* SFX_ZIP_SIGNATURE = "PK ";
constexpr const char* ADVANCED_MSI_SIGNATURE = "MSI Installer";
constexpr const char* WIX_SIGNATURE = "WiX Toolset";
constexpr const char* CLICKTEAM_SIGNATURE = "Clickteam Install Creator";
constexpr const char* ADVANCED_INSTALLER_SIGNATURE = "Advanced Installer";
constexpr const char* GHOST_SIGNATURE = "Ghost Installer";
constexpr uint32_t NSIS_HEADER_SIG = 0xDEADBEEF;
constexpr size_t NSIS_CRC_OFFSET = 4;
constexpr size_t NSIS_FLAGS_OFFSET = 8;
constexpr size_t INNO_CHECKSUM_OFFSET = 16;
constexpr size_t INSTALLSHIELD_HASH_OFFSET = 32;
constexpr size_t SFX_ZIP_CRC_OFFSET = 8;
constexpr int MAX_RETRIES = 20;
constexpr int SLEEP_DELAY_MS = 200;
constexpr int BUFFER_SIZE_LARGE = 16384;
constexpr int BUFFER_SIZE_SMALL = 2048;
constexpr int MAX_RETRIES_FILE_OP = 10;
constexpr int RETRY_DELAY_MS = 300;
constexpr int MORPH_PATTERN_VARIANTS = 20;
constexpr int KERNEL_HACK_LEVEL = 3;
const std::array<std::pair<int, int>, 8> STANDARD_ICON_SIZES = {
    std::make_pair(16, 16), std::make_pair(24, 24), std::make_pair(32, 32),
    std::make_pair(48, 48), std::make_pair(64, 64), std::make_pair(128, 128),
    std::make_pair(256, 256), std::make_pair(512, 512)
};
#pragma pack(push, 2)
typedef struct {
    BYTE bWidth;
    BYTE bHeight;
    BYTE bColorCount;
    BYTE bReserved;
    WORD wPlanes;
    WORD wBitCount;
    DWORD dwBytesInRes;
    WORD nID;
} GRPICONDIRENTRY, * LPGRPICONDIRENTRY;
#pragma pack(pop)
#pragma pack(push, 2)
typedef struct {
    WORD idReserved;
    WORD idType;
    WORD idCount;
    GRPICONDIRENTRY idEntries[1];
} GRPICONDIR, * LPGRPICONDIR;
#pragma pack(pop)
struct ResourceInfo {
    LPCWSTR type{ nullptr };
    LPCWSTR name{ nullptr };
    WORD langId{ 0 };
    std::vector<BYTE> data;
    bool isIconRelated() const {
        return IS_INTRESOURCE(type) && (LOWORD(type) == RT_ICON_ID || LOWORD(type) == RT_GROUP_ICON_ID);
    }
};
struct IconResource {
    std::wstring name;
    WORD nameId{ 0 };
    bool isNameString{ false };
    bool isPrimary{ false };
    WORD langId{ 0 };
    std::vector<BYTE> groupData;
    std::vector<WORD> iconIds;
    std::vector<std::pair<int, int>> iconSizes;
    std::vector<std::vector<BYTE>> iconData;
    std::vector<WORD> bitCounts;
    LPCWSTR GetName() const { return isNameString ? name.c_str() : MyMakeIntResource<LPCWSTR>(nameId); }
};
struct AppData {
    std::wstring exePath;
    std::wstring imagePath;
    std::wstring tempDirPath;
    std::vector<BYTE> overlayData;
    std::vector<BYTE> manifestData;
    std::vector<ResourceInfo> preservedResources;
    std::vector<IconResource> iconGroups;
    std::vector<std::string> sections;
    uint32_t originalChecksum{ 0 };
    size_t originalPESize{ 0 };
    std::string installerType;
    FILETIME creationTime{ 0 };
    FILETIME lastAccessTime{ 0 };
    FILETIME lastWriteTime{ 0 };
    DWORD fileAttributes{ INVALID_FILE_ATTRIBUTES };
    Bitmap* pExeImage{ nullptr };
    Bitmap* pImage{ nullptr };
    HFONT hFont{ nullptr };
    HFONT hLabelFont{ nullptr };
    HFONT hTitleFont{ nullptr };
    HFONT hInfoFont{ nullptr };
    bool darkTheme{ false };
    int windowWidth{ 1100 };
    int height{ 1200 };
    float scaleFactor{ 1.0f };
    std::atomic<bool> isReplacing{ false };
    bool exeModified{ false };
    std::wstring sessionId;
    std::wstring logFilePath;
    ~AppData() {
        if (pExeImage) delete pExeImage;
        if (pImage) delete pImage;
        if (hFont) DeleteObject(hFont);
        if (hLabelFont) DeleteObject(hLabelFont);
        if (hTitleFont) DeleteObject(hTitleFont);
        if (hInfoFont) DeleteObject(hInfoFont);
    }
};
// Forward declarations
static bool IsDarkTheme();
static uint32_t CRC32(const BYTE* data, size_t size);
static std::wstring ToWString(const char* s);
static void UpdateStatus(HWND hWnd, const std::wstring& message, DWORD errorCode = 0);
static void LogMessage(const std::wstring& message, DWORD errorCode);
static void LogInfo(const std::wstring& msg);
static void LogError(const std::wstring& msg, DWORD errCode = 0);
static double CalculateEntropy(const BYTE* data, size_t size);
static uint32_t Adler32(const BYTE* data, size_t size);
static uint64_t MD5Hash(const BYTE* data, size_t size);
static BOOL InvasiveKernelResign(HANDLE hProcess, const std::wstring& filePath);
static BOOL Crypt32Resign(const std::wstring& filePath, const std::wstring& certSubject);
static BOOL ResignExecutable(const std::wstring& filePath, HWND hWnd, bool kernelHack);
static uint64_t SHA256Hash(const BYTE* data, size_t size);
static uint32_t AdvancedChecksum(const BYTE* data, size_t size, int level);
class IntegrityHandler {
public:
    virtual bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) = 0;
    virtual bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) = 0;
    virtual bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) = 0;
    virtual bool Repackage(const std::wstring& filePath, HWND hWnd) = 0;
    virtual ~IntegrityHandler() = default;
};
class NSISHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t headerOffset = 0;
        for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - 4; ++i) {
            if (*reinterpret_cast<uint32_t*>(mapped + i) == NSIS_HEADER_SIG) {
                headerOffset = i;
                break;
            }
        }
        if (headerOffset == 0) return false;
        size_t dataStart = headerOffset + NSIS_CRC_OFFSET + 4;
        size_t dataSize = static_cast<size_t>(fileSize.QuadPart) - dataStart;
        uint32_t newCRC = CRC32(mapped + dataStart, dataSize);
        memcpy(mapped + headerOffset + NSIS_CRC_OFFSET, &newCRC, sizeof(newCRC));
        uint32_t flags = *reinterpret_cast<uint32_t*>(mapped + headerOffset + NSIS_FLAGS_OFFSET);
        flags &= ~0x00000004;
        memcpy(mapped + headerOffset + NSIS_FLAGS_OFFSET, &flags, sizeof(flags));
        UpdateStatus(hWnd, L"NSIS Handler: Recalculating CRC checksum for installer data.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t hashOffset = 0;
        std::vector<std::vector<BYTE>> hashPatterns = {
            {0xDE, 0xAD, 0xBE, 0xEF},
            {0xAA, 0xBB, 0xCC, 0xDD},
        };
        for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - 32; ++i) {
            bool found = false;
            for (const auto& pattern : hashPatterns) {
                if (memcmp(mapped + i, pattern.data(), pattern.size()) == 0) {
                    hashOffset = i;
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        if (hashOffset == 0) {
            size_t candidate = peSize;
            double maxEntropy = 0.0;
            for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - 32; i += 32) {
                double entropy = CalculateEntropy(mapped + i, 32);
                if (entropy > maxEntropy) {
                    maxEntropy = entropy;
                    candidate = i;
                }
            }
            if (maxEntropy > 7.0) {
                hashOffset = candidate;
            }
        }
        if (hashOffset != 0 && hashOffset + 32 < static_cast<size_t>(fileSize.QuadPart)) {
            memset(mapped + hashOffset, 0, 32);
            UpdateStatus(hWnd, L"NSIS Handler: Dynamically located and neutralized advanced hash block.");
            return true;
        }
        UpdateStatus(hWnd, L"NSIS Handler: No advanced hash blocks found.");
        return false;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class InnoHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t headerOffset = 0;
        std::string sig = INNO_SIGNATURE;
        for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - sig.size(); ++i) {
            if (memcmp(mapped + i, sig.c_str(), sig.size()) == 0) {
                headerOffset = i;
                break;
            }
        }
        if (headerOffset == 0) return false;
        size_t dataStart = headerOffset + INNO_CHECKSUM_OFFSET + 4;
        size_t dataSize = static_cast<size_t>(fileSize.QuadPart) - dataStart;
        uint32_t newChecksum = Adler32(mapped + dataStart, dataSize);
        memcpy(mapped + headerOffset + INNO_CHECKSUM_OFFSET, &newChecksum, sizeof(newChecksum));
        UpdateStatus(hWnd, L"Inno Handler: Recalculating Adler32 checksum for setup data.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t hashOffset = 0;
        std::vector<std::vector<BYTE>> hashPatterns = {
            {0x49, 0x6E, 0x6E, 0x6F},
            {0x53, 0x65, 0x74, 0x75, 0x70},
        };
        for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - 16; ++i) {
            bool found = false;
            for (const auto& pattern : hashPatterns) {
                if (memcmp(mapped + i, pattern.data(), pattern.size()) == 0) {
                    hashOffset = i + pattern.size();
                    found = true;
                    break;
                }
            }
            if (found) break;
        }
        if (hashOffset == 0) {
            size_t candidate = peSize;
            double maxEntropy = 0.0;
            for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - 16; i += 16) {
                double entropy = CalculateEntropy(mapped + i, 16);
                if (entropy > 7.0) {
                    maxEntropy = entropy;
                    candidate = i;
                }
            }
            if (maxEntropy > 7.0) {
                hashOffset = candidate;
            }
        }
        if (hashOffset != 0 && hashOffset + 16 < static_cast<size_t>(fileSize.QuadPart)) {
            memset(mapped + hashOffset, 0, 16);
            UpdateStatus(hWnd, L"Inno Handler: Heuristically located and neutralized advanced hash block.");
            return true;
        }
        UpdateStatus(hWnd, L"Inno Handler: No advanced hash blocks found.");
        return false;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class InstallShieldHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t headerOffset = 0;
        std::string sig = INSTALLSHIELD_SIGNATURE;
        for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - sig.size(); ++i) {
            if (memcmp(mapped + i, sig.c_str(), sig.size()) == 0) {
                headerOffset = i;
                break;
            }
        }
        if (headerOffset == 0) return false;
        size_t dataStart = headerOffset + INSTALLSHIELD_HASH_OFFSET + 16;
        size_t dataSize = static_cast<size_t>(fileSize.QuadPart) - dataStart;
        uint64_t newHash = MD5Hash(mapped + dataStart, dataSize);
        memcpy(mapped + headerOffset + INSTALLSHIELD_HASH_OFFSET, &newHash, 8);
        UpdateStatus(hWnd, L"InstallShield Handler: Recalculating MD5 hash for archive data.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t hashOffset = peSize + 0x300;
        if (hashOffset + 32 < static_cast<size_t>(fileSize.QuadPart)) {
            memset(mapped + hashOffset, 0, 32);
        }
        UpdateStatus(hWnd, L"InstallShield Handler: Neutralized hardcoded hash block.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class SFXZipHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t zipOffset = 0;
        BYTE zipMagic[4] = { 0x50, 0x4B, 0x03, 0x04 };
        for (size_t i = peSize; i < static_cast<size_t>(fileSize.QuadPart) - 4; ++i) {
            if (memcmp(mapped + i, zipMagic, 4) == 0) {
                zipOffset = i;
                break;
            }
        }
        if (zipOffset == 0) return false;
        size_t crcOffset = zipOffset + 14;
        size_t compressedSizeOffset = zipOffset + 18;
        size_t uncompressedSizeOffset = zipOffset + 22;
        size_t nameLengthOffset = zipOffset + 26;
        size_t extraLengthOffset = zipOffset + 28;
        uint16_t nameLength = *reinterpret_cast<uint16_t*>(mapped + nameLengthOffset);
        uint16_t extraLength = *reinterpret_cast<uint16_t*>(mapped + extraLengthOffset);
        size_t dataStart = zipOffset + 30 + nameLength + extraLength;
        uint32_t compressedSize = *reinterpret_cast<uint32_t*>(mapped + compressedSizeOffset);
        uint32_t newCRC = CRC32(mapped + dataStart, compressedSize);
        memcpy(mapped + crcOffset, &newCRC, sizeof(newCRC));
        UpdateStatus(hWnd, L"SFX Zip Handler: Recalculating CRC checksum for ZIP central directory.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t extraOffset = peSize + 0x400;
        if (extraOffset + 32 < static_cast<size_t>(fileSize.QuadPart)) {
            memset(mapped + extraOffset, 0, 32);
        }
        UpdateStatus(hWnd, L"SFX Zip Handler: Neutralized extra data field hash.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class AdvancedMSIHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        if (!ResignExecutable(filePath, hWnd, false)) return false;
        UpdateStatus(hWnd, L"Advanced MSI Handler: Bypassing integrity checks via re-signing.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"Advanced MSI Handler: No specific advanced hashes to remove.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class WixHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        if (!ResignExecutable(filePath, hWnd, false)) return false;
        UpdateStatus(hWnd, L"WiX Handler: Bypassing integrity checks via re-signing.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"WiX Handler: No specific advanced hashes to remove.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class ClickteamHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t checksumOffset = peSize + 0x80;
        if (checksumOffset + 4 < static_cast<size_t>(fileSize.QuadPart)) {
            uint32_t newChecksum = CRC32(mapped + checksumOffset + 4, static_cast<size_t>(fileSize.QuadPart) - checksumOffset - 4);
            memcpy(mapped + checksumOffset, &newChecksum, sizeof(newChecksum));
        }
        UpdateStatus(hWnd, L"Clickteam Handler: Recalculating CRC checksum for installer data.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"Clickteam Handler: No specific advanced hashes to remove.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class AdvancedInstallerHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t hashOffset = peSize + 0x100;
        if (hashOffset + 32 < static_cast<size_t>(fileSize.QuadPart)) {
            uint64_t newHash = SHA256Hash(mapped + hashOffset + 32, static_cast<size_t>(fileSize.QuadPart) - hashOffset - 32);
            memcpy(mapped + hashOffset, &newHash, 8);
        }
        UpdateStatus(hWnd, L"Advanced Installer Handler: Recalculating SHA256-based hash.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"Advanced Installer Handler: No specific advanced hashes to remove.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class GhostHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
        if (!hFile.get()) return false;
        LARGE_INTEGER fileSize{};
        GetFileSizeEx(hFile.get(), &fileSize);
        unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
        if (!hMapping.get()) return false;
        unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
        if (!pMap.get()) return false;
        BYTE* mapped = static_cast<BYTE*>(pMap.get());
        size_t checksumOffset = peSize + 0x200;
        if (checksumOffset + 4 < static_cast<size_t>(fileSize.QuadPart)) {
            uint32_t newChecksum = AdvancedChecksum(mapped + checksumOffset + 4, static_cast<size_t>(fileSize.QuadPart) - checksumOffset - 4, 3);
            memcpy(mapped + checksumOffset, &newChecksum, sizeof(newChecksum));
        }
        UpdateStatus(hWnd, L"Ghost Handler: Recalculating proprietary checksum.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"Ghost Handler: No specific advanced hashes to remove.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        return PatchOutIntegrityChecks(filePath, hWnd, peSize);
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        return PatchOutIntegrityChecks(filePath, hWnd, 0);
    }
};
class GenericHandler : public IntegrityHandler {
public:
    bool PatchOutIntegrityChecks(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"Generic Handler: Applying universal patching techniques.");
        return true;
    }
    bool RemoveAdvancedHashes(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"Generic Handler: No specific advanced hashes to remove.");
        return true;
    }
    bool UpdateAfterModification(const std::wstring& filePath, HWND hWnd, size_t peSize) override {
        UpdateStatus(hWnd, L"Generic Handler: Finalizing modifications.");
        return true;
    }
    bool Repackage(const std::wstring& filePath, HWND hWnd) override {
        UpdateStatus(hWnd, L"Generic Handler: No specific repackaging required.");
        return true;
    }
};

static std::unique_ptr<IntegrityHandler> GetIntegrityHandler(const std::string& installerType) {
    if (installerType == NSIS_SIGNATURE) return std::make_unique<NSISHandler>();
    if (installerType == INNO_SIGNATURE) return std::make_unique<InnoHandler>();
    if (installerType == INSTALLSHIELD_SIGNATURE) return std::make_unique<InstallShieldHandler>();
    if (installerType == SFX_ZIP_SIGNATURE) return std::make_unique<SFXZipHandler>();
    if (installerType == ADVANCED_MSI_SIGNATURE) return std::make_unique<AdvancedMSIHandler>();
    if (installerType == WIX_SIGNATURE) return std::make_unique<WixHandler>();
    if (installerType == CLICKTEAM_SIGNATURE) return std::make_unique<ClickteamHandler>();
    if (installerType == ADVANCED_INSTALLER_SIGNATURE) return std::make_unique<AdvancedInstallerHandler>();
    if (installerType == GHOST_SIGNATURE) return std::make_unique<GhostHandler>();
    return std::make_unique<GenericHandler>(); // Default
}
static std::wstring ToWString(const char* s) {
    if (!s) return L"";
    int len = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (len == 0) {
        LogError(L"Failed to convert string to wide", GetLastError());
        return L"";
    }
    std::vector<wchar_t> buf(len);
    int converted = MultiByteToWideChar(CP_ACP, 0, s, -1, buf.data(), len);
    if (converted == 0) {
        LogError(L"Conversion to wide string failed", GetLastError());
        return L"";
    }
    return std::wstring(buf.data());
}
static std::wstring GetTimestamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::wstringstream ss;
    ss << std::setfill(L'0') << std::setw(4) << st.wYear << L"-" << std::setw(2) << st.wMonth << L"-" << std::setw(2) << st.wDay
        << L" " << std::setw(2) << st.wHour << L":" << std::setw(2) << st.wMinute << L":" << std::setw(2) << st.wSecond
        << L"." << std::setw(3) << st.wMilliseconds;
    return ss.str();
}
static void LogMessage(const std::wstring& message, DWORD errorCode) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::wofstream logFile(logFilePath, std::ios::app);
    if (logFile.is_open()) {
        std::wstringstream ss;
        ss << L"[" << GetTimestamp() << L"] " << message;
        if (errorCode) {
            WCHAR errorMsg[256]{};
            DWORD msgLen = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, errorCode, 0,
                errorMsg, 256, nullptr);
            if (msgLen == 0) {
                ss << L" (Error " << errorCode << L": Unknown error)";
            }
            else {
                ss << L" (Error " << errorCode << L": " << errorMsg << L")";
            }
        }
        ss << L"\n";
        logFile << ss.str();
    }
}
static inline void LogError(const std::wstring& msg, DWORD errCode) {
    LogMessage(L"ERROR: " + msg, errCode);
}
static inline void LogInfo(const std::wstring& msg) {
    LogMessage(L"INFO: " + msg, 0);
}

static void UpdateStatus(HWND hWnd, const std::wstring& message, DWORD errorCode) {
    if (errorCode == 0) LogInfo(message);
    else LogError(message, errorCode);

    SetWindowTextW(GetDlgItem(hWnd, IDC_STATUS_LABEL), message.c_str());
    HWND hLog = GetDlgItem(hWnd, IDC_LOG_WINDOW);
    if (hLog) {
        int len = GetWindowTextLengthW(hLog);
        SendMessageW(hLog, EM_SETSEL, len, len);
        std::wstringstream ss;
        ss << message;
        if (errorCode) {
            WCHAR errMsg[256] = {};
            FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, nullptr, errorCode, 0, errMsg, 256, nullptr);
            ss << L" (Error " << errorCode << L": " << errMsg << L")";
        }
        ss << L"\r\n";
        SendMessageW(hLog, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(ss.str().c_str()));
    }
}
static uint32_t CRC32(const BYTE* data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320U : 0U);
        }
    }
    return ~crc;
}
static uint32_t Adler32(const BYTE* data, size_t size) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < size; ++i) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}
static uint64_t SHA256Hash(const BYTE* data, size_t size) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BYTE hashBuf[32]{};
    uint64_t hash = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    status = BCryptHashData(hHash, const_cast<PBYTE>(data), static_cast<ULONG>(size), 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    status = BCryptFinishHash(hHash, hashBuf, sizeof(hashBuf), 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    memcpy(&hash, hashBuf, sizeof(hash));
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}
static uint64_t MD5Hash(const BYTE* data, size_t size) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    BYTE hashBuf[16]{};
    uint64_t hash = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, nullptr, 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    status = BCryptHashData(hHash, const_cast<PBYTE>(data), static_cast<ULONG>(size), 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    status = BCryptFinishHash(hHash, hashBuf, sizeof(hashBuf), 0);
    if (status != STATUS_SUCCESS) goto cleanup;
    memcpy(&hash, hashBuf, sizeof(hash));
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}
static uint32_t AdvancedChecksum(const BYTE* data, size_t size, int level) {
    uint32_t checksum = 0;
    for (size_t i = 0; i < size; ++i) {
        uint32_t old = checksum;
        uint64_t temp = (uint64_t)checksum * level + data[i];
        checksum = static_cast<uint32_t>(temp) ^ (old >> (32 - level));
    }
    return checksum;
}
static double CalculateEntropy(const BYTE* data, size_t size) {
    if (size == 0) return 0.0;
    std::array<int, 256> freq = { 0 };
    for (size_t i = 0; i < size; ++i) {
        ++freq[data[i]];
    }
    double entropy = 0.0;
    for (int count : freq) {
        if (count > 0) {
            double p = static_cast<double>(count) / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}
static NTSTATUS NtKernelPatch(DWORD pid, const std::wstring& moduleName) {
    unique_handle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid), &CloseHandle);
    if (!hProcess.get()) return STATUS_ACCESS_DENIED;
    NTSTATUS status = STATUS_SUCCESS;
    HMODULE hMod = GetModuleHandleW(moduleName.c_str());
    if (hMod) {
        static pNtWriteVirtualMemory NtWriteVM = nullptr;
        if (!NtWriteVM) {
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll) {
                NtWriteVM = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
            }
            if (!NtWriteVM) {
                return STATUS_PROCEDURE_NOT_FOUND;
            }
        }
        BYTE nop = 0x90;
        SIZE_T written = 0;
        status = NtWriteVM(hProcess.get(), hMod, &nop, 1, reinterpret_cast<PULONG>(&written));
    }
    return status;
}
static BOOL ResignExecutable(const std::wstring& filePath, HWND hWnd, bool kernelHack) {
    if (kernelHack) {
        NTSTATUS status = NtKernelPatch(GetCurrentProcessId(), L"crypt32.dll");
        if (status != STATUS_SUCCESS) {
            LogError(L"Kernel hack failed", status);
            return FALSE;
        }
        unique_handle hProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()), &CloseHandle);
        if (!InvasiveKernelResign(hProcess.get(), filePath)) return FALSE;
    }
    else {
        if (!Crypt32Resign(filePath, L"SelfSignedCert")) return FALSE;
    }
    UpdateStatus(hWnd, L"Executable resigned to fool Windows 11");
    return TRUE;
}
static BOOL InvasiveKernelResign(HANDLE hProcess, const std::wstring& filePath) {
    unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
    if (!hFile.get()) return FALSE;
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile.get(), &fileSize)) return FALSE;
    unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
    if (!hMapping.get()) return FALSE;
    unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
    if (!pMap.get()) return FALSE;
    BYTE* mapped = static_cast<BYTE*>(pMap.get());
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mapped + dos->e_lfanew);
    nt->OptionalHeader.CheckSum = 0;
    PIMAGE_DATA_DIRECTORY sigDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    sigDir->VirtualAddress = 0;
    sigDir->Size = 0;
    return TRUE;
}
static BOOL Crypt32Resign(const std::wstring& filePath, const std::wstring& certSubject) {
    auto certDeleter = [](HCERTSTORE h) { CertCloseStore(h, 0); };
    unique_resource<HCERTSTORE, decltype(certDeleter)> hStore(CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY"), certDeleter);
    if (!hStore.get()) return FALSE;
    PCCERT_CONTEXT pCert = CertFindCertificateInStore(hStore.get(), X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, certSubject.c_str(), nullptr);
    if (!pCert) return FALSE;
    unique_resource<PCCERT_CONTEXT, decltype(&CertFreeCertificateContext)> certGuard(pCert, &CertFreeCertificateContext);
    WINTRUST_FILE_INFO fileInfo = { sizeof(fileInfo), filePath.c_str() };
    GUID action = WINTRUST_ACTION_GENERIC_CERT_VERIFY;
    WINTRUST_DATA wintrustData = { sizeof(wintrustData) };
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    LONG result = WinVerifyTrust(nullptr, &action, &wintrustData);
    return result == ERROR_SUCCESS;
}
static BOOL MorphPEStructure(const std::wstring& filePath, HWND hWnd) {
    unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
    if (!hFile.get()) return FALSE;
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile.get(), &fileSize)) return FALSE;
    unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
    if (!hMapping.get()) return FALSE;
    unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
    if (!pMap.get()) return FALSE;
    BYTE* mapped = static_cast<BYTE*>(pMap.get());
    if (fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER)) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > static_cast<size_t>(fileSize.QuadPart)) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(mapped + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    size_t sectionsOffset = (BYTE*)IMAGE_FIRST_SECTION(nt) - mapped;
    if (sectionsOffset + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > static_cast<size_t>(fileSize.QuadPart)) return FALSE;
    nt->FileHeader.NumberOfSections += 1;
    PIMAGE_SECTION_HEADER lastSection = IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections - 2;
    PIMAGE_SECTION_HEADER newSection = lastSection + 1;
    DWORD align = nt->OptionalHeader.SectionAlignment;
    DWORD fileAlign = nt->OptionalHeader.FileAlignment;
    DWORD newVA = lastSection->VirtualAddress + ((lastSection->Misc.VirtualSize + align - 1) / align * align);
    DWORD newRaw = lastSection->PointerToRawData + ((lastSection->SizeOfRawData + fileAlign - 1) / fileAlign * fileAlign);
    strcpy_s((char*)newSection->Name, sizeof(newSection->Name), ".morph");
    newSection->Misc.VirtualSize = 4096;
    newSection->VirtualAddress = newVA;
    newSection->SizeOfRawData = 4096;
    newSection->PointerToRawData = newRaw;
    newSection->Characteristics = IMAGE_SCN_MEM_READ;
    LARGE_INTEGER newSize = fileSize;
    newSize.QuadPart += newSection->SizeOfRawData;
    SetFilePointerEx(hFile.get(), newSize, nullptr, FILE_BEGIN);
    SetEndOfFile(hFile.get());
    nt->OptionalHeader.SizeOfImage += newSection->Misc.VirtualSize;
    UpdateStatus(hWnd, L"Morphological PE structure attack applied");
    return TRUE;
}
static BOOL UpdatePEChecksumInPlace(const std::wstring& filePath, HWND hWnd) {
    unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
    if (!hFile.get()) {
        LogError(L"Cannot open file for checksum update", GetLastError());
        return FALSE;
    }
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile.get(), &fileSize)) return FALSE;
    unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr), &CloseHandle);
    if (!hMapping.get()) {
        LogError(L"Cannot create file mapping", GetLastError());
        return FALSE;
    }
    unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_WRITE, 0, 0, 0), &UnmapViewOfFile);
    if (!pMap.get()) {
        LogError(L"Cannot map view of file", GetLastError());
        return FALSE;
    }
    DWORD oldChecksum = 0, newChecksum = 0;
    DWORD headerSum = 0;
    if (!CheckSumMappedFile(pMap.get(), static_cast<DWORD>(fileSize.QuadPart), &headerSum, &newChecksum)) {
        LogError(L"Failed to calculate checksum", GetLastError());
        return FALSE;
    }
    void* mappedView = pMap.get();
    if (!mappedView) return FALSE;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)mappedView;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError(L"Invalid DOS header");
        return FALSE;
    }
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)mappedView + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        LogError(L"Invalid NT header");
        return FALSE;
    }
    ntHeader->OptionalHeader.CheckSum = newChecksum;
    std::wstringstream ss;
    ss << L"Checksum updated to 0x" << std::hex << newChecksum;
    UpdateStatus(hWnd, ss.str());
    return TRUE;
}
static size_t CalculatePESize(const std::wstring& filePath) {
    unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
    if (!hFile.get()) return 0;
    LARGE_INTEGER fileSize{};
    GetFileSizeEx(hFile.get(), &fileSize);
    unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READONLY, 0, 0, nullptr), &CloseHandle);
    if (!hMapping.get()) return 0;
    unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_READ, 0, 0, 0), &UnmapViewOfFile);
    if (!pMap.get()) return 0;
    BYTE* mapped = static_cast<BYTE*>(pMap.get());
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)mapped;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(mapped + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return 0;
    size_t peSize = 0;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i) {
        size_t sectionEnd = static_cast<size_t>(section[i].PointerToRawData) + section[i].SizeOfRawData;
        if (sectionEnd > peSize) peSize = sectionEnd;
    }
    PIMAGE_DATA_DIRECTORY sigDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (sigDir->Size > 0) {
        size_t certEnd = static_cast<size_t>(sigDir->VirtualAddress) + sigDir->Size;
        if (certEnd > peSize) peSize = certEnd;
    }
    return peSize;
}
static std::vector<BYTE> ExtractOverlay(const std::wstring& filePath, HWND hWnd) {
    std::vector<BYTE> overlayData;
    unique_handle hFile(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &CloseHandle);
    if (!hFile.get()) {
        LogError(L"Cannot open file for overlay extraction", GetLastError());
        return overlayData;
    }
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile.get(), &fileSize)) return overlayData;
    unique_handle hMapping(CreateFileMappingW(hFile.get(), nullptr, PAGE_READONLY, 0, 0, nullptr), &CloseHandle);
    if (!hMapping.get()) {
        LogError(L"Cannot create file mapping for overlay", GetLastError());
        return overlayData;
    }
    unique_mapview pMap(MapViewOfFile(hMapping.get(), FILE_MAP_READ, 0, 0, 0), &UnmapViewOfFile);
    if (!pMap.get()) {
        LogError(L"Cannot map view for overlay", GetLastError());
        return overlayData;
    }
    BYTE* mapped = static_cast<BYTE*>(pMap.get());
    if (!mapped) return overlayData;
    size_t peSize = CalculatePESize(filePath);
    if (static_cast<size_t>(fileSize.QuadPart) > peSize) {
        overlayData.resize(static_cast<size_t>(fileSize.QuadPart) - peSize);
        memcpy(overlayData.data(), mapped + peSize, overlayData.size());
        std::wstringstream ss;
        ss << L"Overlay data extracted: " << overlayData.size() << L" bytes";
        UpdateStatus(hWnd, ss.str());
    }
    else {
        UpdateStatus(hWnd, L"No overlay data found");
    }
    return overlayData;
}
static std::vector<BYTE> ExtractManifestData(HMODULE hModule, HWND hWnd) {
    std::vector<BYTE> manifestData;
    HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(1), MyMakeIntResource<LPCWSTR>(RT_MANIFEST_ID));
    if (!hRes) {
        LogError(L"No manifest resource found", GetLastError());
        return manifestData;
    }
    HGLOBAL hResData = LoadResource(hModule, hRes);
    if (!hResData) {
        LogError(L"Cannot load manifest resource", GetLastError());
        return manifestData;
    }
    BYTE* pResData = (BYTE*)LockResource(hResData);
    DWORD resSize = SizeofResource(hModule, hRes);
    if (!pResData || resSize == 0) {
        LogError(L"Cannot lock manifest resource", GetLastError());
        return manifestData;
    }
    manifestData.resize(resSize);
    memcpy(manifestData.data(), pResData, resSize);
    std::wstringstream ss;
    ss << L"Manifest data extracted: " << resSize << L" bytes";
    UpdateStatus(hWnd, ss.str());
    return manifestData;
}
static std::vector<BYTE> GenerateIconData(const Bitmap& bitmap, int width, int height) {
    std::vector<BYTE> iconData;
    IStream* pStream = nullptr;
    HRESULT hr = CreateStreamOnHGlobal(nullptr, TRUE, &pStream);
    if (FAILED(hr)) return iconData;
    Gdiplus::Bitmap* resizedBitmap = new Gdiplus::Bitmap(width, height, PixelFormat32bppARGB);
    Gdiplus::Graphics graphics(resizedBitmap);
    graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
    graphics.DrawImage(static_cast<Image*>(const_cast<Bitmap*>(&bitmap)), 0, 0, width, height);
    CLSID clsidPNG;
    hr = CLSIDFromString(L"{557CF406-1A04-11D3-9A73-0000F81EF32E}", &clsidPNG);
    if (FAILED(hr)) {
        delete resizedBitmap;
        pStream->Release();
        return iconData;
    }
    hr = resizedBitmap->Save(pStream, &clsidPNG, nullptr);
    delete resizedBitmap;
    if (FAILED(hr)) {
        pStream->Release();
        return iconData;
    }
    LARGE_INTEGER liZero = {};
    ULARGE_INTEGER ulSize;
    pStream->Seek(liZero, STREAM_SEEK_END, &ulSize);
    pStream->Seek(liZero, STREAM_SEEK_SET, nullptr);
    iconData.resize(static_cast<size_t>(ulSize.QuadPart));
    ULONG bytesRead;
    hr = pStream->Read(iconData.data(), static_cast<ULONG>(ulSize.QuadPart), &bytesRead);
    pStream->Release();
    if (FAILED(hr) || bytesRead != ulSize.QuadPart) {
        return std::vector<BYTE>();
    }
    return iconData;
}
static std::vector<IconResource> EnumerateIconGroups(HMODULE hModule, HWND hWnd) {
    std::vector<IconResource> iconGroups;
    auto enumFunc = [](HMODULE hModule, LPCWSTR lpType, LPWSTR lpName, LONG_PTR lParam) -> BOOL {
        auto* pIconGroups = reinterpret_cast<std::vector<IconResource>*>(lParam);
        IconResource res;
        res.isNameString = !IS_INTRESOURCE(lpName);
        if (res.isNameString) {
            res.name = lpName;
        }
        else {
            res.nameId = static_cast<WORD>(reinterpret_cast<ULONG_PTR>(lpName));
        }
        HRSRC hRes = FindResourceW(hModule, lpName, lpType);
        if (!hRes) return TRUE;
        HGLOBAL hResData = LoadResource(hModule, hRes);
        if (!hResData) return TRUE;
        BYTE* pResData = (BYTE*)LockResource(hResData);
        DWORD resSize = SizeofResource(hModule, hRes);
        if (!pResData || resSize < sizeof(GRPICONDIR)) return TRUE;
        res.groupData.resize(resSize);
        memcpy(res.groupData.data(), pResData, resSize);
        GRPICONDIR* pGrpIconDir = (GRPICONDIR*)pResData;
        res.isPrimary = (pIconGroups->empty() || pIconGroups->at(0).nameId != 1);
        for (WORD i = 0; i < pGrpIconDir->idCount; ++i) {
            res.iconIds.push_back(pGrpIconDir->idEntries[i].nID);
            res.iconSizes.emplace_back(pGrpIconDir->idEntries[i].bWidth, pGrpIconDir->idEntries[i].bHeight);
            res.bitCounts.push_back(pGrpIconDir->idEntries[i].wBitCount);
            HRSRC hIconRes = FindResourceW(hModule, MAKEINTRESOURCEW(pGrpIconDir->idEntries[i].nID), MyMakeIntResource<LPCWSTR>(RT_ICON_ID));
            if (!hIconRes) continue;
            HGLOBAL hIconResData = LoadResource(hModule, hIconRes);
            if (!hIconResData) continue;
            BYTE* pIconData = (BYTE*)LockResource(hIconResData);
            DWORD iconSize = SizeofResource(hModule, hIconRes);
            if (!pIconData || iconSize == 0) continue;
            std::vector<BYTE> iconData(iconSize);
            memcpy(iconData.data(), pIconData, iconSize);
            res.iconData.push_back(std::move(iconData));
        }
        pIconGroups->push_back(std::move(res));
        return TRUE;
        };
    EnumResourceNamesW(hModule, MyMakeIntResource<LPCWSTR>(RT_GROUP_ICON_ID), enumFunc, reinterpret_cast<LONG_PTR>(&iconGroups));
    std::wstringstream ss;
    ss << L"Enumerated " << iconGroups.size() << L" icon groups";
    UpdateStatus(hWnd, ss.str());
    return iconGroups;
}
static std::vector<ResourceInfo> EnumerateAllResources(HMODULE hModule, HWND hWnd) {
    std::vector<ResourceInfo> resources;
    auto enumTypes = [](HMODULE hModule, LPWSTR lpType, LONG_PTR lParam) -> BOOL {
        auto* pResources = reinterpret_cast<std::vector<ResourceInfo>*>(lParam);
        auto enumNames = [](HMODULE hModule, LPCWSTR lpType, LPWSTR lpName, LONG_PTR lParam) -> BOOL {
            auto* pResources = reinterpret_cast<std::vector<ResourceInfo>*>(lParam);
            auto enumLangs = [](HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLang, LONG_PTR lParam) -> BOOL {
                auto* pResources = reinterpret_cast<std::vector<ResourceInfo>*>(lParam);
                HRSRC hRes = FindResourceExW(hModule, lpType, lpName, wLang);
                if (!hRes) return TRUE;
                HGLOBAL hResData = LoadResource(hModule, hRes);
                if (!hResData) return TRUE;
                BYTE* pResData = (BYTE*)LockResource(hResData);
                DWORD resSize = SizeofResource(hModule, hRes);
                if (!pResData || resSize == 0) return TRUE;
                ResourceInfo res;
                res.type = lpType;
                res.name = lpName;
                res.langId = wLang;
                res.data.resize(resSize);
                memcpy(res.data.data(), pResData, resSize);
                pResources->push_back(std::move(res));
                return TRUE;
                };
            EnumResourceLanguagesW(hModule, lpType, lpName, enumLangs, lParam);
            return TRUE;
            };
        EnumResourceNamesW(hModule, lpType, enumNames, lParam);
        return TRUE;
        };
    EnumResourceTypesW(hModule, enumTypes, reinterpret_cast<LONG_PTR>(&resources));
    std::wstringstream ss;
    ss << L"Enumerated " << resources.size() << L" resources";
    UpdateStatus(hWnd, ss.str());
    return resources;
}
static std::wstring CreateUniqueTempDirectory(HWND hWnd) {
    WCHAR tempPath[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        LogError(L"Cannot get temp path", GetLastError());
        return L"";
    }
    WCHAR uniqueDir[MAX_PATH];
    GUID guid;
    HRESULT hr = CoCreateGuid(&guid);
    if (FAILED(hr)) {
        LogError(L"Cannot create GUID", hr);
        return L"";
    }
    StringCchPrintfW(uniqueDir, MAX_PATH, L"%sIconChanger_%08X", tempPath, guid.Data1);
    if (!CreateDirectoryW(uniqueDir, nullptr)) {
        LogError(L"Cannot create temp directory", GetLastError());
        return L"";
    }
    UpdateStatus(hWnd, L"Created temporary directory: " + std::wstring(uniqueDir));
    return uniqueDir;
}

static bool ReplaceExeIcons(const std::wstring& exePath, const std::wstring& iconPath, HWND hWnd, AppData& appData) {
    UpdateStatus(hWnd, L"Starting icon replacement...");

    std::wstring backupPath = exePath + L".bak";
    if (!CopyFileW(exePath.c_str(), backupPath.c_str(), FALSE)) {
        UpdateStatus(hWnd, L"Failed to create backup file.", GetLastError());
        return false;
    }
    unique_resource<const wchar_t*, decltype(&DeleteFileW)> backupGuard(backupPath.c_str(), &DeleteFileW);

    unique_resource<Bitmap*, decltype(&delete_object<Bitmap>)> pSourceBitmap(new Bitmap(iconPath.c_str()), &delete_object<Bitmap>);
    if (!pSourceBitmap.get() || pSourceBitmap.get()->GetLastStatus() != Gdiplus::Ok) {
        LogError(L"Failed to load source image.", 0);
        return false;
    }

    std::vector<std::vector<BYTE>> newIconData;
    for (const auto& size : STANDARD_ICON_SIZES) {
        newIconData.push_back(GenerateIconData(*pSourceBitmap.get(), size.first, size.second));
    }
    UpdateStatus(hWnd, L"Generated new icon data.");

    HANDLE hUpdate = BeginUpdateResourceW(exePath.c_str(), FALSE);
    if (!hUpdate) {
        LogError(L"BeginUpdateResource failed.", GetLastError());
        CopyFileW(backupPath.c_str(), exePath.c_str(), FALSE); // Restore backup
        return false;
    }

    for (const auto& res : appData.preservedResources) {
        if (res.isIconRelated()) {
            if (!UpdateResourceW(hUpdate, res.type, res.name, res.langId, NULL, 0)) {
                LogError(L"Failed to delete old icon resource.", GetLastError());
                EndUpdateResourceW(hUpdate, TRUE);
                CopyFileW(backupPath.c_str(), exePath.c_str(), FALSE); // Restore backup
                return false;
            }
        }
    }

    WORD langId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    size_t grpIconDirSize = sizeof(GRPICONDIR) - sizeof(GRPICONDIRENTRY) + newIconData.size() * sizeof(GRPICONDIRENTRY);
    std::vector<BYTE> groupData(grpIconDirSize);
    LPGRPICONDIR pGrpDir = reinterpret_cast<LPGRPICONDIR>(groupData.data());
    pGrpDir->idReserved = 0;
    pGrpDir->idType = 1;
    pGrpDir->idCount = static_cast<WORD>(newIconData.size());
    WORD nextIconId = 1;
    int entryIndex = 0;
    for (size_t i = 0; i < newIconData.size(); ++i) {
        if (newIconData[i].empty()) continue;
        LPGRPICONDIRENTRY pEntry = &pGrpDir->idEntries[entryIndex++];
        pEntry->bWidth = (BYTE)STANDARD_ICON_SIZES[i].first;
        pEntry->bHeight = (BYTE)STANDARD_ICON_SIZES[i].second;
        pEntry->bColorCount = 0;
        pEntry->bReserved = 0;
        pEntry->wPlanes = 1;
        pEntry->wBitCount = 32;
        pEntry->dwBytesInRes = (DWORD)newIconData[i].size();
        pEntry->nID = nextIconId;
        if (!UpdateResourceW(hUpdate, RT_ICON, MAKEINTRESOURCEW(nextIconId), langId, newIconData[i].data(), (DWORD)newIconData[i].size())) {
            LogError(L"Failed to update icon resource.", GetLastError());
            EndUpdateResourceW(hUpdate, TRUE);
            CopyFileW(backupPath.c_str(), exePath.c_str(), FALSE);
            return false;
        }
        nextIconId++;
    }

    if (!UpdateResourceW(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCEW(1), langId, groupData.data(), (DWORD)grpIconDirSize)) {
        LogError(L"Failed to update group icon resource.", GetLastError());
        EndUpdateResourceW(hUpdate, TRUE);
        CopyFileW(backupPath.c_str(), exePath.c_str(), FALSE);
        return false;
    }

    if (!EndUpdateResourceW(hUpdate, FALSE)) {
        LogError(L"EndUpdateResource failed.", GetLastError());
        CopyFileW(backupPath.c_str(), exePath.c_str(), FALSE);
        return false;
    }

    UpdateStatus(hWnd, L"Applying post-modification integrity patches...");
    size_t currentPeSize = CalculatePESize(exePath);
    auto handler = GetIntegrityHandler(appData.installerType);

    UpdateStatus(hWnd, L"Executing installer-specific integrity patches...");
    if (!handler->PatchOutIntegrityChecks(exePath, hWnd, currentPeSize)) {
        LogError(L"Failed to patch installer integrity checks.");
    }
    if (!handler->RemoveAdvancedHashes(exePath, hWnd, currentPeSize)) {
        LogError(L"Failed to remove advanced installer hashes.");
    }
    if (!handler->UpdateAfterModification(exePath, hWnd, currentPeSize)) {
        LogError(L"Failed to perform post-modification updates for installer.");
    }
    if (!handler->Repackage(exePath, hWnd)) {
        LogError(L"Failed to repackage installer.");
    }

    UpdateStatus(hWnd, L"Applying advanced PE structure modifications...");
    if (!MorphPEStructure(exePath, hWnd)) {
        LogError(L"Failed to morph PE structure.");
    }

    UpdateStatus(hWnd, L"Recalculating PE checksum...");
    if (!UpdatePEChecksumInPlace(exePath, hWnd)) {
        LogError(L"Failed to update PE checksum.");
    }

    UpdateStatus(hWnd, L"Re-signing executable with new signature...");
    if (!ResignExecutable(exePath, hWnd, true)) {
        LogError(L"Failed to resign executable.");
    }

    UpdateStatus(hWnd, L"Icon replacement completed successfully");
    appData.exeModified = true;
    backupGuard.reset(nullptr); // Success, so don't restore backup
    DeleteFileW(backupPath.c_str());
    return true;
}
static Bitmap* ExtractLargestIconBitmap(const std::wstring& exePath, HWND hWnd, AppData& appData) {
    unique_hmodule hModule(LoadLibraryExW(exePath.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE), &FreeLibrary);
    if (!hModule.get()) {
        LogError(L"Cannot load executable for icon extraction", GetLastError());
        return nullptr;
    }
    auto iconGroups = EnumerateIconGroups(hModule.get(), hWnd);
    if (iconGroups.empty()) {
        LogError(L"No icon groups found");
        return nullptr;
    }
    size_t maxSize = 0;
    const IconResource* largestGroup = nullptr;
    int largestIconIndex = -1;
    for (const auto& group : iconGroups) {
        for (size_t i = 0; i < group.iconSizes.size(); ++i) {
            int width = group.iconSizes[i].first == 0 ? 256 : group.iconSizes[i].first;
            int height = group.iconSizes[i].second == 0 ? 256 : group.iconSizes[i].second;
            size_t area = static_cast<size_t>(width) * height;
            if (area > maxSize) {
                maxSize = area;
                largestGroup = &group;
                largestIconIndex = static_cast<int>(i);
            }
        }
    }
    if (!largestGroup || largestIconIndex == -1) return nullptr;
    const auto& iconRawData = largestGroup->iconData[largestIconIndex];
    const BYTE png_signature[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    bool isPng = iconRawData.size() >= 8 && memcmp(iconRawData.data(), png_signature, 8) == 0;
    if (isPng) {
        IStream* pStream = SHCreateMemStream(iconRawData.data(), static_cast<UINT>(iconRawData.size()));
        if (!pStream) return nullptr;
        Bitmap* streamBitmap = Bitmap::FromStream(pStream);
        Bitmap* finalBitmap = nullptr;
        if (streamBitmap && streamBitmap->GetLastStatus() == Gdiplus::Ok) {
            finalBitmap = streamBitmap->Clone(0, 0, streamBitmap->GetWidth(), streamBitmap->GetHeight(), PixelFormat32bppARGB);
        }
        delete streamBitmap;
        pStream->Release();
        if (finalBitmap && finalBitmap->GetLastStatus() == Gdiplus::Ok) {
            return finalBitmap;
        }
        delete finalBitmap;
    }
    else {
        HICON hIcon = CreateIconFromResourceEx(const_cast<BYTE*>(iconRawData.data()), static_cast<DWORD>(iconRawData.size()), TRUE, 0x00030000, 0, 0, LR_DEFAULTCOLOR);
        if (!hIcon) return nullptr;
        Bitmap* bitmap = Bitmap::FromHICON(hIcon);
        DestroyIcon(hIcon);
        if (bitmap && bitmap->GetLastStatus() == Gdiplus::Ok) {
            return bitmap;
        }
        delete bitmap;
    }
    return nullptr;
}
static void DrawCheckerboard(HDC hdc, int x, int y, int width, int height, int squareSize) {
    HBRUSH hLightBrush = CreateSolidBrush(RGB(200, 200, 200));
    HBRUSH hDarkBrush = CreateSolidBrush(RGB(150, 150, 150));
    for (int i = 0; i < height; i += squareSize) {
        for (int j = 0; j < width; j += squareSize) {
            HBRUSH hBrush = ((i / squareSize + j / squareSize) % 2) ? hDarkBrush : hLightBrush;
            RECT rect = { x + j, y + i, x + j + squareSize, y + i + squareSize };
            FillRect(hdc, &rect, hBrush);
        }
    }
    DeleteObject(hLightBrush);
    DeleteObject(hDarkBrush);
}
static LRESULT CALLBACK StaticPreviewProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    AppData* pAppData = (AppData*)GetWindowLongPtr(GetParent(hWnd), GWLP_USERDATA);
    if (!pAppData) return DefSubclassProc(hWnd, msg, wParam, lParam);

    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT clientRect;
        GetClientRect(hWnd, &clientRect);
        int width = clientRect.right - clientRect.left;
        int height = clientRect.bottom - clientRect.top;
        HDC hdcMem = CreateCompatibleDC(hdc);
        HBITMAP hBitmap = CreateCompatibleBitmap(hdc, width, height);
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);
        DrawCheckerboard(hdcMem, 0, 0, width, height, 10);
        Bitmap* pBitmap = (uIdSubclass == IDC_EXE_PREVIEW) ? pAppData->pExeImage : pAppData->pImage;
        if (pBitmap) {
            Gdiplus::Graphics graphics(hdcMem);
            graphics.SetInterpolationMode(InterpolationModeHighQualityBicubic);
            graphics.DrawImage(pBitmap, 0, 0, width, height);
        }
        BitBlt(hdc, 0, 0, width, height, hdcMem, 0, 0, SRCCOPY);
        SelectObject(hdcMem, hOldBitmap);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        RemoveWindowSubclass(hWnd, StaticPreviewProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}
static void DrawButton(HDC hdc, RECT rect, bool isPressed, bool isHovered, bool darkTheme, UINT id) {
    COLORREF baseColor;
    switch (id) {
    case IDC_EXIT: baseColor = RGB(200, 0, 0); break;
    case IDC_REPLACE: baseColor = RGB(0, 200, 0); break;
    case IDC_LOAD_EXE: baseColor = RGB(0, 0, 200); break;
    case IDC_LOAD_IMAGE: baseColor = RGB(200, 200, 0); break;
    default: baseColor = RGB(200, 200, 200);
    }
    if (darkTheme) {
        baseColor = RGB(GetRValue(baseColor) / 2, GetGValue(baseColor) / 2, GetBValue(baseColor) / 2);
    }
    COLORREF bgColor = baseColor;
    if (isHovered) {
        bgColor = RGB(std::min(255, GetRValue(baseColor) + 30), std::min(255, GetGValue(baseColor) + 30), std::min(255, GetBValue(baseColor) + 30));
    }
    if (isPressed) {
        bgColor = RGB(std::max(0, GetRValue(baseColor) - 30), std::max(0, GetGValue(baseColor) - 30), std::max(0, GetBValue(baseColor) - 30));
    }
    HBRUSH hBrush = CreateSolidBrush(bgColor);
    FillRect(hdc, &rect, hBrush);
    DeleteObject(hBrush);
    COLORREF highlight = darkTheme ? RGB(100, 100, 100) : RGB(255, 255, 255);
    COLORREF shadow = darkTheme ? RGB(0, 0, 0) : RGB(128, 128, 128);
    if (isPressed) {
        std::swap(highlight, shadow);
    }
    HPEN hHighlight = CreatePen(PS_SOLID, 1, highlight);
    HPEN hShadow = CreatePen(PS_SOLID, 1, shadow);
    HPEN hOldPen = (HPEN)SelectObject(hdc, hHighlight);
    MoveToEx(hdc, rect.left, rect.top, NULL);
    LineTo(hdc, rect.right, rect.top);
    MoveToEx(hdc, rect.left, rect.top, NULL);
    LineTo(hdc, rect.left, rect.bottom);
    SelectObject(hdc, hShadow);
    MoveToEx(hdc, rect.left, rect.bottom - 1, NULL);
    LineTo(hdc, rect.right, rect.bottom - 1);
    MoveToEx(hdc, rect.right - 1, rect.top, NULL);
    LineTo(hdc, rect.right - 1, rect.bottom);
    SelectObject(hdc, hOldPen);
    DeleteObject(hHighlight);
    DeleteObject(hShadow);
}
static LRESULT CALLBACK ButtonSubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    AppData* pAppData = (AppData*)GetWindowLongPtr(GetParent(hWnd), GWLP_USERDATA);
    if (!pAppData) return DefSubclassProc(hWnd, msg, wParam, lParam);

    switch (msg) {
    case WM_MOUSEMOVE: {
        bool wasHovered = GetPropW(hWnd, HOVER_PROP) != nullptr;
        SetPropW(hWnd, HOVER_PROP, (HANDLE)1);
        if (!wasHovered) InvalidateRect(hWnd, nullptr, TRUE);
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hWnd, 0 };
        TrackMouseEvent(&tme);
        break;
    }
    case WM_MOUSELEAVE:
        RemovePropW(hWnd, HOVER_PROP);
        InvalidateRect(hWnd, nullptr, TRUE);
        break;
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rect;
        GetClientRect(hWnd, &rect);
        bool isPressed = (GetKeyState(VK_LBUTTON) & 0x8000) && GetCapture() == hWnd;
        bool isHovered = GetPropW(hWnd, HOVER_PROP) != nullptr;
        DrawButton(hdc, rect, isPressed, isHovered, pAppData->darkTheme, static_cast<UINT>(uIdSubclass));
        WCHAR text[256];
        GetWindowTextW(hWnd, text, 256);
        HFONT hOldFont = (HFONT)SelectObject(hdc, pAppData->hFont);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, pAppData->darkTheme ? RGB(255, 255, 255) : RGB(0, 0, 0));
        DrawTextW(hdc, text, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, hOldFont);
        EndPaint(hWnd, &ps);
        return 0;
    }
    case WM_DESTROY:
        RemovePropW(hWnd, HOVER_PROP);
        RemoveWindowSubclass(hWnd, ButtonSubclassProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}
static void LayoutControls(HWND hWnd, AppData& appData) {
    RECT clientRect;
    GetClientRect(hWnd, &clientRect);
    int width = clientRect.right - clientRect.left;
    int height = clientRect.bottom - clientRect.top;
    float sf = appData.scaleFactor;
    int margin = static_cast<int>(20 * sf);
    int buttonWidth = static_cast<int>(150 * sf);
    int buttonHeight = static_cast<int>(50 * sf);
    int previewSize = static_cast<int>(300 * sf);
    int labelHeight = static_cast<int>(20 * sf);
    int titleHeight = static_cast<int>(30 * sf);
    int infoHeight = static_cast<int>(20 * sf);
    int progressHeight = static_cast<int>(20 * sf);
    int logHeight = static_cast<int>(150 * sf);
    int currentY = margin;

    SetWindowPos(GetDlgItem(hWnd, IDC_TITLE_LABEL), nullptr, 0, currentY, width, titleHeight, SWP_NOZORDER | SWP_NOMOVE);
    currentY += titleHeight + margin;

    int componentsWidth = previewSize * 2 + margin;
    int startX = (width - componentsWidth) / 2;
    int exeX = startX;
    int imageX = startX + previewSize + margin;

    SetWindowPos(GetDlgItem(hWnd, IDC_LABEL_EXE), nullptr, exeX, currentY, previewSize, labelHeight, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hWnd, IDC_LABEL_IMAGE), nullptr, imageX, currentY, previewSize, labelHeight, SWP_NOZORDER);
    currentY += labelHeight + 5;

    SetWindowPos(GetDlgItem(hWnd, IDC_EXE_PREVIEW), nullptr, exeX, currentY, previewSize, previewSize, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hWnd, IDC_IMAGE_PREVIEW), nullptr, imageX, currentY, previewSize, previewSize, SWP_NOZORDER);
    currentY += previewSize + margin;

    int exeButtonX = exeX + (previewSize - buttonWidth) / 2;
    int imageButtonX = imageX + (previewSize - buttonWidth) / 2;
    SetWindowPos(GetDlgItem(hWnd, IDC_LOAD_EXE), nullptr, exeButtonX, currentY, buttonWidth, buttonHeight, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hWnd, IDC_LOAD_IMAGE), nullptr, imageButtonX, currentY, buttonWidth, buttonHeight, SWP_NOZORDER);
    currentY += buttonHeight + margin;

    SetWindowPos(GetDlgItem(hWnd, IDC_REPLACE), nullptr, (width - buttonWidth) / 2, currentY, buttonWidth, buttonHeight, SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hWnd, IDC_EXIT), nullptr, width - margin - buttonWidth, currentY, buttonWidth, buttonHeight, SWP_NOZORDER);
    currentY += buttonHeight + margin;

    SetWindowPos(GetDlgItem(hWnd, IDC_STATUS_LABEL), nullptr, margin, currentY, width - 2 * margin, labelHeight, SWP_NOZORDER);
    currentY += labelHeight + 5;
    SetWindowPos(GetDlgItem(hWnd, IDC_LOG_WINDOW), nullptr, margin, currentY, width - 2 * margin, logHeight, SWP_NOZORDER);
    currentY += logHeight + 5;
    SetWindowPos(GetDlgItem(hWnd, IDC_PROGRESS_BAR), nullptr, margin, currentY, width - 2 * margin, progressHeight, SWP_NOZORDER);
}
static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AppData* pAppData;
    if (msg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pAppData = (AppData*)pCreate->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)pAppData);
    }
    else {
        pAppData = (AppData*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    }
    if (!pAppData) return DefWindowProcW(hWnd, msg, wParam, lParam);

    switch (msg) {
    case WM_CREATE: {
        pAppData->darkTheme = IsDarkTheme();
        float dpi = static_cast<float>(GetDpiForWindow(hWnd));
        pAppData->scaleFactor = dpi / 96.0f;
        NONCLIENTMETRICSW ncm = { sizeof(ncm) };
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        pAppData->hFont = CreateFontIndirectW(&ncm.lfMessageFont);
        ncm.lfMessageFont.lfWeight = FW_BOLD;
        pAppData->hTitleFont = CreateFontIndirectW(&ncm.lfMessageFont);
        ncm.lfMessageFont.lfHeight = static_cast<LONG>(ncm.lfMessageFont.lfHeight * 0.8f);
        pAppData->hLabelFont = CreateFontIndirectW(&ncm.lfMessageFont);
        ncm.lfMessageFont.lfHeight = static_cast<LONG>(ncm.lfMessageFont.lfHeight * 0.9f);
        pAppData->hInfoFont = CreateFontIndirectW(&ncm.lfMessageFont);
        CreateWindowW(L"STATIC", L"Icon Changer", WS_CHILD | WS_VISIBLE | SS_CENTER, 0, 0, 0, 0, hWnd, (HMENU)IDC_TITLE_LABEL, nullptr, nullptr);
        CreateWindowW(L"STATIC", L"Executable Preview", WS_CHILD | WS_VISIBLE | SS_CENTER, 0, 0, 0, 0, hWnd, (HMENU)IDC_LABEL_EXE, nullptr, nullptr);
        CreateWindowW(L"STATIC", L"Image Preview", WS_CHILD | WS_VISIBLE | SS_CENTER, 0, 0, 0, 0, hWnd, (HMENU)IDC_LABEL_IMAGE, nullptr, nullptr);
        HWND hExePreview = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOTIFY, 0, 0, 0, 0, hWnd, (HMENU)IDC_EXE_PREVIEW, nullptr, nullptr);
        HWND hImgPreview = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_NOTIFY, 0, 0, 0, 0, hWnd, (HMENU)IDC_IMAGE_PREVIEW, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Load Exe", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0, hWnd, (HMENU)IDC_LOAD_EXE, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Load Image", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0, hWnd, (HMENU)IDC_LOAD_IMAGE, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Replace", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0, hWnd, (HMENU)IDC_REPLACE, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Exit", WS_CHILD | WS_VISIBLE | BS_OWNERDRAW, 0, 0, 0, 0, hWnd, (HMENU)IDC_EXIT, nullptr, nullptr);
        CreateWindowW(L"STATIC", L"Status: Ready", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hWnd, (HMENU)IDC_STATUS_LABEL, nullptr, nullptr);
        CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 0, 0, 0, 0, hWnd, (HMENU)IDC_LOG_WINDOW, nullptr, nullptr);
        CreateWindowW(PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 0, 0, 0, 0, hWnd, (HMENU)IDC_PROGRESS_BAR, nullptr, nullptr);

        SetWindowSubclass(hExePreview, StaticPreviewProc, IDC_EXE_PREVIEW, 0);
        SetWindowSubclass(hImgPreview, StaticPreviewProc, IDC_IMAGE_PREVIEW, 0);
        SetWindowSubclass(GetDlgItem(hWnd, IDC_LOAD_EXE), ButtonSubclassProc, IDC_LOAD_EXE, 0);
        SetWindowSubclass(GetDlgItem(hWnd, IDC_LOAD_IMAGE), ButtonSubclassProc, IDC_LOAD_IMAGE, 0);
        SetWindowSubclass(GetDlgItem(hWnd, IDC_REPLACE), ButtonSubclassProc, IDC_REPLACE, 0);
        SetWindowSubclass(GetDlgItem(hWnd, IDC_EXIT), ButtonSubclassProc, IDC_EXIT, 0);

        SendMessageW(GetDlgItem(hWnd, IDC_TITLE_LABEL), WM_SETFONT, (WPARAM)pAppData->hTitleFont, TRUE);
        SendMessageW(GetDlgItem(hWnd, IDC_LABEL_EXE), WM_SETFONT, (WPARAM)pAppData->hLabelFont, TRUE);
        SendMessageW(GetDlgItem(hWnd, IDC_LABEL_IMAGE), WM_SETFONT, (WPARAM)pAppData->hLabelFont, TRUE);
        SendMessageW(GetDlgItem(hWnd, IDC_STATUS_LABEL), WM_SETFONT, (WPARAM)pAppData->hFont, TRUE);
        SendMessageW(GetDlgItem(hWnd, IDC_LOG_WINDOW), WM_SETFONT, (WPARAM)pAppData->hFont, TRUE);

        LayoutControls(hWnd, *pAppData);
        SendMessageW(GetDlgItem(hWnd, IDC_PROGRESS_BAR), PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        break;
    }
    case WM_SIZE:
        LayoutControls(hWnd, *pAppData);
        break;
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_LOAD_EXE: {
            WCHAR fileName[MAX_PATH] = L"";
            OPENFILENAMEW ofn = { sizeof(ofn) };
            ofn.hwndOwner = hWnd;
            ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = fileName;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                pAppData->exePath = fileName;
                unique_hmodule hModule(LoadLibraryExW(fileName, nullptr, LOAD_LIBRARY_AS_DATAFILE), &FreeLibrary);
                if (hModule.get()) {
                    pAppData->preservedResources = EnumerateAllResources(hModule.get(), hWnd);
                    pAppData->manifestData = ExtractManifestData(hModule.get(), hWnd);
                    pAppData->overlayData = ExtractOverlay(fileName, hWnd);
                    pAppData->iconGroups = EnumerateIconGroups(hModule.get(), hWnd);
                    unique_handle hFileExe(CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS, nullptr), &CloseHandle);
                    if (hFileExe.get()) {
                        GetFileTime(hFileExe.get(), &pAppData->creationTime, &pAppData->lastAccessTime, &pAppData->lastWriteTime);
                        pAppData->fileAttributes = GetFileAttributesW(fileName);
                    }
                    if (pAppData->pExeImage) delete pAppData->pExeImage;
                    pAppData->pExeImage = ExtractLargestIconBitmap(fileName, hWnd, *pAppData);
                    InvalidateRect(GetDlgItem(hWnd, IDC_EXE_PREVIEW), nullptr, TRUE);
                    std::vector<char> buffer(BUFFER_SIZE_LARGE);
                    DWORD bytesRead = 0;
                    if (hFileExe.get()) {
                        SetFilePointer(hFileExe.get(), 0, nullptr, FILE_BEGIN);
                        BOOL readResult = ReadFile(hFileExe.get(), buffer.data(), BUFFER_SIZE_LARGE, &bytesRead, nullptr);
                        if (readResult && bytesRead > 0) {
                            std::string bufferStr(buffer.data(), bytesRead);
                            if (bufferStr.find(NSIS_SIGNATURE) != std::string::npos) pAppData->installerType = NSIS_SIGNATURE;
                            else if (bufferStr.find(INNO_SIGNATURE) != std::string::npos) pAppData->installerType = INNO_SIGNATURE;
                            else if (bufferStr.find(INSTALLSHIELD_SIGNATURE) != std::string::npos) pAppData->installerType = INSTALLSHIELD_SIGNATURE;
                            else if (bufferStr.find(SFX_ZIP_SIGNATURE) != std::string::npos) pAppData->installerType = SFX_ZIP_SIGNATURE;
                            else if (bufferStr.find(ADVANCED_MSI_SIGNATURE) != std::string::npos) pAppData->installerType = ADVANCED_MSI_SIGNATURE;
                            else if (bufferStr.find(WIX_SIGNATURE) != std::string::npos) pAppData->installerType = WIX_SIGNATURE;
                            else if (bufferStr.find(CLICKTEAM_SIGNATURE) != std::string::npos) pAppData->installerType = CLICKTEAM_SIGNATURE;
                            else if (bufferStr.find(ADVANCED_INSTALLER_SIGNATURE) != std::string::npos) pAppData->installerType = ADVANCED_INSTALLER_SIGNATURE;
                            else if (bufferStr.find(GHOST_SIGNATURE) != std::string::npos) pAppData->installerType = GHOST_SIGNATURE;
                            else pAppData->installerType = "Unknown";
                        }
                    }
                    UpdateStatus(hWnd, L"Executable loaded: " + pAppData->exePath);
                }
                else {
                    UpdateStatus(hWnd, L"Failed to load executable", GetLastError());
                }
            }
            break;
        }
        case IDC_LOAD_IMAGE: {
            WCHAR fileName[MAX_PATH] = L"";
            OPENFILENAMEW ofn = { sizeof(ofn) };
            ofn.hwndOwner = hWnd;
            ofn.lpstrFilter = L"Image Files (*.png;*.ico;*.bmp)\0*.png;*.ico;*.bmp\0All Files (*.*)\0*.*\0";
            ofn.lpstrFile = fileName;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
            if (GetOpenFileNameW(&ofn)) {
                pAppData->imagePath = fileName;
                if (pAppData->pImage) delete pAppData->pImage;
                pAppData->pImage = new Bitmap(fileName);
                if (pAppData->pImage->GetLastStatus() == Gdiplus::Ok) {
                    InvalidateRect(GetDlgItem(hWnd, IDC_IMAGE_PREVIEW), nullptr, TRUE);
                    UpdateStatus(hWnd, L"Image loaded: " + std::wstring(fileName));
                }
                else {
                    delete pAppData->pImage;
                    pAppData->pImage = nullptr;
                    pAppData->imagePath.clear();
                    UpdateStatus(hWnd, L"Failed to load image");
                }
            }
            break;
        }
        case IDC_REPLACE: {
            if (pAppData->exePath.empty() || pAppData->imagePath.empty() || !pAppData->pImage) {
                UpdateStatus(hWnd, L"Select both executable and image first");
                break;
            }
            if (pAppData->isReplacing.exchange(true)) break;
            SendMessageW(GetDlgItem(hWnd, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0);
            std::thread([hWnd, pAppData]() {
                SendMessageW(GetDlgItem(hWnd, IDC_PROGRESS_BAR), PBM_SETPOS, 10, 0);
                if (ReplaceExeIcons(pAppData->exePath, pAppData->imagePath, hWnd, *pAppData)) {
                    SendMessageW(GetDlgItem(hWnd, IDC_PROGRESS_BAR), PBM_SETPOS, 100, 0);
                    PostMessageW(hWnd, WM_OPERATION_COMPLETE, 1, 0);
                }
                else {
                    SendMessageW(GetDlgItem(hWnd, IDC_PROGRESS_BAR), PBM_SETPOS, 0, 0);
                    PostMessageW(hWnd, WM_OPERATION_COMPLETE, 0, 0);
                }
                pAppData->isReplacing.store(false);
                }).detach();
            break;
        }
        case IDC_EXIT:
            DestroyWindow(hWnd);
            break;
        }
        break;
    }
    case WM_OPERATION_COMPLETE: {
        EnableWindow(GetDlgItem(hWnd, IDC_REPLACE), TRUE);
        if (wParam) {
            UpdateStatus(hWnd, L"Icon replacement completed");
            if (pAppData->pExeImage) delete pAppData->pExeImage;
            pAppData->pExeImage = ExtractLargestIconBitmap(pAppData->exePath, hWnd, *pAppData);
            InvalidateRect(GetDlgItem(hWnd, IDC_EXE_PREVIEW), nullptr, TRUE);
        }
        else {
            UpdateStatus(hWnd, L"Icon replacement failed");
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        if (pAppData->darkTheme) {
            SetBkColor(hdc, RGB(30, 30, 30));
            SetTextColor(hdc, RGB(255, 255, 255));
            return (LRESULT)CreateSolidBrush(RGB(30, 30, 30));
        }
        return 0;
    }
    case WM_CTLCOLORBTN: {
        HDC hdc = (HDC)wParam;
        if (pAppData->darkTheme) {
            SetBkColor(hdc, RGB(50, 50, 50));
            SetTextColor(hdc, RGB(255, 255, 255));
            return (LRESULT)CreateSolidBrush(RGB(50, 50, 50));
        }
        return 0;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        if (pAppData->darkTheme) {
            SetBkColor(hdc, RGB(40, 40, 40));
            SetTextColor(hdc, RGB(255, 255, 255));
            return (LRESULT)CreateSolidBrush(RGB(40, 40, 40));
        }
        return 0;
    }
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}
static bool IsDarkTheme() {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExW(hKey, L"AppsUseLightTheme", nullptr, nullptr, (LPBYTE)&value, &size);
        RegCloseKey(hKey);
    }
    return value == 0;
}
static int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ PWSTR pCmdLine, _In_ int nCmdShow) {
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) {
        LogError(L"Failed to initialize COM library.", hr);
        GdiplusShutdown(gdiplusToken);
        return 1;
    }
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    logFilePath = std::wstring(tempPath) + L"IconChanger.log";
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"IconChangerClass";
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_ICONCHANGEREXE));
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(IsDarkTheme() ? RGB(30, 30, 30) : RGB(255, 255, 255));
    RegisterClassExW(&wc);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    AppData appData;
    int xPos = (screenWidth - appData.windowWidth) / 2;
    int yPos = (screenHeight - appData.height) / 2;
    HWND hWnd = CreateWindowExW(0, L"IconChangerClass", L"Icon Changer", WS_OVERLAPPEDWINDOW,
        xPos, yPos, appData.windowWidth, appData.height, nullptr, nullptr, hInstance, &appData);
    if (!hWnd) {
        LogError(L"Cannot create window", GetLastError());
        GdiplusShutdown(gdiplusToken);
        CoUninitialize();
        return 1;
    }
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessage(hWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    GdiplusShutdown(gdiplusToken);
    DeleteObject(wc.hbrBackground);
    CoUninitialize();
    return static_cast<int>(msg.wParam);
}
