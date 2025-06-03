
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <iostream>

std::wstring GetWindowTitle(HWND hwnd) {
    wchar_t title[256] = {0};
    GetWindowTextW(hwnd, title, sizeof(title)/sizeof(wchar_t));
    return std::wstring(title);
}

std::wstring GetProcessPath(DWORD pid) {
    std::wstring result = L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        wchar_t path[MAX_PATH] = {0};
        if (GetModuleFileNameExW(hProcess, NULL, path, MAX_PATH)) {
            result = path;
        }
        CloseHandle(hProcess);
    }
    return result;
}

std::wstring ToLower(const std::wstring& s) {
    std::wstring out = s;
    for (auto& c : out) c = towlower(c);
    return out;
}

bool IsSafeApp(const std::wstring& processPathLower) {
    std::vector<std::wstring> safeKeywords = {
        L"obs", L"discord", L"steam", L"hidguardian", L"xbox",
        L"wireless", L"nvidia", L"radeon", L"amd", L"rtx",
        L"gamebar", L"corsair", L"razer", L"steelseries"
    };
    for (const auto& kw : safeKeywords) {
        if (processPathLower.find(kw) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool IsSuspiciousOverlay(HWND hwnd) {
    if (!IsWindowVisible(hwnd))
        return false;

    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_LAYERED) && (exStyle & WS_EX_TOPMOST)) {
        BYTE alpha = 255;
        COLORREF colorKey = 0;
        DWORD flags = 0;

        if (GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags) && alpha < 50) {
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            std::wstring procPath = ToLower(GetProcessPath(pid));
            if (!IsSafeApp(procPath)) {
                return true;
            }
        }
    }
    return false;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (IsSuspiciousOverlay(hwnd)) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        std::wcout << L"[!] Suspicious Overlay Detected:\n";
        std::wcout << L"    HWND: 0x" << hwnd << std::endl;
        std::wcout << L"    Title: " << GetWindowTitle(hwnd) << std::endl;
        std::wcout << L"    PID: " << pid << std::endl;
        std::wcout << L"    Process Path: " << GetProcessPath(pid) << std::endl << std::endl;
    }
    return TRUE;
}

int main() {
    std::wcout << L"Starting Call of Duty Overlay Detection..." << std::endl << std::endl;
    EnumWindows(EnumWindowsProc, 0);
    std::wcout << L"Scan complete." << std::endl;
    return 0;
}
