// NetlogonSecureChannelChecker.cpp
// Ayi NEDJIMI Consultants - WinToolsSuite
// Outil de vérification du canal sécurisé Netlogon (secure channel)

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <lm.h>
#include <winevt.h>
#include <commctrl.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ===== RAII AutoHandle =====
class AutoHandle {
    HANDLE h;
public:
    AutoHandle(HANDLE handle = nullptr) : h(handle) {}
    ~AutoHandle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    operator HANDLE() const { return h; }
    HANDLE* operator&() { return &h; }
    AutoHandle(const AutoHandle&) = delete;
    AutoHandle& operator=(const AutoHandle&) = delete;
};

// ===== Structures =====
struct NetlogonStatus {
    std::wstring domaine;
    std::wstring etatCanal;
    std::wstring signing;
    std::wstring sealing;
    std::wstring strongKey;
    std::wstring alertes;
};

// ===== Globales =====
HWND g_hMainWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hStatusBar = nullptr;
HWND g_hBtnTest = nullptr;
HWND g_hBtnConfig = nullptr;
HWND g_hBtnRepair = nullptr;
HWND g_hBtnExport = nullptr;

std::vector<NetlogonStatus> g_statuses;
std::mutex g_dataMutex;
std::wstring g_logFilePath;

constexpr int ID_BTN_TEST = 1001;
constexpr int ID_BTN_CONFIG = 1002;
constexpr int ID_BTN_REPAIR = 1003;
constexpr int ID_BTN_EXPORT = 1004;
constexpr int ID_LISTVIEW = 2001;
constexpr int ID_STATUSBAR = 3001;

// ===== Logging =====
void InitLog() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    g_logFilePath = std::wstring(tempPath) + L"WinTools_NetlogonSecureChannelChecker_log.txt";
}

void Log(const std::wstring& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::wofstream logFile(g_logFilePath, std::ios::app);
    if (logFile.is_open()) {
        logFile << std::setfill(L'0')
                << std::setw(4) << st.wYear << L"-"
                << std::setw(2) << st.wMonth << L"-"
                << std::setw(2) << st.wDay << L" "
                << std::setw(2) << st.wHour << L":"
                << std::setw(2) << st.wMinute << L":"
                << std::setw(2) << st.wSecond << L" | "
                << message << std::endl;
        logFile.close();
    }
}

// ===== Utilitaires Registre =====
DWORD ReadRegistryDWORD(HKEY hKeyRoot, const wchar_t* subKey, const wchar_t* valueName, DWORD defaultValue = 0) {
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return defaultValue;
    }

    DWORD value = defaultValue;
    DWORD bufferSize = sizeof(DWORD);
    DWORD type;

    RegQueryValueExW(hKey, valueName, nullptr, &type, (LPBYTE)&value, &bufferSize);
    RegCloseKey(hKey);

    return value;
}

std::wstring GetDomainName() {
    LPWSTR domainName = nullptr;
    NETSETUP_JOIN_STATUS joinStatus;

    NET_API_STATUS status = NetGetJoinInformation(nullptr, &domainName, &joinStatus);

    if (status == NERR_Success) {
        std::wstring result;
        if (joinStatus == NetSetupDomainName) {
            result = domainName;
        } else {
            result = L"Workgroup / Non joint au domaine";
        }
        NetApiBufferFree(domainName);
        return result;
    }

    return L"Inconnu";
}

// ===== ListView =====
void InitListView() {
    LVCOLUMNW lvc = {0};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    lvc.fmt = LVCFMT_LEFT;

    lvc.pszText = (LPWSTR)L"Domaine";
    lvc.cx = 180;
    ListView_InsertColumn(g_hListView, 0, &lvc);

    lvc.pszText = (LPWSTR)L"État Canal";
    lvc.cx = 150;
    ListView_InsertColumn(g_hListView, 1, &lvc);

    lvc.pszText = (LPWSTR)L"Signing";
    lvc.cx = 120;
    ListView_InsertColumn(g_hListView, 2, &lvc);

    lvc.pszText = (LPWSTR)L"Sealing";
    lvc.cx = 120;
    ListView_InsertColumn(g_hListView, 3, &lvc);

    lvc.pszText = (LPWSTR)L"Strong Key";
    lvc.cx = 120;
    ListView_InsertColumn(g_hListView, 4, &lvc);

    lvc.pszText = (LPWSTR)L"Alertes";
    lvc.cx = 250;
    ListView_InsertColumn(g_hListView, 5, &lvc);

    ListView_SetExtendedListViewStyle(g_hListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
}

void UpdateListView() {
    std::lock_guard<std::mutex> lock(g_dataMutex);

    ListView_DeleteAllItems(g_hListView);

    for (size_t i = 0; i < g_statuses.size(); ++i) {
        LVITEMW lvi = {0};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = (int)i;

        lvi.iSubItem = 0;
        lvi.pszText = (LPWSTR)g_statuses[i].domaine.c_str();
        ListView_InsertItem(g_hListView, &lvi);

        ListView_SetItemText(g_hListView, (int)i, 1, (LPWSTR)g_statuses[i].etatCanal.c_str());
        ListView_SetItemText(g_hListView, (int)i, 2, (LPWSTR)g_statuses[i].signing.c_str());
        ListView_SetItemText(g_hListView, (int)i, 3, (LPWSTR)g_statuses[i].sealing.c_str());
        ListView_SetItemText(g_hListView, (int)i, 4, (LPWSTR)g_statuses[i].strongKey.c_str());
        ListView_SetItemText(g_hListView, (int)i, 5, (LPWSTR)g_statuses[i].alertes.c_str());
    }

    std::wstring status = L"Statuts vérifiés: " + std::to_wstring(g_statuses.size());
    SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)status.c_str());
}

// ===== Test Secure Channel =====
void TestSecureChannel() {
    Log(L"Début test secure channel Netlogon");

    std::vector<NetlogonStatus> statuses;
    NetlogonStatus status;

    std::wstring domainName = GetDomainName();
    status.domaine = domainName;

    if (domainName == L"Workgroup / Non joint au domaine" || domainName == L"Inconnu") {
        status.etatCanal = L"Non applicable";
        status.signing = L"-";
        status.sealing = L"-";
        status.strongKey = L"-";
        status.alertes = L"Machine non jointe à un domaine";
        statuses.push_back(status);

        {
            std::lock_guard<std::mutex> lock(g_dataMutex);
            g_statuses = statuses;
        }

        Log(L"Machine non jointe au domaine");
        PostMessageW(g_hMainWnd, WM_USER + 1, 0, 0);
        return;
    }

    // Tester le secure channel via I_NetLogonControl2
    // Note: Cette API nécessite des privilèges élevés
    LPBYTE buffer = nullptr;
    NET_API_STATUS apiStatus = I_NetLogonControl2(
        nullptr,
        NETLOGON_CONTROL_TC_QUERY,
        2,
        (LPBYTE)&domainName,
        &buffer
    );

    if (apiStatus == NERR_Success) {
        status.etatCanal = L"OK - Trust intact";
        status.alertes = L"Aucune";
        Log(L"Secure channel OK");

        if (buffer != nullptr) {
            NetApiBufferFree(buffer);
        }
    } else if (apiStatus == ERROR_NO_LOGON_SERVERS) {
        status.etatCanal = L"ERREUR - Pas de DC accessible";
        status.alertes = L"CRITIQUE: Aucun contrôleur de domaine accessible";
        Log(L"Erreur: Pas de DC accessible");
    } else if (apiStatus == ERROR_NO_TRUST_LSA_SECRET) {
        status.etatCanal = L"ERREUR - Trust rompu";
        status.alertes = L"CRITIQUE: Relation d'approbation rompue";
        Log(L"Erreur: Trust rompu");
    } else {
        status.etatCanal = L"ERREUR - Code " + std::to_wstring(apiStatus);
        status.alertes = L"Erreur lors du test: " + std::to_wstring(apiStatus);
        Log(L"Erreur test secure channel: " + std::to_wstring(apiStatus));
    }

    // Lire configuration Netlogon depuis le registre
    const wchar_t* netlogonKey = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";

    DWORD requireSign = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"RequireSignOrSeal", 0);
    DWORD requireStrongKey = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"RequireStrongKey", 0);
    DWORD sealSecureChannel = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"SealSecureChannel", 1);
    DWORD signSecureChannel = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"SignSecureChannel", 1);

    status.signing = signSecureChannel == 1 ? L"Activé" : L"Désactivé";
    status.sealing = sealSecureChannel == 1 ? L"Activé" : L"Désactivé";
    status.strongKey = requireStrongKey == 1 ? L"Requis" : L"Non requis";

    // Vérifications de sécurité
    if (requireSign == 0) {
        status.alertes += L" | ATTENTION: SignOrSeal non requis";
        Log(L"ALERTE: RequireSignOrSeal désactivé");
    }

    if (requireStrongKey == 0) {
        status.alertes += L" | ATTENTION: StrongKey non requis (vulnérable)";
        Log(L"ALERTE: RequireStrongKey désactivé (vulnérable Zerologon)");
    }

    if (signSecureChannel == 0) {
        status.alertes += L" | ATTENTION: Signing désactivé";
        Log(L"ALERTE: SignSecureChannel désactivé");
    }

    if (sealSecureChannel == 0) {
        status.alertes += L" | ATTENTION: Sealing désactivé";
        Log(L"ALERTE: SealSecureChannel désactivé");
    }

    statuses.push_back(status);

    // Vérifier les événements d'échec de secure channel
    EVT_HANDLE hResults = EvtQuery(nullptr, L"System",
        L"*[System[Provider[@Name='NETLOGON'] and EventID=5719]]",
        EvtQueryChannelPath | EvtQueryReverseDirection);

    if (hResults) {
        EVT_HANDLE hEvent = nullptr;
        DWORD returned = 0;

        if (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned)) {
            NetlogonStatus eventStatus;
            eventStatus.domaine = L"Événement récent";
            eventStatus.etatCanal = L"Échec détecté";
            eventStatus.signing = L"-";
            eventStatus.sealing = L"-";
            eventStatus.strongKey = L"-";
            eventStatus.alertes = L"Event ID 5719: Échec secure channel récent";
            statuses.push_back(eventStatus);

            Log(L"Event ID 5719 détecté: Échec secure channel");
            EvtClose(hEvent);
        }

        EvtClose(hResults);
    }

    {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        g_statuses = statuses;
    }

    Log(L"Test secure channel terminé");

    PostMessageW(g_hMainWnd, WM_USER + 1, 0, 0);
}

// ===== Vérifier configuration =====
void VerifyConfig() {
    Log(L"Vérification configuration Netlogon");

    std::vector<NetlogonStatus> statuses;
    const wchar_t* netlogonKey = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters";

    // RequireSignOrSeal
    NetlogonStatus st1;
    st1.domaine = L"RequireSignOrSeal";
    DWORD requireSign = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"RequireSignOrSeal", 0);
    st1.etatCanal = requireSign == 1 ? L"Activé" : L"Désactivé";
    st1.signing = L"-";
    st1.sealing = L"-";
    st1.strongKey = L"-";
    st1.alertes = requireSign == 1 ? L"Bon" : L"ATTENTION: Désactiver expose aux attaques";
    statuses.push_back(st1);

    // RequireStrongKey
    NetlogonStatus st2;
    st2.domaine = L"RequireStrongKey";
    DWORD requireStrongKey = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"RequireStrongKey", 0);
    st2.etatCanal = requireStrongKey == 1 ? L"Activé" : L"Désactivé";
    st2.signing = L"-";
    st2.sealing = L"-";
    st2.strongKey = L"-";
    st2.alertes = requireStrongKey == 1 ? L"Bon" : L"CRITIQUE: Vulnérable Zerologon (CVE-2020-1472)";
    statuses.push_back(st2);

    // SignSecureChannel
    NetlogonStatus st3;
    st3.domaine = L"SignSecureChannel";
    DWORD signSecureChannel = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"SignSecureChannel", 1);
    st3.etatCanal = signSecureChannel == 1 ? L"Activé" : L"Désactivé";
    st3.signing = L"-";
    st3.sealing = L"-";
    st3.strongKey = L"-";
    st3.alertes = signSecureChannel == 1 ? L"Bon" : L"ATTENTION: Canal non signé";
    statuses.push_back(st3);

    // SealSecureChannel
    NetlogonStatus st4;
    st4.domaine = L"SealSecureChannel";
    DWORD sealSecureChannel = ReadRegistryDWORD(HKEY_LOCAL_MACHINE, netlogonKey, L"SealSecureChannel", 1);
    st4.etatCanal = sealSecureChannel == 1 ? L"Activé" : L"Désactivé";
    st4.signing = L"-";
    st4.sealing = L"-";
    st4.strongKey = L"-";
    st4.alertes = sealSecureChannel == 1 ? L"Bon" : L"ATTENTION: Canal non scellé";
    statuses.push_back(st4);

    {
        std::lock_guard<std::mutex> lock(g_dataMutex);
        g_statuses = statuses;
    }

    Log(L"Vérification configuration terminée");

    PostMessageW(g_hMainWnd, WM_USER + 1, 0, 0);
}

// ===== Réparer Secure Channel =====
void RepairSecureChannel() {
    Log(L"Tentative de réparation secure channel");

    std::wstring domainName = GetDomainName();

    if (domainName == L"Workgroup / Non joint au domaine" || domainName == L"Inconnu") {
        MessageBoxW(g_hMainWnd, L"La machine n'est pas jointe à un domaine.", L"Information", MB_ICONINFORMATION);
        return;
    }

    MessageBoxW(g_hMainWnd,
        L"La réparation du secure channel nécessite l'exécution de la commande:\n\n"
        L"nltest /sc_reset:<domaine>\n\n"
        L"Cette opération doit être effectuée manuellement avec privilèges administrateur.",
        L"Réparation Secure Channel", MB_ICONINFORMATION);

    Log(L"Instruction de réparation affichée à l'utilisateur");
}

// ===== Export CSV =====
void ExportToCSV() {
    OPENFILENAMEW ofn = {0};
    wchar_t szFile[MAX_PATH] = L"NetlogonStatus.csv";

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrTitle = L"Exporter le statut Netlogon";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    std::ofstream csvFile(szFile, std::ios::binary);
    if (!csvFile.is_open()) {
        MessageBoxW(g_hMainWnd, L"Impossible d'ouvrir le fichier pour l'export.", L"Erreur", MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    csvFile << "\xEF\xBB\xBF";

    // En-têtes
    csvFile << "Domaine;État Canal;Signing;Sealing;Strong Key;Alertes\n";

    std::lock_guard<std::mutex> lock(g_dataMutex);
    for (const auto& st : g_statuses) {
        std::wstring line = st.domaine + L";" +
                           st.etatCanal + L";" +
                           st.signing + L";" +
                           st.sealing + L";" +
                           st.strongKey + L";" +
                           st.alertes + L"\n";

        int len = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, nullptr, 0, nullptr, nullptr);
        char* utf8 = new char[len];
        WideCharToMultiByte(CP_UTF8, 0, line.c_str(), -1, utf8, len, nullptr, nullptr);
        csvFile << utf8;
        delete[] utf8;
    }

    csvFile.close();

    Log(L"Export CSV: " + std::wstring(szFile));
    MessageBoxW(g_hMainWnd, L"Export terminé avec succès.", L"Information", MB_ICONINFORMATION);
}

// ===== Window Procedure =====
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        g_hListView = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            10, 10, 960, 450, hWnd, (HMENU)ID_LISTVIEW, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hListView, WM_SETFONT, (WPARAM)hFont, TRUE);
        InitListView();

        g_hBtnTest = CreateWindowExW(0, L"BUTTON", L"Tester Secure Channel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 470, 180, 35, hWnd, (HMENU)ID_BTN_TEST, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hBtnTest, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_hBtnConfig = CreateWindowExW(0, L"BUTTON", L"Vérifier Config",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            200, 470, 180, 35, hWnd, (HMENU)ID_BTN_CONFIG, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hBtnConfig, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_hBtnRepair = CreateWindowExW(0, L"BUTTON", L"Réparer (Guide)",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            390, 470, 180, 35, hWnd, (HMENU)ID_BTN_REPAIR, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hBtnRepair, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_hBtnExport = CreateWindowExW(0, L"BUTTON", L"Exporter",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            580, 470, 180, 35, hWnd, (HMENU)ID_BTN_EXPORT, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hBtnExport, WM_SETFONT, (WPARAM)hFont, TRUE);

        g_hStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, nullptr,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hWnd, (HMENU)ID_STATUSBAR, GetModuleHandle(nullptr), nullptr);
        SendMessageW(g_hStatusBar, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Prêt - Ayi NEDJIMI Consultants");

        return 0;
    }

    case WM_SIZE: {
        int width = LOWORD(lParam);
        int height = HIWORD(lParam);

        MoveWindow(g_hListView, 10, 10, width - 20, height - 120, TRUE);
        MoveWindow(g_hBtnTest, 10, height - 100, 180, 35, TRUE);
        MoveWindow(g_hBtnConfig, 200, height - 100, 180, 35, TRUE);
        MoveWindow(g_hBtnRepair, 390, height - 100, 180, 35, TRUE);
        MoveWindow(g_hBtnExport, 580, height - 100, 180, 35, TRUE);
        SendMessageW(g_hStatusBar, WM_SIZE, 0, 0);
        return 0;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_BTN_TEST:
            EnableWindow(g_hBtnTest, FALSE);
            SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Test du secure channel...");
            std::thread([]() {
                TestSecureChannel();
                EnableWindow(g_hBtnTest, TRUE);
            }).detach();
            break;

        case ID_BTN_CONFIG:
            EnableWindow(g_hBtnConfig, FALSE);
            SendMessageW(g_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"Vérification configuration...");
            std::thread([]() {
                VerifyConfig();
                EnableWindow(g_hBtnConfig, TRUE);
            }).detach();
            break;

        case ID_BTN_REPAIR:
            RepairSecureChannel();
            break;

        case ID_BTN_EXPORT:
            ExportToCSV();
            break;
        }
        return 0;
    }

    case WM_USER + 1:
        UpdateListView();
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, message, wParam, lParam);
}

// ===== WinMain =====
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    InitLog();
    Log(L"=== NetlogonSecureChannelChecker démarré ===");

    INITCOMMONCONTROLSEX icex = {0};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wcex = {0};
    wcex.cbSize = sizeof(wcex);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = L"NetlogonSecureChannelCheckerClass";
    wcex.hIcon = LoadIcon(nullptr, IDI_SHIELD);
    wcex.hIconSm = LoadIcon(nullptr, IDI_SHIELD);

    RegisterClassExW(&wcex);

    g_hMainWnd = CreateWindowExW(0, L"NetlogonSecureChannelCheckerClass",
        L"NetlogonSecureChannelChecker - Ayi NEDJIMI Consultants",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 600,
        nullptr, nullptr, hInstance, nullptr);

    if (!g_hMainWnd) return 1;

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    Log(L"=== NetlogonSecureChannelChecker arrêté ===");
    return (int)msg.wParam;
}
