// TempCleaner.cpp - очистка временных папок Windows (C++17, Win32 API)
//
// Сборка (Developer Command Prompt for VS):
//   cl /std:c++17 /EHsc /O2 /utf-8 TempCleaner.cpp
//
// Параметры:
//   --dry-run   только показать, что будет удалено
//   --yes       без вопроса о подтверждении

#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <conio.h>
#include <fcntl.h>
#include <io.h>

#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

// Запрашиваем права администратора (нужны для %SystemRoot%\TEMP, SystemTemp, ccmcache)
#pragma comment(linker, "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

struct Stats
{
    unsigned long long bytes = 0;
    int files = 0;
    int dirs = 0;
    int skipped = 0;
};

struct Target
{
    std::wstring path;
    bool removeRoot; // true - удалить папку целиком (ccmcache), false - только очистить
};

// ---------------------------------------------------------------------------
// Вспомогательные функции
// ---------------------------------------------------------------------------

// Раскрывает переменные окружения вида %USERPROFILE%
static std::wstring ExpandEnv(const std::wstring& s)
{
    DWORD n = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (n == 0) return s;
    std::wstring r(n, L'\0');
    ExpandEnvironmentStringsW(s.c_str(), r.data(), n);
    r.resize(n - 1); // убрать завершающий нуль
    return r;
}

// Префикс \\?\ снимает ограничение MAX_PATH
static std::wstring LongPath(const std::wstring& p)
{
    if (p.rfind(L"\\\\?\\", 0) == 0) return p;
    return L"\\\\?\\" + p;
}

static std::wstring Lower(std::wstring s)
{
    for (auto& c : s) c = static_cast<wchar_t>(std::towlower(c));
    return s;
}

static bool DirExists(const std::wstring& p)
{
    const DWORD a = GetFileAttributesW(LongPath(p).c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

// Защита от случайной очистки корня диска
static bool IsSafe(std::wstring path)
{
    while (!path.empty() && (path.back() == L'\\' || path.back() == L'/'))
        path.pop_back();
    return path.size() > 2; // "C:" - небезопасно
}

static std::wstring FormatSize(unsigned long long bytes)
{
    const wchar_t* units[] = { L"Б", L"КБ", L"МБ", L"ГБ", L"ТБ" };
    double size = static_cast<double>(bytes);
    int i = 0;
    while (size >= 1024.0 && i < 4) { size /= 1024.0; ++i; }
    std::wostringstream os;
    os << std::fixed << std::setprecision(2) << size << L" " << units[i];
    return os.str();
}

// ---------------------------------------------------------------------------
// Пользователь, который залогинен (а не тот, от кого запущена программа)
// ---------------------------------------------------------------------------

static bool QuerySessionString(DWORD session, WTS_INFO_CLASS cls, std::wstring& out)
{
    LPWSTR buf = nullptr;
    DWORD bytes = 0;
    out.clear();
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, cls, &buf, &bytes))
        return false;
    if (buf) out.assign(buf);
    WTSFreeMemory(buf);
    return !out.empty();
}

static bool UserOfSession(DWORD session, std::wstring& domain, std::wstring& name)
{
    if (session == 0xFFFFFFFF) return false; // нет консольной сессии
    if (!QuerySessionString(session, WTSUserName, name)) return false;
    QuerySessionString(session, WTSDomainName, domain);
    return true;
}

// Консольная сессия, а если в ней никого нет - первая активная (например RDP)
static bool GetLoggedOnUser(std::wstring& domain, std::wstring& name)
{
    domain.clear();
    name.clear();

    if (UserOfSession(WTSGetActiveConsoleSessionId(), domain, name))
        return true;

    PWTS_SESSION_INFOW info = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &info, &count))
        return false;

    bool found = false;
    for (DWORD i = 0; i < count && !found; ++i)
    {
        if (info[i].State == WTSActive)
            found = UserOfSession(info[i].SessionId, domain, name);
    }
    WTSFreeMemory(info);
    return found;
}

// Путь к профилю по SID пользователя: ProfileList\<SID>\ProfileImagePath
static bool GetProfilePath(const std::wstring& domain, const std::wstring& name, std::wstring& profile)
{
    const std::wstring account = domain.empty() ? name : domain + L"\\" + name;

    DWORD sidSize = 0, domSize = 0;
    SID_NAME_USE use;
    LookupAccountNameW(nullptr, account.c_str(), nullptr, &sidSize, nullptr, &domSize, &use);
    if (sidSize == 0) return false;

    std::vector<BYTE> sid(sidSize);
    std::wstring dom(domSize, L'\0');
    if (!LookupAccountNameW(nullptr, account.c_str(), sid.data(), &sidSize, dom.data(), &domSize, &use))
        return false;

    LPWSTR sidStr = nullptr;
    if (!ConvertSidToStringSidW(sid.data(), &sidStr)) return false;
    const std::wstring keyPath =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + std::wstring(sidStr);
    LocalFree(sidStr);

    wchar_t buf[2 * MAX_PATH];
    DWORD size = sizeof(buf); // в байтах
    const LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE, keyPath.c_str(), L"ProfileImagePath",
                                 RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_SUBKEY_WOW6464KEY,
                                 nullptr, buf, &size);
    if (rc != ERROR_SUCCESS) return false;

    profile = buf;
    return !profile.empty();
}

// ---------------------------------------------------------------------------
// Поиск ccmcache (кэш клиента SCCM/ConfigMgr)
// ---------------------------------------------------------------------------

// Проверяет %SystemRoot%\ccmcache, <диск>:\ccmcache и <диск>:\<любая папка>\ccmcache
// на всех фиксированных дисках (в том числе C:\Windows\ccmcache).
static std::vector<std::wstring> FindCcmCache()
{
    std::vector<std::wstring> result;
    std::set<std::wstring> seen;

    auto check = [&](const std::wstring& p)
    {
        if (DirExists(p) && seen.insert(Lower(p)).second)
            result.push_back(p);
    };

    check(ExpandEnv(L"%SystemRoot%") + L"\\ccmcache");

    wchar_t drives[512];
    const DWORD len = GetLogicalDriveStringsW(512, drives);
    if (len == 0 || len > 512) return result;

    for (const wchar_t* d = drives; *d; d += wcslen(d) + 1)
    {
        if (GetDriveTypeW(d) != DRIVE_FIXED) continue;

        const std::wstring root = d; // корень диска, например "C:" со слешем
        check(root + L"ccmcache");

        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW((root + L"*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do
        {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            check(root + fd.cFileName + L"\\ccmcache");
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Очистка
// ---------------------------------------------------------------------------

static void CleanDirectory(const std::wstring& dir, Stats& st, bool dryRun)
{
    // Сначала собираем содержимое, потом закрываем дескриптор поиска,
    // чтобы он не мешал удалению папки.
    std::vector<WIN32_FIND_DATAW> entries;
    {
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW((LongPath(dir) + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() != ERROR_FILE_NOT_FOUND) ++st.skipped;
            return;
        }
        do
        {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                continue;
            entries.push_back(fd);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    for (const auto& e : entries)
    {
        const std::wstring full = dir + L"\\" + e.cFileName;
        const std::wstring lp = LongPath(full);
        const bool isDir = (e.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const bool isReparse = (e.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

        if (isDir)
        {
            // Символические ссылки и junction не обходим: удаляем только саму ссылку
            if (!isReparse)
                CleanDirectory(full, st, dryRun);

            if (dryRun)
            {
                ++st.dirs;
            }
            else if (RemoveDirectoryW(lp.c_str()))
            {
                ++st.dirs;
            }
            else if (GetLastError() != ERROR_DIR_NOT_EMPTY)
            {
                ++st.skipped;
            }
            // ERROR_DIR_NOT_EMPTY: внутри остались занятые файлы, они уже учтены
        }
        else
        {
            const unsigned long long size =
                (static_cast<unsigned long long>(e.nFileSizeHigh) << 32) | e.nFileSizeLow;

            if (dryRun)
            {
                ++st.files;
                st.bytes += size;
                continue;
            }

            SetFileAttributesW(lp.c_str(), FILE_ATTRIBUTE_NORMAL); // снять ReadOnly
            if (DeleteFileW(lp.c_str()))
            {
                ++st.files;
                st.bytes += size;
            }
            else
            {
                ++st.skipped; // файл используется или нет доступа
            }
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    bool dryRun = false;
    bool autoYes = false;
    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--dry-run") == 0) dryRun = true;
        else if (_wcsicmp(argv[i], L"--yes") == 0) autoYes = true;
    }

    std::wcout << L"Очистка временных папок"
               << (dryRun ? L" (пробный запуск, ничего не удаляется)" : L"") << L"\n\n";

    wchar_t me[256] = L"?";
    DWORD meLen = 256;
    GetUserNameW(me, &meLen);
    std::wcout << L"Программа запущена от:     " << me << L"\n";

    std::vector<Target> targets;

    // 1. Папки пользователя, который СЕЙЧАС залогинен (а не того, от кого запущена программа)
    std::wstring domain, name, profile;
    if (GetLoggedOnUser(domain, name) && GetProfilePath(domain, name, profile) && DirExists(profile))
    {
        std::wcout << L"Залогиненный пользователь: " << (domain.empty() ? L"" : domain + L"\\") << name << L"\n";
        std::wcout << L"Профиль:                   " << profile << L"\n";

        targets.push_back({ profile + L"\\AppData\\Local\\Temp", false });
        targets.push_back({ profile + L"\\AppData\\Local\\Microsoft\\Windows\\INetCache", false });
    }
    else
    {
        std::wcout << L"Залогиненный пользователь: не найден, его папки будут пропущены.\n";
    }

    // 2. Системные папки
    targets.push_back({ ExpandEnv(L"%SystemRoot%\\TEMP"), false });
    targets.push_back({ ExpandEnv(L"%SystemRoot%\\SystemTemp"), false });
    targets.push_back({ ExpandEnv(L"%SystemRoot%\\SoftwareDistribution"), false });
    targets.push_back({ L"C:\\Temp", false });

    // 3. Найденные папки ccmcache - удаляются целиком
    for (const auto& p : FindCcmCache())
        targets.push_back({ p, true });

    std::wcout << L"\nБудут очищены:\n";
    for (const auto& t : targets)
        std::wcout << L"  " << t.path << (t.removeRoot ? L"   (папка будет удалена целиком)" : L"") << L"\n";
    std::wcout << L"\n";

    if (!dryRun && !autoYes)
    {
        std::wcout << L"Продолжить? [y/N]: ";
        std::wstring answer;
        std::getline(std::wcin, answer);
        answer = Lower(answer);
        if (answer != L"y" && answer != L"yes" && answer != L"д" && answer != L"да")
        {
            std::wcout << L"Отменено.\n";
            return 0;
        }
    }

    Stats total;
    for (const auto& target : targets)
    {
        std::wcout << L"\n=== " << target.path << L"\n";

        if (!IsSafe(target.path))
        {
            std::wcout << L"Небезопасный путь (корень диска), пропуск.\n";
            continue;
        }
        if (!DirExists(target.path))
        {
            std::wcout << L"Папка не найдена, пропуск.\n";
            continue;
        }

        Stats st;
        CleanDirectory(target.path, st, dryRun);

        if (target.removeRoot)
        {
            if (dryRun)
            {
                ++st.dirs;
            }
            else if (RemoveDirectoryW(LongPath(target.path).c_str()))
            {
                ++st.dirs;
            }
            else
            {
                ++st.skipped;
                std::wcout << L"Папка удалена не полностью: остались занятые файлы.\n";
            }
        }

        std::wcout << L"Файлов: " << st.files << L", папок: " << st.dirs
                   << L", освобождено: " << FormatSize(st.bytes)
                   << L", пропущено (занято/нет доступа): " << st.skipped << L"\n";

        total.bytes += st.bytes;
        total.files += st.files;
        total.dirs += st.dirs;
        total.skipped += st.skipped;
    }

    std::wcout << L"\n==============================\n";
    std::wcout << L"Итого файлов: " << total.files << L", папок: " << total.dirs << L"\n";
    std::wcout << (dryRun ? L"Можно освободить: " : L"Освобождено: ")
               << FormatSize(total.bytes) << L"\n";
    std::wcout << L"Пропущено: " << total.skipped << L"\n";

    if (!autoYes)
    {
        std::wcout << L"\nНажмите любую клавишу для выхода...";
        _getwch();
    }
    return 0;
}
