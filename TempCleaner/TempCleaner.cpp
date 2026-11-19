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

#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <streambuf>
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

// ---------------------------------------------------------------------------
// Вывод: в консоль - Unicode (WriteConsoleW), в канал/файл (например при запуске
// через PsExec) - в OEM-кодировке, чтобы русский текст не ломался.
// ---------------------------------------------------------------------------

class ConsoleBuf : public std::wstreambuf
{
public:
    ConsoleBuf()
    {
        out_ = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        isConsole_ = out_ != nullptr && out_ != INVALID_HANDLE_VALUE && GetConsoleMode(out_, &mode);
    }

protected:
    int_type overflow(int_type c) override
    {
        if (c != traits_type::eof())
        {
            const wchar_t ch = static_cast<wchar_t>(c);
            Write(&ch, 1);
        }
        return traits_type::not_eof(c);
    }

    std::streamsize xsputn(const wchar_t* s, std::streamsize n) override
    {
        Write(s, static_cast<size_t>(n));
        return n;
    }

private:
    void Write(const wchar_t* s, size_t n)
    {
        if (n == 0 || out_ == nullptr || out_ == INVALID_HANDLE_VALUE) return;

        DWORD written = 0;
        if (isConsole_)
        {
            WriteConsoleW(out_, s, static_cast<DWORD>(n), &written, nullptr);
            return;
        }

        const int len = WideCharToMultiByte(CP_OEMCP, 0, s, static_cast<int>(n), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return;
        std::string tmp(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_OEMCP, 0, s, static_cast<int>(n), tmp.data(), len, nullptr, nullptr);
        WriteFile(out_, tmp.data(), static_cast<DWORD>(tmp.size()), &written, nullptr);
    }

    HANDLE out_ = nullptr;
    bool isConsole_ = false;
};

// Подменяет буфер wcout на время работы программы и возвращает его при выходе
struct WcoutRedirect
{
    ConsoleBuf buf;
    std::wstreambuf* old;
    WcoutRedirect() : old(std::wcout.rdbuf(&buf)) {}
    ~WcoutRedirect()
    {
        std::wcout.flush();
        std::wcout.rdbuf(old);
    }
};

static std::wstring Trim(const std::wstring& s)
{
    size_t b = 0, e = s.size();
    while (b < e && std::iswspace(s[b])) ++b;
    while (e > b && std::iswspace(s[e - 1])) --e;
    return s.substr(b, e - b);
}

static bool AskYes(const std::wstring& question)
{
    std::wcout << question;
    std::wstring answer;
    std::getline(std::wcin, answer);
    answer = Lower(Trim(answer));
    return answer == L"y" || answer == L"yes" || answer == L"д" || answer == L"да";
}

static bool EndsWith(const std::wstring& s, const std::wstring& suffix)
{
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Читает текстовый файл: UTF-16 LE (с BOM), UTF-8 (с BOM или без), иначе ANSI
static bool ReadTextFile(const std::wstring& path, std::wstring& out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(h, &size) || size.QuadPart > 16 * 1024 * 1024)
    {
        CloseHandle(h);
        return false;
    }

    std::string data(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    const BOOL ok = data.empty() ? TRUE : ReadFile(h, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    data.resize(read);

    out.clear();
    if (data.size() >= 2 && static_cast<unsigned char>(data[0]) == 0xFF && static_cast<unsigned char>(data[1]) == 0xFE)
    {
        out.resize((data.size() - 2) / 2);
        if (!out.empty()) memcpy(out.data(), data.data() + 2, out.size() * sizeof(wchar_t));
        return true;
    }

    size_t skip = 0;
    if (data.size() >= 3 && static_cast<unsigned char>(data[0]) == 0xEF &&
        static_cast<unsigned char>(data[1]) == 0xBB && static_cast<unsigned char>(data[2]) == 0xBF)
        skip = 3;

    const char* p = data.data() + skip;
    const int len = static_cast<int>(data.size() - skip);
    if (len == 0) return true;

    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    int n = MultiByteToWideChar(cp, flags, p, len, nullptr, 0);
    if (n <= 0)
    {
        cp = CP_ACP;
        flags = 0;
        n = MultiByteToWideChar(cp, flags, p, len, nullptr, 0);
    }
    if (n <= 0) return false;

    out.resize(static_cast<size_t>(n));
    MultiByteToWideChar(cp, flags, p, len, out.data(), n);
    return true;
}

// Формат файла: по одному имени в строке; пустые строки и строки, начинающиеся с # или ;,
// игнорируются; повторы удаляются; допускается запись вида \\PC-0123.
static bool ReadComputerList(const std::wstring& path, std::vector<std::wstring>& result, std::wstring& error)
{
    std::wstring content;
    if (!ReadTextFile(path, content))
    {
        error = L"Не удалось прочитать файл: " + path;
        return false;
    }

    std::set<std::wstring> seen;
    size_t pos = 0;
    while (pos <= content.size())
    {
        size_t end = content.find(L'\n', pos);
        if (end == std::wstring::npos) end = content.size();
        std::wstring line = Trim(content.substr(pos, end - pos));
        pos = end + 1;

        if (line.empty() || line[0] == L'#' || line[0] == L';') continue;
        while (!line.empty() && (line.front() == L'\\' || line.front() == L'/')) line.erase(0, 1);
        if (!line.empty() && seen.insert(Lower(line)).second) result.push_back(line);
    }

    if (result.empty())
    {
        error = L"В файле нет ни одного имени компьютера.";
        return false;
    }
    return true;
}

// Один компьютер или список из файла
static bool ParseTargets(const std::wstring& input, std::vector<std::wstring>& result, std::wstring& error)
{
    std::wstring text = Trim(input);
    if (text.size() >= 2 && text.front() == L'"' && text.back() == L'"')
        text = Trim(text.substr(1, text.size() - 2));

    const DWORD attrs = GetFileAttributesW(text.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        return ReadComputerList(text, result, error);

    std::wstring name = text;
    while (!name.empty() && (name.front() == L'\\' || name.front() == L'/')) name.erase(0, 1);

    const std::wstring lower = Lower(name);
    if (name.find_first_of(L"\\/:") != std::wstring::npos || EndsWith(lower, L".txt") || EndsWith(lower, L".lst"))
    {
        error = L"Файл не найден: " + text;
        return false;
    }

    result.push_back(name);
    return true;
}

static int RunPse(const std::wstring& pse, const std::wstring& self, const std::wstring& computer,
                  bool dryRun, const std::wstring& serviceName)
{
    std::wstring cmd = L"\"" + pse + L"\" \\\\" + computer +
                       L" -accepteula -nobanner -n 15 -r " + serviceName + L" -s -c -f \"" + self + L"\" --yes --no-pause";
    if (dryRun) cmd += L" --dry-run";

    std::wcout << cmd << L"\n\n";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi))
    {
        std::wcout << L"Не удалось запустить pse.exe, ошибка Win32: " << GetLastError() << L"\n";
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}

// Запускает эту же программу на удалённых компьютерах через PsExec (файл pse.exe), по очереди.
// Exe копируется на удалённый компьютер (-c -f) и работает там от SYSTEM (-s)
// без интерактива: --yes --no-pause. Залогиненный пользователь определяется на месте через WTS.
// Ошибка на одном компьютере не останавливает обработку остальных.
static int RunRemote(const std::vector<std::wstring>& computers, bool dryRun, bool confirm,
                     const std::wstring& serviceName)
{
    std::vector<std::wstring> valid;
    for (const auto& c : computers)
    {
        bool ok = !c.empty() && c.size() <= 255;
        for (const wchar_t ch : c)
        {
            if (ch < 32 || wcschr(L" \t\"\\/:*?<>|", ch) != nullptr) ok = false;
        }
        if (ok) valid.push_back(c);
        else std::wcout << L"Некорректное имя компьютера, пропуск: " << c << L"\n";
    }
    if (valid.empty())
    {
        std::wcout << L"Нет компьютеров для запуска.\n";
        return 1;
    }

    // SearchPath ищет pse.exe в папке программы, текущей папке, системных папках и в PATH
    wchar_t pseBuf[MAX_PATH];
    const DWORD found = SearchPathW(nullptr, L"pse.exe", nullptr, MAX_PATH, pseBuf, nullptr);
    if (found == 0 || found >= MAX_PATH)
    {
        std::wcout << L"Не найден pse.exe. Положите его рядом с программой или в папку из PATH.\n";
        return 1;
    }

    wchar_t selfBuf[MAX_PATH];
    const DWORD selfLen = GetModuleFileNameW(nullptr, selfBuf, MAX_PATH);
    if (selfLen == 0 || selfLen >= MAX_PATH)
    {
        std::wcout << L"Не удалось определить путь к программе.\n";
        return 1;
    }
    const std::wstring pse = pseBuf;
    const std::wstring self = selfBuf;

    if (!dryRun && confirm)
    {
        bool yes;
        if (valid.size() == 1)
        {
            yes = AskYes(L"Запустить очистку на компьютере " + valid[0] + L"? [y/N]: ");
        }
        else
        {
            std::wcout << L"Компьютеров в списке: " << valid.size() << L"\n";
            for (size_t i = 0; i < valid.size() && i < 30; ++i) std::wcout << L"  " << valid[i] << L"\n";
            if (valid.size() > 30) std::wcout << L"  ... и ещё " << valid.size() - 30 << L"\n";
            yes = AskYes(L"Запустить очистку на всех? [y/N]: ");
        }
        if (!yes)
        {
            std::wcout << L"Отменено.\n";
            return 0;
        }
    }

    std::vector<std::wstring> failed;
    for (size_t i = 0; i < valid.size(); ++i)
    {
        std::wcout << L"\n=== [" << i + 1 << L"/" << valid.size() << L"] " << valid[i] << L"\n";

        const int code = RunPse(pse, self, valid[i], dryRun, serviceName);
        if (code != 0)
        {
            failed.push_back(valid[i] + L" (код " + std::to_wstring(code) + L")");
            std::wcout << L"Ошибка: код завершения " << code << L"\n";
        }
    }

    if (valid.size() > 1)
    {
        std::wcout << L"\n==============================\n";
        std::wcout << L"Успешно: " << valid.size() - failed.size() << L" из " << valid.size() << L"\n";
        if (!failed.empty())
        {
            std::wcout << L"С ошибками:\n";
            for (const auto& f : failed) std::wcout << L"  " << f << L"\n";
        }
    }

    return failed.empty() ? 0 : 1;
}

int wmain(int argc, wchar_t** argv)
{
    WcoutRedirect redirect;
    _setmode(_fileno(stdin), _O_U16TEXT);

    bool dryRun = false;
    bool autoYes = false;
    bool noPause = false;
    bool missingList = false;
    std::wstring listFile; // параметр --list <файл>
    std::wstring serviceName = L"ps_tc"; // параметр --service <имя>: имя службы PsExec (ключ -r)
    bool missingService = false;
    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--dry-run") == 0) dryRun = true;
        else if (_wcsicmp(argv[i], L"--yes") == 0) autoYes = true;
        else if (_wcsicmp(argv[i], L"--no-pause") == 0) noPause = true;
        else if (_wcsicmp(argv[i], L"--list") == 0)
        {
            if (i + 1 < argc) listFile = argv[++i];
            else missingList = true;
        }
        else if (_wcsicmp(argv[i], L"--service") == 0)
        {
            if (i + 1 < argc) serviceName = argv[++i];
            else missingService = true;
        }
    }
    const bool interactive = !autoYes && !noPause;

    std::wcout << L"Очистка временных папок"
               << (dryRun ? L" (пробный запуск, ничего не удаляется)" : L"") << L"\n\n";

    if (missingList)
    {
        std::wcout << L"Параметр --list требует путь к файлу.\n";
        return 1;
    }

    bool serviceOk = !missingService && !serviceName.empty() && serviceName.size() <= 64;
    for (const wchar_t c : serviceName)
    {
        const bool good = (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                          (c >= L'0' && c <= L'9') || c == L'_' || c == L'-';
        if (!good) serviceOk = false;
    }
    if (!serviceOk)
    {
        std::wcout << L"Параметр --service требует имя службы (латинские буквы, цифры, _ и -).\n";
        return 1;
    }

    // Имя компьютера или файл со списком: пусто - запуск локально, иначе - удалённо через pse.exe (PsExec).
    // В неинтерактивном режиме (--yes / --no-pause, в том числе на удалённой стороне) не спрашиваем.
    std::wstring targetInput = listFile;
    if (targetInput.empty() && interactive)
    {
        std::wcout << L"Имя компьютера или файл со списком (Enter - этот компьютер): ";
        std::getline(std::wcin, targetInput);
        targetInput = Trim(targetInput);
    }

    if (!targetInput.empty())
    {
        std::vector<std::wstring> computers;
        std::wstring error;
        int code;
        if (ParseTargets(targetInput, computers, error))
        {
            code = RunRemote(computers, dryRun, !autoYes, serviceName);
        }
        else
        {
            std::wcout << error << L"\n";
            code = 1;
        }

        if (interactive)
        {
            std::wcout << L"\nНажмите любую клавишу для выхода...";
            _getwch();
        }
        return code;
    }

    if (interactive) std::wcout << L"\n";

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

    if (interactive)
    {
        std::wcout << L"\nНажмите любую клавишу для выхода...";
        _getwch();
    }
    return 0;
}
