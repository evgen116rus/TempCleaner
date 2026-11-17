using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

// Использование:
//   TempCleaner.exe             - очистка с подтверждением
//   TempCleaner.exe --dry-run   - только показать, что будет удалено
//   TempCleaner.exe --yes       - очистка без вопроса

bool dryRun = args.Contains("--dry-run", StringComparer.OrdinalIgnoreCase);
bool autoYes = args.Contains("--yes", StringComparer.OrdinalIgnoreCase);

Console.WriteLine("Очистка временных папок" + (dryRun ? " (пробный запуск, ничего не удаляется)" : ""));
Console.WriteLine();
Console.WriteLine($"Программа запущена от:   {Environment.UserDomainName}\\{Environment.UserName}");

var targets = new List<Target>();

// 1. Папки пользователя, который СЕЙЧАС залогинен (а не того, от кого запущена программа)
var logged = LoggedOn.Find();
if (logged is null)
{
    Console.WriteLine("Залогиненный пользователь: не найден, его папки будут пропущены.");
}
else
{
    Console.WriteLine($"Залогиненный пользователь: {logged.Account}");
    Console.WriteLine($"Профиль:                 {logged.ProfilePath}");

    targets.Add(new(Path.Combine(logged.ProfilePath, "AppData", "Local", "Temp"), false));
    targets.Add(new(Path.Combine(logged.ProfilePath, "AppData", "Local", "Microsoft", "Windows", "INetCache"), false));
}

// 2. Системные папки
targets.Add(new(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\TEMP"), false));
targets.Add(new(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\SystemTemp"), false));
targets.Add(new(Environment.ExpandEnvironmentVariables(@"%SystemRoot%\SoftwareDistribution"), false));
targets.Add(new(@"C:\Temp", false));

// 3. Найденные папки ccmcache (кэш клиента SCCM/ConfigMgr) - удаляются целиком
foreach (var p in FindCcmCache())
    targets.Add(new(p, true));

Console.WriteLine();
Console.WriteLine("Будут очищены:");
foreach (var t in targets)
    Console.WriteLine("  " + t.FullPath + (t.RemoveRoot ? "   (папка будет удалена целиком)" : ""));
Console.WriteLine();

if (!dryRun && !autoYes)
{
    Console.Write("Продолжить? [y/N]: ");
    var answer = Console.ReadLine()?.Trim().ToLowerInvariant();
    if (answer is not ("y" or "yes" or "д" or "да"))
    {
        Console.WriteLine("Отменено.");
        return;
    }
}

long totalFreed = 0;
int totalFiles = 0, totalDirs = 0, totalSkipped = 0;

foreach (var target in targets)
{
    Console.WriteLine($"\n=== {target.FullPath}");

    if (!IsSafe(target.FullPath))
    {
        Console.WriteLine("Небезопасный путь (корень диска), пропуск.");
        continue;
    }

    var root = new DirectoryInfo(target.FullPath);
    if (!root.Exists)
    {
        Console.WriteLine("Папка не найдена, пропуск.");
        continue;
    }

    var stats = new Stats();
    CleanDirectory(root, stats, dryRun);

    if (target.RemoveRoot)
    {
        try
        {
            if (dryRun)
            {
                stats.Dirs++;
            }
            else if (!root.EnumerateFileSystemInfos().Any())
            {
                root.Delete(false);
                stats.Dirs++;
            }
            else
            {
                Console.WriteLine("Папка удалена не полностью: остались занятые файлы.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            stats.Skipped++;
            Console.WriteLine("Не удалось удалить саму папку: " + ex.Message);
        }
    }

    Console.WriteLine($"Файлов: {stats.Files}, папок: {stats.Dirs}, освобождено: {FormatSize(stats.Bytes)}, пропущено (занято/нет доступа): {stats.Skipped}");

    totalFreed += stats.Bytes;
    totalFiles += stats.Files;
    totalDirs += stats.Dirs;
    totalSkipped += stats.Skipped;
}

Console.WriteLine();
Console.WriteLine("==============================");
Console.WriteLine($"Итого файлов: {totalFiles}, папок: {totalDirs}");
Console.WriteLine($"{(dryRun ? "Можно освободить" : "Освобождено")}: {FormatSize(totalFreed)}");
Console.WriteLine($"Пропущено: {totalSkipped}");

if (!autoYes)
{
    Console.WriteLine("\nНажмите любую клавишу для выхода...");
    Console.ReadKey();
}

// ---------------------------------------------------------------------------

// Защита от случайной очистки корня диска
static bool IsSafe(string path)
{
    var full = Path.GetFullPath(path).TrimEnd('\\', '/');
    return full.Length > 3;
}

// Ищет папки ccmcache: %SystemRoot%\ccmcache, <диск>:\ccmcache и <диск>:\<любая папка>\ccmcache
// на всех фиксированных дисках (в том числе C:\Windows\ccmcache).
static IEnumerable<string> FindCcmCache()
{
    var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    void Check(string p)
    {
        if (Directory.Exists(p)) found.Add(Path.GetFullPath(p));
    }

    var sysRoot = Environment.GetEnvironmentVariable("SystemRoot");
    if (!string.IsNullOrEmpty(sysRoot))
        Check(Path.Combine(sysRoot, "ccmcache"));

    foreach (var drive in DriveInfo.GetDrives())
    {
        try
        {
            if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;

            var root = drive.RootDirectory.FullName;
            Check(Path.Combine(root, "ccmcache"));

            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                try
                {
                    if ((File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0) continue;
                    Check(Path.Combine(dir, "ccmcache"));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    return found;
}

static void CleanDirectory(DirectoryInfo root, Stats stats, bool dryRun)
{
    // Сначала файлы
    IEnumerable<FileInfo> files;
    try { files = root.EnumerateFiles(); }
    catch { stats.Skipped++; return; }

    foreach (var file in files)
    {
        try
        {
            long size = file.Length;
            if (!dryRun)
            {
                file.Attributes = FileAttributes.Normal; // снять ReadOnly
                file.Delete();
            }
            stats.Files++;
            stats.Bytes += size;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            stats.Skipped++; // файл используется или нет доступа
        }
    }

    // Затем подпапки
    IEnumerable<DirectoryInfo> dirs;
    try { dirs = root.EnumerateDirectories(); }
    catch { stats.Skipped++; return; }

    foreach (var dir in dirs)
    {
        try
        {
            // Символические ссылки/junction не обходим, чтобы не выйти за пределы папки
            if (dir.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                if (!dryRun) dir.Delete(false);
                stats.Dirs++;
                continue;
            }

            CleanDirectory(dir, stats, dryRun);

            // Удалить папку, если она опустела
            if (!dir.EnumerateFileSystemInfos().Any())
            {
                if (!dryRun) dir.Delete(false);
                stats.Dirs++;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            stats.Skipped++;
        }
    }
}

static string FormatSize(long bytes)
{
    string[] units = { "Б", "КБ", "МБ", "ГБ", "ТБ" };
    double size = bytes;
    int i = 0;
    while (size >= 1024 && i < units.Length - 1) { size /= 1024; i++; }
    return size.ToString("0.##", CultureInfo.CurrentCulture) + " " + units[i];
}

record Target(string FullPath, bool RemoveRoot);

record LoggedOnInfo(string Account, string ProfilePath);

class Stats
{
    public int Files;
    public int Dirs;
    public int Skipped;
    public long Bytes;
}

// Определяет пользователя, который залогинен в системе (консольная сессия, иначе
// первая активная, например RDP), и путь к его профилю. Работает и тогда, когда
// программа запущена через UAC под другой учётной записью администратора.
static class LoggedOn
{
    const int WTSUserName = 5;
    const int WTSDomainName = 7;
    const int WTSActive = 0;
    const uint NoSession = 0xFFFFFFFF;

    [DllImport("kernel32.dll")]
    static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool WTSQuerySessionInformation(IntPtr hServer, uint sessionId, int infoClass, out IntPtr buffer, out uint bytesReturned);

    [DllImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr memory);

    [StructLayout(LayoutKind.Sequential)]
    struct WTS_SESSION_INFO
    {
        public uint SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    static string QueryString(uint session, int infoClass)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, session, infoClass, out var buf, out _))
            return "";
        try { return Marshal.PtrToStringUni(buf) ?? ""; }
        finally { WTSFreeMemory(buf); }
    }

    static (string Domain, string User)? UserOfSession(uint session)
    {
        if (session == NoSession) return null;
        var user = QueryString(session, WTSUserName);
        if (user.Length == 0) return null;
        return (QueryString(session, WTSDomainName), user);
    }

    static (string Domain, string User)? FindSessionUser()
    {
        var u = UserOfSession(WTSGetActiveConsoleSessionId());
        if (u != null) return u;

        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var list, out var count))
            return null;
        try
        {
            int size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (int i = 0; i < count; i++)
            {
                var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(list + i * size);
                if (info.State != WTSActive) continue;
                u = UserOfSession(info.SessionId);
                if (u != null) return u;
            }
        }
        finally { WTSFreeMemory(list); }

        return null;
    }

    public static LoggedOnInfo? Find()
    {
        var su = FindSessionUser();
        if (su is null) return null;

        var (domain, user) = su.Value;
        try
        {
            var account = domain.Length == 0 ? new NTAccount(user) : new NTAccount(domain, user);
            var sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));

            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid.Value);

            var path = key?.GetValue("ProfileImagePath") as string;
            if (string.IsNullOrWhiteSpace(path)) return null;

            var display = domain.Length == 0 ? user : domain + "\\" + user;
            return new LoggedOnInfo(display, Environment.ExpandEnvironmentVariables(path));
        }
        catch (SystemException)
        {
            return null;
        }
    }
}
