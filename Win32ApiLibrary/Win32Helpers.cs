using System;
using System.Runtime.InteropServices;

namespace Win32ApiLibrary
{
    public static class Win32ApiHelpers
    {
        public static bool CheckValidOperatingSystem()
        {
            OperatingSystem os = Environment.OSVersion;
            try
            {
                if (!os.Platform.Equals(PlatformID.Win32NT))
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }

            return true;
        }

        public static uint GetProcessIdByName(string processName)
        {
            uint pid = 0;
            var pe32 = new Win32Api.PROCESSENTRY32()
            {
                dwSize = (uint)Marshal.SizeOf(typeof(Win32Api.PROCESSENTRY32))
            };

            var hSnapshot = Win32Api.CreateToolhelp32Snapshot(Win32Api.SnapshotFlags.Process, 0);

            if (Win32Api.Process32First(hSnapshot, ref pe32))
            {
                do
                {
                    if (pe32.szExeFile.Equals(processName))
                    {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Win32Api.Process32Next(hSnapshot, ref pe32));
            }

            Win32Api.CloseHandle(hSnapshot);
            return pid;
        }
    }
}
