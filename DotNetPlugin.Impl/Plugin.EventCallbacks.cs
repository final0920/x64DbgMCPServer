using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using DotNetPlugin.NativeBindings;
using DotNetPlugin.NativeBindings.SDK;
using DotNetPlugin.NativeBindings.Win32;

namespace DotNetPlugin
{
    partial class Plugin
    {

        [EventCallback(Plugins.CBTYPE.CB_INITDEBUG)]
        public static void OnInitDebug(ref Plugins.PLUG_CB_INITDEBUG info)
        {
            var szFileName = info.szFileName.GetValue();
            LogInfo($"debugging of file {szFileName} started!");
            GSimpleMcpServer.IsActivelyDebugging = true;
        }

        [EventCallback(Plugins.CBTYPE.CB_STOPDEBUG)]
        public static void OnStopDebug(ref Plugins.PLUG_CB_STOPDEBUG info)
        {
            LogInfo($"debugging stopped!");
            GSimpleMcpServer.IsActivelyDebugging = false;
        }

        [EventCallback(Plugins.CBTYPE.CB_CREATEPROCESS)]
        public static void OnCreateProcess(IntPtr infoPtr)
        {
            // info can also be cast manually
            var info = infoPtr.ToStructUnsafe<Plugins.PLUG_CB_CREATEPROCESS>();

            var CreateProcessInfo = info.CreateProcessInfo;
            var modInfo = info.modInfo;
            string DebugFileName = info.DebugFileName.GetValue();
            var fdProcessInfo = info.fdProcessInfo;
            LogInfo($"Create process {DebugFileName}");
        }

        [EventCallback(Plugins.CBTYPE.CB_LOADDLL)]
        public static void OnLoadDll(ref Plugins.PLUG_CB_LOADDLL info)
        {
            var LoadDll = info.LoadDll;
            var modInfo = info.modInfo;
            string modname = info.modname.GetValue();
            LogInfo($"Load DLL {modname}");
        }

        [EventCallback(Plugins.CBTYPE.CB_DEBUGEVENT)]
        public static void DebugEvent(ref Plugins.PLUG_CB_DEBUGEVENT info)
        {
            // *** Replace 'PointerToTheStringField' with the actual field name ***
            //Debug.WriteLine(info.DebugEvent.Value.dwDebugEventCode.ToString());
            /*
                CREATE_THREAD_DEBUG_EVENT
                LOAD_DLL_DEBUG_EVENT
                EXCEPTION_DEBUG_EVENT
                EXIT_THREAD_DEBUG_EVENT
                EXIT_PROCESS_DEBUG_EVENT
                CREATE_PROCESS_DEBUG_EVENT
             */

            if (info.DebugEvent.Value.dwDebugEventCode == DebugEventType.OUTPUT_DEBUG_STRING_EVENT)//DebugEventCode.OUTPUT_DEBUG_STRING_EVENT
            {
                IntPtr stringPointer = info.DebugEvent.Value.u.DebugString.lpDebugStringData;
                if (stringPointer != IntPtr.Zero)
                {
                    try
                    {
                        if (info.DebugEvent.Value.u.DebugString.fUnicode != 0) // Non-zero means Unicode (UTF-16)
                        {
                            // Reads until the first null character (\0\0 for UTF-16)
                            LogInfo(Marshal.PtrToStringUni(stringPointer) ?? string.Empty);
                        }
                        else // Zero means ANSI
                        {
                            // Reads until the first null character (\0)
                            LogInfo(Marshal.PtrToStringAnsi(stringPointer) ?? string.Empty);
                        }
                    }
                    catch (AccessViolationException accEx)
                    {
                        LogInfo($"Error: Access Violation trying to read string from pointer {stringPointer}. Check if pointer is valid. {accEx.Message}");
                    }
                    catch (Exception ex)
                    {
                        LogInfo($"Error marshalling string from pointer {stringPointer}: {ex.Message}");
                    }
                }
                else
                {
                    LogInfo("The relevant string pointer in PLUG_CB_DEBUGEVENT is null (IntPtr.Zero).");
                }
            }
            // You can add more processing for other parts of the 'info' struct here
        }

        [EventCallback(Plugins.CBTYPE.CB_OUTPUTDEBUGSTRING)]
        public static void OutputDebugString(ref Plugins.PLUG_CB_OUTPUTDEBUGSTRING info)
        {
            LogInfo($"OutputDebugString ");
        }

        [EventCallback(Plugins.CBTYPE.CB_BREAKPOINT)]
        public static void Breakpoint(ref Plugins.PLUG_CB_BREAKPOINT info)
        {
            // === DNF chat capture on 公告CALL (chat-box display chokepoint @ 0x146249100) ===
            // rdx = message struct; [rdx+8] = pointer to the UTF-16 message text.
            // Use a non-pausing breakpoint:  bp 0x146249100 ; bpcond 0x146249100,0
            if ((ulong)info.breakpoint.Value.addr == 0x146249100UL)
            {
                try
                {
                    ulong rcx = (ulong)Bridge.DbgValFromString("rcx");
                    ulong r8 = (ulong)Bridge.DbgValFromString("r8");
                    ulong r9 = (ulong)Bridge.DbgValFromString("r9");
                    nuint rdx = Bridge.DbgValFromString("rdx");
                    var sb = new StringBuilder();
                    sb.Append("rcx=" + rcx.ToString("X") + " r8=" + r8.ToString("X") + " r9=" + r9.ToString("X") + " || ");
                    byte[] st = new byte[48];
                    if (Bridge.DbgMemRead(rdx, st, (nuint)st.Length))
                        for (int k = 0; k < st.Length; k += 4)
                            sb.Append("+" + k.ToString("X2") + ":" + BitConverter.ToUInt32(st, k).ToString("X8") + " ");

                    nuint contentPtr = Bridge.DbgValFromString("[rdx+8]");
                    string s = "";
                    if ((ulong)contentPtr > 0x10000UL)
                    {
                        byte[] buf = new byte[256];
                        if (Bridge.DbgMemRead(contentPtr, buf, (nuint)buf.Length))
                        {
                            s = Encoding.Unicode.GetString(buf);
                            int nul = s.IndexOf('\0');
                            if (nul >= 0) s = s.Substring(0, nul);
                        }
                    }
                    try { System.IO.File.AppendAllText(@"D:\ms\chat_analysis.txt", sb.ToString() + "|| " + s + Environment.NewLine); } catch { }
                    if (!string.IsNullOrEmpty(s))
                    {
                        try { System.IO.File.AppendAllText(@"D:\ms\chat.txt", s + Environment.NewLine); } catch { }
                        LogInfo("CHAT: " + s);
                    }
                }
                catch { }
                return;
            }

            LogInfo($"Breakpoint " + info.breakpoint.Value.addr.ToHexString() + " in " + info.breakpoint.Value.mod);
        }

        [EventCallback(Plugins.CBTYPE.CB_SYSTEMBREAKPOINT)]
        public static void SystemBreakpoint(ref Plugins.PLUG_CB_SYSTEMBREAKPOINT info)
        {
            LogInfo($"SystemBreakpoint " + info.reserved);
        }
    }
}
