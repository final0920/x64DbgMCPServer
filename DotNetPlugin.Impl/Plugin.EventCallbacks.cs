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
                    uint mtype = BitConverter.ToUInt32(st, 0x24);
                    try { System.IO.File.AppendAllText(@"D:\ms\chat_analysis.txt", "+24=" + mtype.ToString("X") + " " + sb.ToString() + "|| " + s + Environment.NewLine); } catch { }
                    // 频道玩家内容白名单: 0x3D=聊天, 0x4E=招募/收徒 ; 0x11/0x1E/0x23=系统公告丢弃
                    string label = mtype == 0x3Du ? "聊天" : (mtype == 0x4Eu ? "频道" : null);
                    if (label != null && !string.IsNullOrEmpty(s))
                    {
                        try { System.IO.File.AppendAllText(@"D:\ms\chat.txt", label + "│" + s + Environment.NewLine); } catch { }
                        LogInfo("CHAT[" + label + "]: " + s);
                        // === 调用方追踪(非暂停): 扫栈找 dnf.exe 范围返回地址 = 调用链 ===
                        // [rsp]=公告CALL的直接调用方; 更深的是上层分发/网络接收路径
                        try
                        {
                            // r15 = 公告CALL 调用方里的源消息对象(0x90字节, +0x24类型);rsi=管理器;r14=另一上下文
                            ulong r15 = (ulong)Bridge.DbgValFromString("r15");
                            ulong r14 = (ulong)Bridge.DbgValFromString("r14");
                            ulong rsiReg = (ulong)Bridge.DbgValFromString("rsi");
                            nuint rsp = Bridge.DbgValFromString("rsp");
                            byte[] stk = new byte[0x400];
                            var cs = new StringBuilder();
                            if (Bridge.DbgMemRead(rsp, stk, (nuint)stk.Length))
                            {
                                for (int k = 0; k < stk.Length; k += 8)
                                {
                                    ulong v = BitConverter.ToUInt64(stk, k);
                                    if (v >= 0x140000000UL && v < 0x147000000UL)
                                        cs.Append("+" + k.ToString("X") + ":" + v.ToString("X") + " ");
                                }
                            }
                            System.IO.File.AppendAllText(@"D:\ms\chat_trace.txt",
                                "[" + label + "] r15=" + r15.ToString("X") + " rsi=" + rsiReg.ToString("X") + " r14=" + r14.ToString("X")
                                + " sid=" + BitConverter.ToUInt32(st, 0x14).ToString("X") + " | " + s + " ||STK|| " + cs.ToString() + Environment.NewLine);
                        }
                        catch { }
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
