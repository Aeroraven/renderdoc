/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2026 Baldur Karlsson
 * Copyright (c) 2014 Crytek
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#include <winsock2.h>
#include <winternl.h>
#include <d3dkmthk.h>
#include <shellapi.h>
#include "core/core.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"

#include <string>

typedef int(WSAAPI *PFN_WSASTARTUP)(__in WORD wVersionRequested, __out LPWSADATA lpWSAData);
typedef int(WSAAPI *PFN_WSACLEANUP)();

typedef BOOL(WINAPI *PFN_CREATE_PROCESS_A)(LPCSTR lpApplicationName, LPSTR lpCommandLine,
                                           LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                           LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                           BOOL bInheritHandles, DWORD dwCreationFlags,
                                           LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
                                           LPSTARTUPINFOA lpStartupInfo,
                                           LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL(WINAPI *PFN_CREATE_PROCESS_W)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
                                           LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                           LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                           BOOL bInheritHandles, DWORD dwCreationFlags,
                                           LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
                                           LPSTARTUPINFOW lpStartupInfo,
                                           LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL(WINAPI *PFN_CREATE_PROCESS_INTERNAL_W)(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken);

typedef BOOL(WINAPI *PFN_CREATE_PROCESS_AS_USER_A)(
    HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL(WINAPI *PFN_CREATE_PROCESS_AS_USER_W)(
    HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL(WINAPI *PFN_CREATE_PROCESS_WITH_LOGON_W)(LPCWSTR lpUsername, LPCWSTR lpDomain,
                                                      LPCWSTR lpPassword, DWORD dwLogonFlags,
                                                      LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
                                                      DWORD dwCreationFlags, LPVOID lpEnvironment,
                                                      LPCWSTR lpCurrentDirectory,
                                                      LPSTARTUPINFOW lpStartupInfo,
                                                      LPPROCESS_INFORMATION lpProcessInformation);

typedef HINSTANCE(WINAPI *PFN_SHELL_EXECUTE_W)(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile,
                                               LPCWSTR lpParameters, LPCWSTR lpDirectory,
                                               INT nShowCmd);
typedef BOOL(WINAPI *PFN_SHELL_EXECUTE_EX_W)(SHELLEXECUTEINFOW *pExecInfo);
using PFN_D3DKMT_CREATE_DEVICE = decltype(&::D3DKMTCreateDevice);
using PFN_D3DKMT_CREATE_CONTEXT = decltype(&::D3DKMTCreateContext);
using PFN_D3DKMT_CREATE_ALLOCATION2 = decltype(&::D3DKMTCreateAllocation2);
using PFN_D3DKMT_OPEN_RESOURCE2 = decltype(&::D3DKMTOpenResource2);
using PFN_D3DKMT_PRESENT = decltype(&::D3DKMTPresent);

uintptr_t FindRemoteDLL(DWORD pid, rdcstr libName);

class SysHook : LibraryHook
{
public:
  SysHook()
  {
    // we start with a refcount of 1 because we initialise WSA ourselves for our own sockets.
    m_WSARefCount = 1;
  }

  void RegisterHooks()
  {
    RDCLOG("Registering Win32 system hooks");

    // register libraries that we care about. We don't need a callback when they are loaded
    LibraryHooks::RegisterLibraryHook("kernel32.dll", NULL);
    LibraryHooks::RegisterLibraryHook("kernelbase.dll", NULL);
    LibraryHooks::RegisterLibraryHook("advapi32.dll", NULL);
    LibraryHooks::RegisterLibraryHook("api-ms-win-core-processthreads-l1-1-0.dll", NULL);
    LibraryHooks::RegisterLibraryHook("api-ms-win-core-processthreads-l1-1-1.dll", NULL);
    LibraryHooks::RegisterLibraryHook("api-ms-win-core-processthreads-l1-1-2.dll", NULL);
    LibraryHooks::RegisterLibraryHook("shell32.dll", NULL);
    LibraryHooks::RegisterLibraryHook("ws2_32.dll", NULL);
    LibraryHooks::RegisterLibraryHook("gdi32.dll", NULL);

    // we want to hook CreateProcess purely so that we can recursively insert our hooks (if we so
    // wish)
    CreateProcessA.Register("kernel32.dll", "CreateProcessA", CreateProcessA_hook);
    CreateProcessW.Register("kernel32.dll", "CreateProcessW", CreateProcessW_hook);
    CreateProcessInternalW.Register("kernelbase.dll", "CreateProcessInternalW",
                                    CreateProcessInternalW_hook);

    CreateProcessAsUserA.Register("advapi32.dll", "CreateProcessAsUserA", CreateProcessAsUserA_hook);
    CreateProcessAsUserW.Register("advapi32.dll", "CreateProcessAsUserW", CreateProcessAsUserW_hook);

    CreateProcessWithLogonW.Register("advapi32.dll", "CreateProcessWithLogonW",
                                     CreateProcessWithLogonW_hook);

    // handle API set exports if they exist. These don't really exist so we don't have to worry
    // about double hooking, and also they call into the 'real' implementation in kernelbase.dll
    API110CreateProcessA.Register("api-ms-win-core-processthreads-l1-1-0.dll", "CreateProcessA",
                                  API110CreateProcessA_hook);
    API110CreateProcessW.Register("api-ms-win-core-processthreads-l1-1-0.dll", "CreateProcessW",
                                  API110CreateProcessW_hook);
    API110CreateProcessAsUserW.Register("api-ms-win-core-processthreads-l1-1-0.dll",
                                        "CreateProcessAsUserW", API110CreateProcessAsUserW_hook);

    API111CreateProcessA.Register("api-ms-win-core-processthreads-l1-1-1.dll", "CreateProcessA",
                                  API111CreateProcessA_hook);
    API111CreateProcessW.Register("api-ms-win-core-processthreads-l1-1-1.dll", "CreateProcessW",
                                  API111CreateProcessW_hook);
    API111CreateProcessAsUserW.Register("api-ms-win-core-processthreads-l1-1-0.dll",
                                        "CreateProcessAsUserW", API111CreateProcessAsUserW_hook);

    API112CreateProcessA.Register("api-ms-win-core-processthreads-l1-1-2.dll", "CreateProcessA",
                                  API112CreateProcessA_hook);
    API112CreateProcessW.Register("api-ms-win-core-processthreads-l1-1-2.dll", "CreateProcessW",
                                  API112CreateProcessW_hook);
    API112CreateProcessAsUserW.Register("api-ms-win-core-processthreads-l1-1-0.dll",
                                        "CreateProcessAsUserW", API112CreateProcessAsUserW_hook);

    ShellExecuteW.Register("shell32.dll", "ShellExecuteW", ShellExecuteW_hook);
    ShellExecuteExW.Register("shell32.dll", "ShellExecuteExW", ShellExecuteExW_hook);

    WSAStartup.Register("ws2_32.dll", "WSAStartup", WSAStartup_hook);
    WSACleanup.Register("ws2_32.dll", "WSACleanup", WSACleanup_hook);

    D3DKMTCreateDevice.Register("gdi32.dll", "D3DKMTCreateDevice", D3DKMTCreateDevice_hook);
    D3DKMTCreateContext.Register("gdi32.dll", "D3DKMTCreateContext", D3DKMTCreateContext_hook);
    D3DKMTCreateAllocation2.Register("gdi32.dll", "D3DKMTCreateAllocation2",
                                     D3DKMTCreateAllocation2_hook);
    D3DKMTOpenResource2.Register("gdi32.dll", "D3DKMTOpenResource2", D3DKMTOpenResource2_hook);
    D3DKMTPresent.Register("gdi32.dll", "D3DKMTPresent", D3DKMTPresent_hook);

    m_RecurseSlot = Threading::AllocateTLSSlot();
    Threading::SetTLSValue(m_RecurseSlot, NULL);
  }

private:
  static SysHook syshooks;

  int m_WSARefCount;
  uint64_t m_RecurseSlot = 0;

  bool CheckRecurse()
  {
    if(Threading::GetTLSValue(m_RecurseSlot) == NULL)
    {
      Threading::SetTLSValue(m_RecurseSlot, (void *)1);
      return false;
    }

    return true;
  }
  void EndRecurse() { Threading::SetTLSValue(m_RecurseSlot, NULL); }
  HookedFunction<PFN_CREATE_PROCESS_A> CreateProcessA;
  HookedFunction<PFN_CREATE_PROCESS_W> CreateProcessW;
  HookedFunction<PFN_CREATE_PROCESS_INTERNAL_W> CreateProcessInternalW;

  HookedFunction<PFN_CREATE_PROCESS_A> API110CreateProcessA;
  HookedFunction<PFN_CREATE_PROCESS_W> API110CreateProcessW;
  HookedFunction<PFN_CREATE_PROCESS_A> API111CreateProcessA;
  HookedFunction<PFN_CREATE_PROCESS_W> API111CreateProcessW;
  HookedFunction<PFN_CREATE_PROCESS_A> API112CreateProcessA;
  HookedFunction<PFN_CREATE_PROCESS_W> API112CreateProcessW;

  HookedFunction<PFN_CREATE_PROCESS_AS_USER_A> CreateProcessAsUserA;
  HookedFunction<PFN_CREATE_PROCESS_AS_USER_W> CreateProcessAsUserW;

  HookedFunction<PFN_CREATE_PROCESS_AS_USER_W> API110CreateProcessAsUserW;
  HookedFunction<PFN_CREATE_PROCESS_AS_USER_W> API111CreateProcessAsUserW;
  HookedFunction<PFN_CREATE_PROCESS_AS_USER_W> API112CreateProcessAsUserW;

  HookedFunction<PFN_CREATE_PROCESS_WITH_LOGON_W> CreateProcessWithLogonW;
  HookedFunction<PFN_SHELL_EXECUTE_W> ShellExecuteW;
  HookedFunction<PFN_SHELL_EXECUTE_EX_W> ShellExecuteExW;

  HookedFunction<PFN_WSASTARTUP> WSAStartup;
  HookedFunction<PFN_WSACLEANUP> WSACleanup;
  HookedFunction<PFN_D3DKMT_CREATE_DEVICE> D3DKMTCreateDevice;
  HookedFunction<PFN_D3DKMT_CREATE_CONTEXT> D3DKMTCreateContext;
  HookedFunction<PFN_D3DKMT_CREATE_ALLOCATION2> D3DKMTCreateAllocation2;
  HookedFunction<PFN_D3DKMT_OPEN_RESOURCE2> D3DKMTOpenResource2;
  HookedFunction<PFN_D3DKMT_PRESENT> D3DKMTPresent;

  static rdcstr SafeWideLogString(LPCWSTR str)
  {
    return str ? StringFormat::Wide2UTF8(str) : "<null>";
  }

  static rdcstr SafeAnsiLogString(LPCSTR str)
  {
    return str ? str : "<null>";
  }

  static uint64_t KMTHandleValue(D3DKMT_HANDLE handle)
  {
    return (uint64_t)(uintptr_t)handle;
  }

  template <typename FlagsType>
  static uint32_t RawFlagValue(const FlagsType &flags)
  {
    uint32_t value = 0;
    const size_t copyBytes = sizeof(value) < sizeof(flags) ? sizeof(value) : sizeof(flags);
    memcpy(&value, &flags, copyBytes);
    return value;
  }

  static int WSAAPI WSAStartup_hook(WORD wVersionRequested, LPWSADATA lpWSAData)
  {
    int ret = syshooks.WSAStartup()(wVersionRequested, lpWSAData);

    // only increment the refcount if the function succeeded
    if(ret == 0)
      syshooks.m_WSARefCount++;

    return ret;
  }

  static int WSAAPI WSACleanup_hook()
  {
    // don't let the application murder our sockets with a mismatched WSACleanup() call
    if(syshooks.m_WSARefCount == 1)
    {
      RDCLOG("WSACleanup called with (to the application) no WSAStartup! Ignoring.");
      SetLastError(WSANOTINITIALISED);
      return SOCKET_ERROR;
    }

    // decrement refcount and call the real thing
    syshooks.m_WSARefCount--;
    return syshooks.WSACleanup()();
  }

  static NTSTATUS APIENTRY D3DKMTCreateDevice_hook(D3DKMT_CREATEDEVICE *pData)
  {
    if(pData)
    {
      RDCLOG("D3DKMTCreateDevice in adapter=0x%llx flags=0x%08x commandBuffer=%p",
             KMTHandleValue(pData->hAdapter), RawFlagValue(pData->Flags), pData->pCommandBuffer);
    }
    else
    {
      RDCLOG("D3DKMTCreateDevice called with null args");
    }

    NTSTATUS ret = syshooks.D3DKMTCreateDevice()(pData);

    if(pData)
    {
      RDCLOG("D3DKMTCreateDevice out status=0x%08x device=0x%llx commandBuffer=%p",
             (uint32_t)ret, KMTHandleValue(pData->hDevice), pData->pCommandBuffer);
    }
    else
    {
      RDCLOG("D3DKMTCreateDevice out status=0x%08x", (uint32_t)ret);
    }

    return ret;
  }

  static NTSTATUS APIENTRY D3DKMTCreateContext_hook(D3DKMT_CREATECONTEXT *pData)
  {
    if(pData)
    {
      RDCLOG(
          "D3DKMTCreateContext in device=0x%llx node=%u engineAffinity=0x%08x clientHint=%u "
          "flags=0x%08x privateDataSize=%u",
          KMTHandleValue(pData->hDevice), pData->NodeOrdinal, pData->EngineAffinity,
          (uint32_t)pData->ClientHint, pData->Flags.Value, pData->PrivateDriverDataSize);
    }
    else
    {
      RDCLOG("D3DKMTCreateContext called with null args");
    }

    NTSTATUS ret = syshooks.D3DKMTCreateContext()(pData);

    if(pData)
    {
      RDCLOG("D3DKMTCreateContext out status=0x%08x context=0x%llx commandBuffer=%p",
             (uint32_t)ret, KMTHandleValue(pData->hContext), pData->pCommandBuffer);
    }
    else
    {
      RDCLOG("D3DKMTCreateContext out status=0x%08x", (uint32_t)ret);
    }

    return ret;
  }

  static NTSTATUS APIENTRY D3DKMTCreateAllocation2_hook(D3DKMT_CREATEALLOCATION *pData)
  {
    if(pData)
    {
      RDCLOG(
          "D3DKMTCreateAllocation2 in device=0x%llx resource=0x%llx numAllocs=%u flags=0x%08x "
          "privRuntime=%u privDriver=%u",
          KMTHandleValue(pData->hDevice), KMTHandleValue(pData->hResource), pData->NumAllocations,
          RawFlagValue(pData->Flags), pData->PrivateRuntimeDataSize,
          pData->PrivateDriverDataSize);
    }
    else
    {
      RDCLOG("D3DKMTCreateAllocation2 called with null args");
    }

    NTSTATUS ret = syshooks.D3DKMTCreateAllocation2()(pData);

    if(pData)
    {
      RDCLOG(
          "D3DKMTCreateAllocation2 out status=0x%08x resource=0x%llx globalShare=0x%llx "
          "privateRuntimeHandle=0x%p",
          (uint32_t)ret, KMTHandleValue(pData->hResource), KMTHandleValue(pData->hGlobalShare),
          pData->hPrivateRuntimeResourceHandle);
    }
    else
    {
      RDCLOG("D3DKMTCreateAllocation2 out status=0x%08x", (uint32_t)ret);
    }

    return ret;
  }

  static NTSTATUS APIENTRY D3DKMTOpenResource2_hook(D3DKMT_OPENRESOURCE *pData)
  {
    if(pData)
    {
      RDCLOG(
          "D3DKMTOpenResource2 in device=0x%llx globalShare=0x%llx numAllocs=%u "
          "privRuntime=%u resourcePriv=%u totalPriv=%u",
          KMTHandleValue(pData->hDevice), KMTHandleValue(pData->hGlobalShare),
          pData->NumAllocations, pData->PrivateRuntimeDataSize,
          pData->ResourcePrivateDriverDataSize, pData->TotalPrivateDriverDataBufferSize);
    }
    else
    {
      RDCLOG("D3DKMTOpenResource2 called with null args");
    }

    NTSTATUS ret = syshooks.D3DKMTOpenResource2()(pData);

    if(pData)
    {
      RDCLOG("D3DKMTOpenResource2 out status=0x%08x resource=0x%llx totalPriv=%u",
             (uint32_t)ret, KMTHandleValue(pData->hResource),
             pData->TotalPrivateDriverDataBufferSize);
    }
    else
    {
      RDCLOG("D3DKMTOpenResource2 out status=0x%08x", (uint32_t)ret);
    }

    return ret;
  }

  static NTSTATUS APIENTRY D3DKMTPresent_hook(D3DKMT_PRESENT *pData)
  {
    if(pData)
    {
      RDCLOG(
          "D3DKMTPresent in device=0x%llx context=0x%llx window=0x%p source=0x%llx dest=0x%llx "
          "presentCount=%u flipInterval=%u flags=0x%08x broadcastCount=%lu",
          KMTHandleValue(pData->hDevice), KMTHandleValue(pData->hContext), pData->hWindow,
          KMTHandleValue(pData->hSource), KMTHandleValue(pData->hDestination),
          pData->PresentCount, (uint32_t)pData->FlipInterval, pData->Flags.Value,
          pData->BroadcastContextCount);
    }
    else
    {
      RDCLOG("D3DKMTPresent called with null args");
    }

    NTSTATUS ret = syshooks.D3DKMTPresent()(pData);

    RDCLOG("D3DKMTPresent out status=0x%08x", (uint32_t)ret);

    return ret;
  }

  static BOOL WINAPI
  Hooked_CreateProcess(const char *entryPoint,
                       std::function<BOOL(DWORD dwCreationFlags, LPVOID pEnvironment,
                                          LPPROCESS_INFORMATION lpProcessInformation)>
                           realFunc,
                       const rdcstr &applicationName, const rdcstr &commandLine,
                       const rdcstr &currentDirectory,
                       DWORD dwCreationFlags, bool inject, LPVOID pEnvironment,
                       LPPROCESS_INFORMATION lpProcessInformation)
  {
    bool recursive = syshooks.CheckRecurse();

    if(recursive)
      return realFunc(dwCreationFlags, pEnvironment, lpProcessInformation);

    PROCESS_INFORMATION dummy;
    RDCEraseEl(dummy);

    // not sure if this is valid, but I need the PID so I'll fill in my own struct to ensure that.
    if(lpProcessInformation == NULL)
    {
      lpProcessInformation = &dummy;
    }
    else
    {
      *lpProcessInformation = dummy;
    }

    RDCLOG("%s request app=%s cmd=%s dir=%s flags=0x%08x inject=%s", entryPoint,
           applicationName.c_str(), commandLine.c_str(), currentDirectory.c_str(), dwCreationFlags,
           inject ? "true" : "false");

    bool resume = (dwCreationFlags & CREATE_SUSPENDED) == 0;
    dwCreationFlags |= CREATE_SUSPENDED;

    rdcstr envA;
    std::wstring envW;
    void *env = pEnvironment;
    const bool unicode_env = (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) != 0;

// give ourselves access to the ANSI version if we want it
#undef GetEnvironmentStrings

    static_assert(std::is_same<decltype(GetEnvironmentStrings()), char *>::value,
                  "GetEnvironmentStrings macro is messing up");

    // if we have no existing environment, take it from the current env strings that will be used
    // implicitly so we can patch it
    if(!env)
      env = unicode_env ? (void *)GetEnvironmentStringsW() : (void *)GetEnvironmentStrings();

    // patch the environment string to remove vulkan layer variable
    if(unicode_env)
    {
      const wchar_t *cur = (const wchar_t *)env;

      // loop over every A=B\0 string
      while(*cur)
      {
        // if it is NOT the vulkan env var, append it to our block
        if(wcsncmp(cur, CONCAT(L, GUGUGAGA_VULKAN_LAYER_VAR), sizeof(GUGUGAGA_VULKAN_LAYER_VAR) - 1))
        {
          envW += cur;
          envW.push_back(L'\0');
        }

        cur += wcslen(cur) + 1;
      }

      // append the extra \0 to terminate the block
      envW.push_back(L'\0');

      // use the patched block
      env = (void *)envW.data();
    }
    else
    {
      const char *cur = (const char *)env;

      // loop over every A=B\0 string
      while(*cur)
      {
        // if it is NOT the vulkan env var, append it to our block
        if(strncmp(cur, GUGUGAGA_VULKAN_LAYER_VAR, sizeof(GUGUGAGA_VULKAN_LAYER_VAR) - 1))
        {
          envA += cur;
          envA.push_back('\0');
        }

        cur += strlen(cur) + 1;
      }

      // append the extra \0 to terminate the block
      envA.push_back('\0');

      // use the patched block
      env = (void *)envA.data();
    }

    RDCDEBUG("Calling real %s", entryPoint);
    BOOL ret = realFunc(dwCreationFlags, env, lpProcessInformation);
    DWORD retError = ret ? ERROR_SUCCESS : GetLastError();
    RDCDEBUG("Called real %s", entryPoint);

    RDCLOG("%s result ret=%s err=%u pid=%u tid=%u flags=0x%08x inject=%s", entryPoint,
           ret ? "true" : "false", retError, lpProcessInformation->dwProcessId,
           lpProcessInformation->dwThreadId, dwCreationFlags, inject ? "true" : "false");

    if(ret && inject)
    {
      RDCDEBUG("Intercepting %s", entryPoint);

      // inherit logfile and capture options
      rdcpair<RDResult, uint32_t> res = Process::InjectIntoProcess(
          lpProcessInformation->dwProcessId, {}, GuguGaga::Inst().GetCaptureFileTemplate(),
          GuguGaga::Inst().GetCaptureOptions(), false);

      rdcstr injectStatus = !res.first.message.empty() ? res.first.message : ToStr(res.first.code);
      RDCLOG("%s child PID %u injection result: %s (ident %u)", entryPoint,
             lpProcessInformation->dwProcessId, injectStatus.c_str(), res.second);

      if(res.first == ResultCode::Succeeded)
        GuguGaga::Inst().AddChildProcess((uint32_t)lpProcessInformation->dwProcessId, res.second);
    }

    if(resume)
    {
      ResumeThread(lpProcessInformation->hThread);
    }

    // ensure we clean up after ourselves
    if(dummy.dwProcessId != 0)
    {
      CloseHandle(dummy.hProcess);
      CloseHandle(dummy.hThread);
    }

    syshooks.EndRecurse();

    return ret;
  }

  static bool ShouldInject(LPCWSTR lpApplicationName, LPCWSTR lpCommandLine)
  {
    if(!GuguGaga::Inst().GetCaptureOptions().hookIntoChildren)
      return false;

    bool inject = true;

    // sanity check to make sure we're not going to go into an infinity loop injecting into
    // ourselves.
    if(lpApplicationName)
    {
      rdcstr app = strlower(StringFormat::Wide2UTF8(lpApplicationName));

      if(app.contains("gugugagacmd.exe") || app.contains("qgugugaga.exe"))
      {
        inject = false;
      }
    }
    if(lpCommandLine)
    {
      rdcstr cmd = strlower(StringFormat::Wide2UTF8(lpCommandLine));

      if(cmd.contains("gugugagacmd.exe") || cmd.contains("qgugugaga.exe"))
      {
        inject = false;
      }
    }
    return inject;
  }

  static bool ShouldInject(LPCSTR lpApplicationName, LPCSTR lpCommandLine)
  {
    if(!GuguGaga::Inst().GetCaptureOptions().hookIntoChildren)
      return false;

    return ShouldInject(lpApplicationName ? StringFormat::UTF82Wide(lpApplicationName).c_str() : NULL,
                        lpCommandLine ? StringFormat::UTF82Wide(lpCommandLine).c_str() : NULL);
  }

  static BOOL WINAPI CreateProcessA_hook(
      __in_opt LPCSTR lpApplicationName, __inout_opt LPSTR lpCommandLine,
      __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
      __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment, __in_opt LPCSTR lpCurrentDirectory,
      __in LPSTARTUPINFOA lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessA",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.CreateProcessA()(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                           lpThreadAttributes, bInheritHandles, flags, env,
                                           lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeAnsiLogString(lpApplicationName), SafeAnsiLogString(lpCommandLine),
        SafeAnsiLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI CreateProcessW_hook(__in_opt LPCWSTR lpApplicationName,
                                         __inout_opt LPWSTR lpCommandLine,
                                         __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                         __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                         __in BOOL bInheritHandles, __in DWORD dwCreationFlags,
                                         __in_opt LPVOID lpEnvironment,
                                         __in_opt LPCWSTR lpCurrentDirectory,
                                         __in LPSTARTUPINFOW lpStartupInfo,
                                         __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.CreateProcessW()(lpApplicationName, lpCommandLine, lpProcessAttributes,
                                           lpThreadAttributes, bInheritHandles, flags, env,
                                           lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI CreateProcessInternalW_hook(
      HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
      BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
      LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
      LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
  {
    return Hooked_CreateProcess(
        "CreateProcessInternalW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.CreateProcessInternalW()(
              hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi, hNewToken);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API110CreateProcessA_hook(
      __in_opt LPCSTR lpApplicationName, __inout_opt LPSTR lpCommandLine,
      __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
      __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment, __in_opt LPCSTR lpCurrentDirectory,
      __in LPSTARTUPINFOA lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessA",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API110CreateProcessA()(
              lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeAnsiLogString(lpApplicationName), SafeAnsiLogString(lpCommandLine),
        SafeAnsiLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API110CreateProcessW_hook(
      __in_opt LPCWSTR lpApplicationName, __inout_opt LPWSTR lpCommandLine,
      __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
      __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment, __in_opt LPCWSTR lpCurrentDirectory,
      __in LPSTARTUPINFOW lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API110CreateProcessW()(
              lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API111CreateProcessA_hook(
      __in_opt LPCSTR lpApplicationName, __inout_opt LPSTR lpCommandLine,
      __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
      __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment, __in_opt LPCSTR lpCurrentDirectory,
      __in LPSTARTUPINFOA lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessA",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API111CreateProcessA()(
              lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeAnsiLogString(lpApplicationName), SafeAnsiLogString(lpCommandLine),
        SafeAnsiLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API111CreateProcessW_hook(
      __in_opt LPCWSTR lpApplicationName, __inout_opt LPWSTR lpCommandLine,
      __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
      __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment, __in_opt LPCWSTR lpCurrentDirectory,
      __in LPSTARTUPINFOW lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API111CreateProcessW()(
              lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API112CreateProcessA_hook(
      __in_opt LPCSTR lpApplicationName, __inout_opt LPSTR lpCommandLine,
      __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
      __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment, __in_opt LPCSTR lpCurrentDirectory,
      __in LPSTARTUPINFOA lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessA",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API112CreateProcessA()(
              lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeAnsiLogString(lpApplicationName), SafeAnsiLogString(lpCommandLine),
        SafeAnsiLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API112CreateProcessW_hook(
      __in_opt LPCWSTR lpApplicationName, __inout_opt LPWSTR lpCommandLine,
      __in_opt LPSECURITY_ATTRIBUTES lpProcessAttributes,
      __in_opt LPSECURITY_ATTRIBUTES lpThreadAttributes, __in BOOL bInheritHandles,
      __in DWORD dwCreationFlags, __in_opt LPVOID lpEnvironment, __in_opt LPCWSTR lpCurrentDirectory,
      __in LPSTARTUPINFOW lpStartupInfo, __out LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API112CreateProcessW()(
              lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI CreateProcessAsUserA_hook(
      HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
      BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
      LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessAsUserA",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.CreateProcessAsUserA()(
              hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeAnsiLogString(lpApplicationName), SafeAnsiLogString(lpCommandLine),
        SafeAnsiLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI CreateProcessAsUserW_hook(
      HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
      BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
      LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessAsUserW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.CreateProcessAsUserW()(
              hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI CreateProcessWithLogonW_hook(LPCWSTR lpUsername, LPCWSTR lpDomain,
                                                  LPCWSTR lpPassword, DWORD dwLogonFlags,
                                                  LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
                                                  DWORD dwCreationFlags, LPVOID lpEnvironment,
                                                  LPCWSTR lpCurrentDirectory,
                                                  LPSTARTUPINFOW lpStartupInfo,
                                                  LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessAsUserW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.CreateProcessWithLogonW()(lpUsername, lpDomain, lpPassword, dwLogonFlags,
                                                    lpApplicationName, lpCommandLine, flags, env,
                                                    lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API110CreateProcessAsUserW_hook(
      HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
      BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
      LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessAsUserW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API110CreateProcessAsUserW()(
              hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API111CreateProcessAsUserW_hook(
      HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
      BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
      LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessAsUserW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API111CreateProcessAsUserW()(
              hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI API112CreateProcessAsUserW_hook(
      HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
      LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
      BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
      LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
  {
    return Hooked_CreateProcess(
        "CreateProcessAsUserW",
        [=](DWORD flags, LPVOID env, LPPROCESS_INFORMATION pi) {
          return syshooks.API112CreateProcessAsUserW()(
              hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
              bInheritHandles, flags, env, lpCurrentDirectory, lpStartupInfo, pi);
        },
        SafeWideLogString(lpApplicationName), SafeWideLogString(lpCommandLine),
        SafeWideLogString(lpCurrentDirectory),
        dwCreationFlags, ShouldInject(lpApplicationName, lpCommandLine), lpEnvironment,
        lpProcessInformation);
  }

  static BOOL WINAPI ShellExecuteExW_hook(SHELLEXECUTEINFOW *pExecInfo)
  {
    bool recursive = syshooks.CheckRecurse();

    if(recursive)
      return syshooks.ShellExecuteExW()(pExecInfo);

    if(pExecInfo)
    {
      RDCLOG(
          "ShellExecuteExW verb=%s file=%s params=%s dir=%s mask=0x%08x show=%d hwnd=0x%p",
          SafeWideLogString(pExecInfo->lpVerb).c_str(),
          SafeWideLogString(pExecInfo->lpFile).c_str(),
          SafeWideLogString(pExecInfo->lpParameters).c_str(),
          SafeWideLogString(pExecInfo->lpDirectory).c_str(), pExecInfo->fMask, pExecInfo->nShow,
          pExecInfo->hwnd);
    }
    else
    {
      RDCLOG("ShellExecuteExW called with null SHELLEXECUTEINFOW");
    }

    BOOL ret = syshooks.ShellExecuteExW()(pExecInfo);
    DWORD retError = ret ? ERROR_SUCCESS : GetLastError();

    HANDLE childProcess = (ret && pExecInfo) ? pExecInfo->hProcess : NULL;
    DWORD childPID = childProcess ? GetProcessId(childProcess) : 0;
    bool inject = pExecInfo && ShouldInject(pExecInfo->lpFile, pExecInfo->lpParameters);
    bool alreadyInjected = childPID != 0 &&
                           FindRemoteDLL(childPID, STRINGIZE(RDOC_BASE_NAME) ".dll") != 0;

    RDCLOG("ShellExecuteExW result ret=%s err=%u hProcess=0x%p pid=%u mask=0x%08x inject=%s",
           ret ? "true" : "false", retError, childProcess, childPID,
           pExecInfo ? pExecInfo->fMask : 0, inject ? "true" : "false");

    if(alreadyInjected)
      RDCLOG("ShellExecuteExW child PID %u already has gugugaga.dll loaded, skipping fallback "
             "injection",
             childPID);

    if(ret && inject && childProcess && childPID != 0 && !alreadyInjected)
    {
      rdcpair<RDResult, uint32_t> res = Process::InjectIntoProcess(
          childPID, {}, GuguGaga::Inst().GetCaptureFileTemplate(),
          GuguGaga::Inst().GetCaptureOptions(), false);

      rdcstr injectStatus = !res.first.message.empty() ? res.first.message : ToStr(res.first.code);
      RDCLOG("ShellExecuteExW child PID %u injection result: %s (ident %u)", childPID,
             injectStatus.c_str(), res.second);

      if(res.first == ResultCode::Succeeded)
        GuguGaga::Inst().AddChildProcess(childPID, res.second);
    }

    syshooks.EndRecurse();

    return ret;
  }

  static HINSTANCE WINAPI ShellExecuteW_hook(HWND hwnd, LPCWSTR lpOperation, LPCWSTR lpFile,
                                             LPCWSTR lpParameters, LPCWSTR lpDirectory,
                                             INT nShowCmd)
  {
    RDCLOG("ShellExecuteW verb=%s file=%s params=%s dir=%s show=%d hwnd=0x%p",
           SafeWideLogString(lpOperation).c_str(), SafeWideLogString(lpFile).c_str(),
           SafeWideLogString(lpParameters).c_str(), SafeWideLogString(lpDirectory).c_str(),
           nShowCmd, hwnd);

    return syshooks.ShellExecuteW()(hwnd, lpOperation, lpFile, lpParameters, lpDirectory,
                                    nShowCmd);
  }
};

SysHook SysHook::syshooks;
