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

// must be separate so that it's included first and not sorted by clang-format
#include <windows.h>

#include <intrin.h>
#include <tlhelp32.h>
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include "common/common.h"
#include "common/threading.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"

#define VERBOSE_DEBUG_HOOK OPTION_OFF
// When enabled, keep scanning executable modules even if an earlier import in the same module was
// already hooked. This is useful for investigating cases where a later graphics import such as
// d3d11.dll!D3D11CreateDevice might otherwise be skipped.
#define AGGRESSIVE_EXE_IAT_SCAN OPTION_ON
#define VERBOSE_AGGRESSIVE_EXE_IAT_SCAN OPTION_ON
// Diagnostic switch: keep observing D3D11CreateDevice resolution, but don't let RenderDoc replace
// it. This helps separate "hook path found" from "RenderDoc-wrapped device breaks middleware".
#define BYPASS_D3D11CREATEDEVICE_HOOK OPTION_OFF

// map from address of IAT entry, to original contents
std::map<void **, void *> s_InstalledHooks;
Threading::CriticalSection installedLock;

static const char *GetBaseFilename(const char *filename)
{
  if(filename == NULL)
    return "";

  const char *slash = strrchr(filename, '\\');
  const char *fwdslash = strrchr(filename, '/');
  const char *base = filename;

  if(slash && slash + 1 > base)
    base = slash + 1;
  if(fwdslash && fwdslash + 1 > base)
    base = fwdslash + 1;

  return base;
}

static bool IsInterestingGraphicsModuleName(const char *filename)
{
  if(filename == NULL || filename[0] == 0)
    return false;

  const char *base = GetBaseFilename(filename);

  return !_stricmp(base, "d3d11.dll") || !_stricmp(base, "d3d12.dll") ||
         !_stricmp(base, "d3d12core.dll") || !_stricmp(base, "d3d12sdklayers.dll") ||
         !_stricmp(base, "dxgi.dll") || !_stricmp(base, "dxcore.dll") ||
         !_stricmp(base, "dcomp.dll") || !_stricmp(base, "opengl32.dll") ||
         !_stricmp(base, "gdi32.dll") || !_stricmp(base, "vulkan-1.dll") ||
         !_stricmp(base, "nvapi64.dll") || !_stricmp(base, "nvapi.dll") ||
         !_stricmp(base, "sl.interposer.dll") || !_stricmp(base, "sl.common.dll");
}

static bool ContainsInsensitive(const char *haystack, const char *needle)
{
  if(haystack == NULL || needle == NULL)
    return false;

  rdcstr hay = strlower(haystack);
  rdcstr nee = strlower(needle);
  return hay.find(nee) != -1;
}

static bool IsInterestingGraphicsProcName(const char *func)
{
  if(func == NULL || func[0] == 0)
    return false;

  return ContainsInsensitive(func, "d3d") || ContainsInsensitive(func, "dxgi") ||
         ContainsInsensitive(func, "dxcore") || ContainsInsensitive(func, "vulkan") ||
         ContainsInsensitive(func, "vk") || ContainsInsensitive(func, "wgl") ||
         ContainsInsensitive(func, "egl") || ContainsInsensitive(func, "gl") ||
         ContainsInsensitive(func, "present") || ContainsInsensitive(func, "swapchain") ||
         ContainsInsensitive(func, "swapbuffers") || ContainsInsensitive(func, "createdevice") ||
         ContainsInsensitive(func, "createfactory") || ContainsInsensitive(func, "getinterface") ||
         ContainsInsensitive(func, "openadapter") || ContainsInsensitive(func, "layered") ||
         ContainsInsensitive(func, "composition") || ContainsInsensitive(func, "nvapi") ||
         ContainsInsensitive(func, "streamline");
}

static rdcstr DescribeModuleHandle(HMODULE mod)
{
  char modulePath[MAX_PATH] = {};
  DWORD len = GetModuleFileNameA(mod, modulePath, DWORD(ARRAY_COUNT(modulePath)));

  if(len == 0 || len >= ARRAY_COUNT(modulePath))
  {
    char ptrString[64] = {};
    sprintf_s(ptrString, "%p", mod);
    return ptrString;
  }

  return GetBaseFilename(modulePath);
}

struct ImgDelayDescrRDoc
{
  DWORD grAttrs;
  DWORD szName;
  DWORD phmod;
  DWORD pIAT;
  DWORD pINT;
  DWORD pBoundIAT;
  DWORD pUnloadIAT;
  DWORD dwTimeStamp;
};

#if ENABLED(AGGRESSIVE_EXE_IAT_SCAN) || ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
static bool IsExecutableModuleName(const char *filename)
{
  if(filename == NULL || filename[0] == 0)
    return false;

  const char *base = GetBaseFilename(filename);
  size_t len = strlen(base);
  return len >= 4 && !_stricmp(base + len - 4, ".exe");
}

static bool IsInterestingIATImport(const char *dllName, const char *funcName)
{
  return dllName != NULL && funcName != NULL && IsInterestingGraphicsModuleName(dllName) &&
         IsInterestingGraphicsProcName(funcName);
}
#endif

static void *ResolveDelayThunkPointer(byte *baseAddress, DWORD grAttrs, DWORD value)
{
  if(value == 0)
    return NULL;

  // Delay imports in modern PE32+ images are typically stored as RVAs when dlattrRva is set.
  if(grAttrs & 1)
    return baseAddress + value;

  return (void *)(uintptr_t)value;
}

static bool AddressIsInModule(const void *addr, const char *moduleName)
{
  if(addr == NULL || moduleName == NULL)
    return false;

  HMODULE module = NULL;
  if(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        (LPCWSTR)addr, &module) == FALSE ||
     module == NULL)
  {
    return false;
  }

  return !_stricmp(DescribeModuleHandle(module).c_str(), moduleName);
}

static bool ShouldBypassHookForDiagnostics(const char *dllName, const char *funcName)
{
#if ENABLED(BYPASS_D3D11CREATEDEVICE_HOOK)
  return dllName != NULL && funcName != NULL && !_stricmp(dllName, "d3d11.dll") &&
         !_stricmp(funcName, "D3D11CreateDevice");
#else
  (void)dllName;
  (void)funcName;
  return false;
#endif
}

static bool ShouldContinueIATScan(const char *modName, bool applied, bool already)
{
#if ENABLED(AGGRESSIVE_EXE_IAT_SCAN)
  return applied && already && IsExecutableModuleName(modName);
#else
  (void)modName;
  (void)applied;
  (void)already;
  return false;
#endif
}

bool ApplyHook(FunctionHook &hook, void **IATentry, bool &already)
{
  DWORD oldProtection = PAGE_EXECUTE;

  if(*IATentry == hook.hook)
  {
    already = true;
    return true;
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("Patching IAT for %s: %p to %p", hook.function.c_str(), IATentry, hook.hook);
#endif

  {
    SCOPED_LOCK(installedLock);
    if(s_InstalledHooks.find(IATentry) == s_InstalledHooks.end())
      s_InstalledHooks[IATentry] = *IATentry;
  }

  BOOL success = VirtualProtect(IATentry, sizeof(void *), PAGE_READWRITE, &oldProtection);
  if(!success)
  {
    RDCERR("Failed to make IAT entry writeable 0x%p", IATentry);
    return false;
  }

  *IATentry = hook.hook;

  success = VirtualProtect(IATentry, sizeof(void *), oldProtection, &oldProtection);
  if(!success)
  {
    RDCERR("Failed to restore IAT entry protection 0x%p", IATentry);
    return false;
  }

  return true;
}

struct DllHookset
{
  HMODULE module = NULL;
  bool hooksfetched = false;
  // if we have multiple copies of the dll loaded (unlikely), the other module handles will be
  // stored here
  rdcarray<HMODULE> altmodules;
  rdcarray<FunctionHook> FunctionHooks;
  DWORD OrdinalBase = 0;
  rdcarray<rdcstr> OrdinalNames;
  rdcarray<FunctionLoadCallback> Callbacks;
  Threading::CriticalSection ordinallock;

  void FetchOrdinalNames()
  {
    SCOPED_LOCK(ordinallock);

    // return if we already fetched the ordinals
    if(!OrdinalNames.empty())
      return;

    byte *baseAddress = (byte *)module;

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("FetchOrdinalNames");
#endif

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)baseAddress;

    if(dosheader->e_magic != 0x5a4d)
      return;

    char *PE00 = (char *)(baseAddress + dosheader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(PE00 + 4);
    PIMAGE_OPTIONAL_HEADER optHeader =
        (PIMAGE_OPTIONAL_HEADER)((BYTE *)fileHeader + sizeof(IMAGE_FILE_HEADER));

    DWORD eatOffset = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    IMAGE_EXPORT_DIRECTORY *exportDesc = (IMAGE_EXPORT_DIRECTORY *)(baseAddress + eatOffset);

    WORD *ordinals = (WORD *)(baseAddress + exportDesc->AddressOfNameOrdinals);
    DWORD *names = (DWORD *)(baseAddress + exportDesc->AddressOfNames);

    DWORD count = RDCMIN(exportDesc->NumberOfFunctions, exportDesc->NumberOfNames);

    WORD maxOrdinal = 0;
    for(DWORD i = 0; i < count; i++)
      maxOrdinal = RDCMAX(maxOrdinal, ordinals[i]);

    OrdinalBase = exportDesc->Base;
    OrdinalNames.resize(maxOrdinal + 1);

    for(DWORD i = 0; i < count; i++)
    {
      OrdinalNames[ordinals[i]] = (char *)(baseAddress + names[i]);

#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("ordinal found: '%s' %u", OrdinalNames[ordinals[i]].c_str(), (uint32_t)ordinals[i]);
#endif
    }
  }
};

struct CachedHookData
{
  bool hookAll = true;

  std::map<rdcstr, DllHookset> DllHooks;
  HMODULE ownmodule = NULL;
  Threading::CriticalSection lock;
  char lowername[512] = {};

  std::set<rdcstr> ignores;

  bool missedOrdinals = false;
  std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> libraryIntercept;

  int32_t posthooking = 0;

  void ApplyHooks(const char *modName, HMODULE module)
  {
    {
      size_t i = 0;
      while(modName[i])
      {
        lowername[i] = (char)tolower(modName[i]);
        i++;
      }
      lowername[i] = 0;
    }

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== ApplyHooks(%s, %p)", modName, module);
#endif

    // fraps seems to non-safely modify the assembly around the hook function, if
    // we modify its import descriptors it leads to a crash as it hooks OUR functions.
    // instead, skip modifying the import descriptors, it will hook the 'real' d3d functions
    // and we can call them and have fraps + gugugaga playing nicely together.
    // we also exclude some other overlay renderers here, such as steam's
    //
    // Also we exclude ourselves here - just in case the application has already loaded
    // gugugaga.dll, or tries to load it.
    if(strstr(lowername, "fraps") || strstr(lowername, "gameoverlayrenderer") ||
       strstr(lowername, STRINGIZE(RDOC_BASE_NAME) ".dll") == lowername)
      return;

    // set module pointer if we are hooking exports from this module
    for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
    {
      if(!_stricmp(it->first.c_str(), modName))
      {
        if(it->second.module == NULL)
        {
          it->second.module = module;

          it->second.hooksfetched = true;

          // fetch all function hooks here, since we want to fill out the original function pointer
          // even in case nothing imports from that function (which means it would not get filled
          // out through FunctionHook::ApplyHook)
          for(FunctionHook &hook : it->second.FunctionHooks)
          {
            if(hook.orig && *hook.orig == NULL)
              *hook.orig = GetProcAddress(module, hook.function.c_str());
          }

          it->second.FetchOrdinalNames();
        }
        else if(it->second.module != module)
        {
          // if it's already in altmodules, bail
          bool already = false;

          for(size_t i = 0; i < it->second.altmodules.size(); i++)
          {
            if(it->second.altmodules[i] == module)
            {
              already = true;
              break;
            }
          }

          if(already)
            break;

          // check if the previous module is still valid
          SetLastError(0);
          char filename[MAX_PATH] = {};
          GetModuleFileNameA(it->second.module, filename, MAX_PATH - 1);
          DWORD err = GetLastError();
          char *slash = strrchr(filename, L'\\');

          rdcstr basename = slash ? strlower(rdcstr(slash + 1)) : "";

          if(err == 0 && basename == it->first)
          {
            // previous module is still loaded, add this to the alt modules list
            it->second.altmodules.push_back(module);
          }
          else
          {
            // previous module is no longer loaded or there's a new file there now, add this as the
            // new location
            RDCWARN("%s moved from %p to %p, re-initialising orig pointers", it->first.c_str(),
                    it->second.module, module);

            // we also need to re-initialise the hooks as the orig pointers are now stale
            for(FunctionHook &hook : it->second.FunctionHooks)
            {
              if(hook.orig)
                *hook.orig = GetProcAddress(module, hook.function.c_str());
            }

            it->second.module = module;
          }
        }
      }
    }

    // for safety (and because we don't need to), ignore these modules
    if(!_stricmp(modName, "kernel32.dll") || !_stricmp(modName, "powrprof.dll") ||
       !_stricmp(modName, "CoreMessaging.dll") || !_stricmp(modName, "opengl32.dll") ||
       !_stricmp(modName, "gdi32.dll") || !_stricmp(modName, "gdi32full.dll") ||
       !_stricmp(modName, "windows.storage.dll") || !_stricmp(modName, "nvoglv32.dll") ||
       !_stricmp(modName, "nvoglv64.dll") || !_stricmp(modName, "vulkan-1.dll") ||
       !_stricmp(modName, "atio6axx.dll") || !_stricmp(modName, "atioglxx.dll") ||
       !_stricmp(modName, "nvcuda.dll") || strstr(lowername, "cudart") == lowername ||
       strstr(lowername, "msvcr") == lowername || strstr(lowername, "msvcp") == lowername ||
       strstr(lowername, "nv-vk") == lowername || strstr(lowername, "amdvlk") == lowername ||
       strstr(lowername, "igvk") == lowername || strstr(lowername, "nvopencl") == lowername ||
       strstr(lowername, "nvapi") == lowername)
      return;

    if(ignores.find(lowername) != ignores.end())
      return;

    // the module could have been unloaded after our toolhelp snapshot, especially if we spent a
    // long time
    // dealing with a previous module (like adding our hooks).
    wchar_t modpath[1024] = {0};
    GetModuleFileNameW(module, modpath, 1023);
    if(modpath[0] == 0)
      return;

    // windows 11 and newer versions have weird hotpatch DLLs that don't act like real DLLs. The
    // LoadLibraryW below will fail for these DLLs even when using the module path provided.
    // Only check the path for DLLs that might be a windows-hotpatch but if it matches we'll skip
    // hooking these to avoid problems
    if(strstr(lowername, "hotpatch"))
    {
      wchar_t lowerpath[1024] = {};

      size_t i = 0;
      while(modpath[i])
      {
        lowerpath[i] = towlower(modpath[i]);
        i++;
      }
      lowerpath[i] = 0;

      if(wcsstr(lowerpath, L"\\windows\\winsxs\\"))
        return;
    }

    // increment the module reference count, so it doesn't disappear while we're processing it
    // there's a very small race condition here between if GetModuleFileName returns, the module is
    // unloaded then we load it again. The only way around that is inserting very scary locks
    // between here
    // and FreeLibrary that I want to avoid. Worst case, we load a dll, hook it, then unload it
    // again.
    HMODULE refcountModHandle = LoadLibraryW(modpath);
    RDCASSERTEQUAL(refcountModHandle, module);
    byte *baseAddress = (byte *)refcountModHandle;

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)baseAddress;

    if(dosheader->e_magic != 0x5a4d)
    {
      RDCDEBUG("Ignoring module %s, since magic is 0x%04x not 0x%04x", modName,
               (uint32_t)dosheader->e_magic, 0x5a4dU);
      FreeLibrary(refcountModHandle);
      return;
    }

    char *PE00 = (char *)(baseAddress + dosheader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(PE00 + 4);
    PIMAGE_OPTIONAL_HEADER optHeader =
        (PIMAGE_OPTIONAL_HEADER)((BYTE *)fileHeader + sizeof(IMAGE_FILE_HEADER));

    DWORD iatOffset = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR *)(baseAddress + iatOffset);

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== import descriptors:");
#endif

    while(iatOffset && importDesc->FirstThunk)
    {
      const char *dllName = (const char *)(baseAddress + importDesc->Name);

#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("found IAT for %s", dllName);
#endif

      DllHookset *hookset = NULL;

      for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
        if(!_stricmp(it->first.c_str(), dllName))
          hookset = &it->second;

      if(hookset && importDesc->OriginalFirstThunk > 0)
      {
        IMAGE_THUNK_DATA *origFirst =
            (IMAGE_THUNK_DATA *)(baseAddress + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *first = (IMAGE_THUNK_DATA *)(baseAddress + importDesc->FirstThunk);

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Hooking imports for %s", dllName);
#endif

        while(origFirst->u1.AddressOfData)
        {
          void **IATentry = (void **)&first->u1.AddressOfData;

          struct hook_find
          {
            bool operator()(const FunctionHook &a, const char *b)
            {
              return strcmp(a.function.c_str(), b) < 0;
            }
          };

#if ENABLED(RDOC_X64)
          if(IMAGE_SNAP_BY_ORDINAL64(origFirst->u1.AddressOfData))
#else
          if(IMAGE_SNAP_BY_ORDINAL32(origFirst->u1.AddressOfData))
#endif
          {
            // low bits of origFirst->u1.AddressOfData contain an ordinal
            WORD ordinal = IMAGE_ORDINAL64(origFirst->u1.AddressOfData);

#if ENABLED(VERBOSE_DEBUG_HOOK)
            RDCDEBUG("Found ordinal import %u", (uint32_t)ordinal);
#endif

            if(!hookset->OrdinalNames.empty())
            {
              if(ordinal >= hookset->OrdinalBase)
              {
                // rebase into OrdinalNames index
                DWORD nameIndex = ordinal - hookset->OrdinalBase;

                // it's perfectly valid to have more functions than names, we only
                // list those with names - so ignore any others
                if(nameIndex < hookset->OrdinalNames.size())
                {
                  const char *importName = (const char *)hookset->OrdinalNames[nameIndex].c_str();

#if ENABLED(VERBOSE_DEBUG_HOOK)
                  RDCDEBUG("Located ordinal %u as %s", (uint32_t)ordinal, importName);
#endif

                  auto found =
                      std::lower_bound(hookset->FunctionHooks.begin(), hookset->FunctionHooks.end(),
                                       importName, hook_find());

                  if(found != hookset->FunctionHooks.end() &&
                     !strcmp(found->function.c_str(), importName) && ownmodule != module)
                  {
                    if(ShouldBypassHookForDiagnostics(dllName, importName))
                    {
                      RDCLOG("Skipping import hook for diagnostics module=%s import=%s!%s "
                             "entry=%p current=%p hook=%p",
                             modName, dllName, importName, IATentry, *IATentry, found->hook);
                      origFirst++;
                      first++;
                      continue;
                    }

                    bool already = false;
                    bool applied;

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
                    if(IsInterestingIATImport(dllName, importName) && IsExecutableModuleName(modName))
                    {
                      RDCLOG(
                          "Executable IAT candidate module=%s import=%s!%s entry=%p current=%p "
                          "hook=%p",
                          modName, dllName, importName, IATentry, *IATentry, found->hook);
                    }
#endif

                    {
                      SCOPED_LOCK(lock);
                      applied = ApplyHook(*found, IATentry, already);
                    }

                    // if we failed, or if it's already set and we're not doing a missedOrdinals
                    // second pass, then just bail out immediately as we've already hooked this
                    // module and there's no point wasting time re-hooking nothing
                    if(!applied || (already && !missedOrdinals))
                    {
                      bool continueScan = ShouldContinueIATScan(modName, applied, already);

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
                      if(continueScan)
                      {
                        RDCLOG("Continuing executable IAT scan for module=%s after import=%s!%s",
                               modName, dllName, importName);
                      }
#endif

                      if(continueScan)
                      {
                        origFirst++;
                        first++;
                        continue;
                      }

#if ENABLED(VERBOSE_DEBUG_HOOK)
                      RDCDEBUG("Stopping hooking module, %d %d %d", (int)applied, (int)already,
                               (int)missedOrdinals);
#endif
                      FreeLibrary(refcountModHandle);
                      return;
                    }
                  }
                }
              }
              else
              {
                RDCERR("Import ordinal is below ordinal base in %s importing module %s", modName,
                       dllName);
              }
            }
            else
            {
#if ENABLED(VERBOSE_DEBUG_HOOK)
              RDCDEBUG("missed ordinals, will try again");
#endif
              // the very first time we try to apply hooks, we might apply them to a module
              // before we've looked up the ordinal names for the one it's linking against.
              // Subsequent times we're only loading one new module - and since it can't
              // link to itself we will have all ordinal names loaded.
              //
              // Setting this flag causes us to do a second pass right at the start
              missedOrdinals = true;
            }

            // continue
            origFirst++;
            first++;
            continue;
          }

          IMAGE_IMPORT_BY_NAME *import =
              (IMAGE_IMPORT_BY_NAME *)(baseAddress + origFirst->u1.AddressOfData);

          const char *importName = (const char *)import->Name;

#if ENABLED(VERBOSE_DEBUG_HOOK)
          RDCDEBUG("Found normal import %s", importName);
#endif

          auto found = std::lower_bound(hookset->FunctionHooks.begin(),
                                        hookset->FunctionHooks.end(), importName, hook_find());

          if(found != hookset->FunctionHooks.end() &&
             !strcmp(found->function.c_str(), importName) && ownmodule != module)
          {
            if(ShouldBypassHookForDiagnostics(dllName, importName))
            {
              RDCLOG("Skipping import hook for diagnostics module=%s import=%s!%s "
                     "entry=%p current=%p hook=%p",
                     modName, dllName, importName, IATentry, *IATentry, found->hook);
              origFirst++;
              first++;
              continue;
            }

            bool already = false;
            bool applied;

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
            if(IsInterestingIATImport(dllName, importName) && IsExecutableModuleName(modName))
            {
              RDCLOG("Executable IAT candidate module=%s import=%s!%s entry=%p current=%p hook=%p",
                     modName, dllName, importName, IATentry, *IATentry, found->hook);
            }
#endif

            {
              SCOPED_LOCK(lock);
              applied = ApplyHook(*found, IATentry, already);
            }

            // if we failed, or if it's already set and we're not doing a missedOrdinals
            // second pass, then just bail out immediately as we've already hooked this
            // module and there's no point wasting time re-hooking nothing
            if(!applied || (already && !missedOrdinals))
            {
              bool continueScan = ShouldContinueIATScan(modName, applied, already);

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
              if(continueScan)
              {
                RDCLOG("Continuing executable IAT scan for module=%s after import=%s!%s", modName,
                       dllName, importName);
              }
#endif

              if(continueScan)
              {
                origFirst++;
                first++;
                continue;
              }

#if ENABLED(VERBOSE_DEBUG_HOOK)
              RDCDEBUG("Stopping hooking module, %d %d %d", (int)applied, (int)already,
                       (int)missedOrdinals);
#endif
              FreeLibrary(refcountModHandle);
              return;
            }
          }

          origFirst++;
          first++;
        }
      }
      else
      {
        if(hookset)
        {
#if ENABLED(VERBOSE_DEBUG_HOOK)
          RDCDEBUG("!! Invalid IAT found for %s! %u %u", dllName, importDesc->OriginalFirstThunk,
                   importDesc->FirstThunk);
#endif
        }
      }

      importDesc++;
    }

    DWORD delayOffset = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    ImgDelayDescrRDoc *delayDesc = (ImgDelayDescrRDoc *)(baseAddress + delayOffset);

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== delay import descriptors:");
#endif

    while(delayOffset && (delayDesc->grAttrs || delayDesc->szName || delayDesc->pIAT ||
                          delayDesc->pINT || delayDesc->dwTimeStamp))
    {
      const char *dllName =
          (const char *)ResolveDelayThunkPointer(baseAddress, delayDesc->grAttrs, delayDesc->szName);

      if(dllName == NULL)
      {
        delayDesc++;
        continue;
      }

#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("found delay IAT for %s", dllName);
#endif

      DllHookset *hookset = NULL;

      for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
        if(!_stricmp(it->first.c_str(), dllName))
          hookset = &it->second;

      if(hookset && delayDesc->pINT > 0 && delayDesc->pIAT > 0)
      {
        IMAGE_THUNK_DATA *origFirst =
            (IMAGE_THUNK_DATA *)ResolveDelayThunkPointer(baseAddress, delayDesc->grAttrs, delayDesc->pINT);
        IMAGE_THUNK_DATA *first =
            (IMAGE_THUNK_DATA *)ResolveDelayThunkPointer(baseAddress, delayDesc->grAttrs, delayDesc->pIAT);

        if(origFirst == NULL || first == NULL)
        {
          delayDesc++;
          continue;
        }

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Hooking delay imports for %s", dllName);
#endif

        while(origFirst->u1.AddressOfData)
        {
          void **IATentry = (void **)&first->u1.AddressOfData;

          struct hook_find
          {
            bool operator()(const FunctionHook &a, const char *b)
            {
              return strcmp(a.function.c_str(), b) < 0;
            }
          };

#if ENABLED(RDOC_X64)
          if(IMAGE_SNAP_BY_ORDINAL64(origFirst->u1.AddressOfData))
#else
          if(IMAGE_SNAP_BY_ORDINAL32(origFirst->u1.AddressOfData))
#endif
          {
            WORD ordinal = IMAGE_ORDINAL64(origFirst->u1.AddressOfData);

            if(!hookset->OrdinalNames.empty() && ordinal >= hookset->OrdinalBase)
            {
              DWORD nameIndex = ordinal - hookset->OrdinalBase;

              if(nameIndex < hookset->OrdinalNames.size())
              {
                const char *importName = (const char *)hookset->OrdinalNames[nameIndex].c_str();

                auto found =
                    std::lower_bound(hookset->FunctionHooks.begin(), hookset->FunctionHooks.end(),
                                     importName, hook_find());

                bool currentResolved =
                    (found != hookset->FunctionHooks.end() && *IATentry == found->hook) ||
                    AddressIsInModule(*IATentry, dllName);

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
                if(IsInterestingIATImport(dllName, importName) && IsExecutableModuleName(modName))
                {
                  RDCLOG(
                      "Executable delay-IAT candidate module=%s import=%s!%s entry=%p current=%p "
                      "hook=%p resolved=%u",
                      modName, dllName, importName, IATentry, *IATentry,
                      found != hookset->FunctionHooks.end() ? found->hook : NULL, currentResolved ? 1U
                                                                                                   : 0U);
                }
#endif

                if(found != hookset->FunctionHooks.end() &&
                   !strcmp(found->function.c_str(), importName) && ownmodule != module)
                {
                  if(ShouldBypassHookForDiagnostics(dllName, importName))
                  {
                    RDCLOG("Skipping delay-import hook for diagnostics module=%s import=%s!%s "
                           "entry=%p current=%p hook=%p resolved=%u",
                           modName, dllName, importName, IATentry, *IATentry, found->hook,
                           currentResolved ? 1U : 0U);
                    origFirst++;
                    first++;
                    continue;
                  }

                  // For delay imports, avoid overwriting the unresolved helper thunk. Once the
                  // delay-load helper resolves the import, it will either write the real function
                  // or our GetProcAddress hook result into this slot and future scans can patch it.
                  if(!currentResolved)
                  {
                    origFirst++;
                    first++;
                    continue;
                  }

                  bool already = false;
                  bool applied;
                  {
                    SCOPED_LOCK(lock);
                    applied = ApplyHook(*found, IATentry, already);
                  }

                  if(!applied || (already && !missedOrdinals))
                  {
                    bool continueScan = ShouldContinueIATScan(modName, applied, already);

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
                    if(continueScan)
                    {
                      RDCLOG(
                          "Continuing executable delay-IAT scan for module=%s after import=%s!%s",
                          modName, dllName, importName);
                    }
#endif

                    if(continueScan)
                    {
                      origFirst++;
                      first++;
                      continue;
                    }

                    FreeLibrary(refcountModHandle);
                    return;
                  }
                }
              }
            }

            origFirst++;
            first++;
            continue;
          }

          IMAGE_IMPORT_BY_NAME *import =
              (IMAGE_IMPORT_BY_NAME *)(baseAddress + origFirst->u1.AddressOfData);
          const char *importName = (const char *)import->Name;

          auto found = std::lower_bound(hookset->FunctionHooks.begin(),
                                        hookset->FunctionHooks.end(), importName, hook_find());

          bool currentResolved =
              (found != hookset->FunctionHooks.end() && *IATentry == found->hook) ||
              AddressIsInModule(*IATentry, dllName);

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
          if(IsInterestingIATImport(dllName, importName) && IsExecutableModuleName(modName))
          {
            RDCLOG(
                "Executable delay-IAT candidate module=%s import=%s!%s entry=%p current=%p "
                "hook=%p resolved=%u",
                modName, dllName, importName, IATentry, *IATentry,
                found != hookset->FunctionHooks.end() ? found->hook : NULL, currentResolved ? 1U : 0U);
          }
#endif

          if(found != hookset->FunctionHooks.end() &&
             !strcmp(found->function.c_str(), importName) && ownmodule != module)
          {
            if(ShouldBypassHookForDiagnostics(dllName, importName))
            {
              RDCLOG("Skipping delay-import hook for diagnostics module=%s import=%s!%s "
                     "entry=%p current=%p hook=%p resolved=%u",
                     modName, dllName, importName, IATentry, *IATentry, found->hook,
                     currentResolved ? 1U : 0U);
              origFirst++;
              first++;
              continue;
            }

            if(!currentResolved)
            {
              origFirst++;
              first++;
              continue;
            }

            bool already = false;
            bool applied;
            {
              SCOPED_LOCK(lock);
              applied = ApplyHook(*found, IATentry, already);
            }

            if(!applied || (already && !missedOrdinals))
            {
              bool continueScan = ShouldContinueIATScan(modName, applied, already);

#if ENABLED(VERBOSE_AGGRESSIVE_EXE_IAT_SCAN)
              if(continueScan)
              {
                RDCLOG("Continuing executable delay-IAT scan for module=%s after import=%s!%s",
                       modName, dllName, importName);
              }
#endif

              if(continueScan)
              {
                origFirst++;
                first++;
                continue;
              }

              FreeLibrary(refcountModHandle);
              return;
            }
          }

          origFirst++;
          first++;
        }
      }
      else
      {
        if(hookset)
        {
#if ENABLED(VERBOSE_DEBUG_HOOK)
          RDCDEBUG("!! Invalid delay IAT found for %s! %u %u", dllName, delayDesc->pINT,
                   delayDesc->pIAT);
#endif
        }
      }

      delayDesc++;
    }

    FreeLibrary(refcountModHandle);
  }
};

static CachedHookData *s_HookData = NULL;

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

static void ForAllModules(std::function<void(const MODULEENTRY32 &me32)> callback)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;

  // up to 10 retries
  for(int i = 0; i < 10; i++)
  {
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

    if(hModuleSnap == INVALID_HANDLE_VALUE)
    {
      DWORD err = GetLastError();

      RDCWARN("CreateToolhelp32Snapshot() -> 0x%08x", err);

      // retry if error is ERROR_BAD_LENGTH
      if(err == ERROR_BAD_LENGTH)
        continue;
    }

    // didn't retry, or succeeded
    break;
  }

  if(hModuleSnap == INVALID_HANDLE_VALUE)
  {
    RDCERR("Couldn't create toolhelp dump of modules in process");
    return;
  }

  MODULEENTRY32 me32;
  RDCEraseEl(me32);
  me32.dwSize = sizeof(MODULEENTRY32);

  BOOL success = Module32First(hModuleSnap, &me32);

  if(success == FALSE)
  {
    DWORD err = GetLastError();

    RDCERR("Couldn't get first module in process: 0x%08x", err);
    CloseHandle(hModuleSnap);
    return;
  }

  do
  {
    callback(me32);
  } while(Module32Next(hModuleSnap, &me32));

  CloseHandle(hModuleSnap);
}

static void HookAllModules()
{
  if(!s_HookData->hookAll)
    return;

  ForAllModules(
      [](const MODULEENTRY32 &me32) { s_HookData->ApplyHooks(me32.szModule, me32.hModule); });

  // check if we're already in this section of code, and if so don't go in again.
  int32_t prev = Atomic::CmpExch32(&s_HookData->posthooking, 0, 1);

  if(prev != 0)
    return;

  // for all loaded modules, call callbacks now
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
  {
    if(it->second.module == NULL)
      continue;

    if(!it->second.hooksfetched)
    {
      it->second.hooksfetched = true;

      // fetch all function hooks here, if we didn't above (perhaps because this library was
      // late-loaded)
      for(FunctionHook &hook : it->second.FunctionHooks)
      {
        if(hook.orig && *hook.orig == NULL)
          *hook.orig = GetProcAddress(it->second.module, hook.function.c_str());
      }
    }

    rdcarray<FunctionLoadCallback> callbacks;
    // don't call callbacks next time
    callbacks.swap(it->second.Callbacks);

    for(FunctionLoadCallback cb : callbacks)
      if(cb)
        cb(it->second.module, it->first.c_str());
  }

  Atomic::CmpExch32(&s_HookData->posthooking, 1, 0);
}

static bool IsAPISet(const wchar_t *filename)
{
  if(wcschr(filename, L'/') != 0 || wcschr(filename, L'\\') != 0)
    return false;

  wchar_t match[] = L"api-ms-win";

  if(wcslen(filename) < ARRAY_COUNT(match) - 1)
    return false;

  for(size_t i = 0; i < ARRAY_COUNT(match) - 1; i++)
    if(towlower(filename[i]) != match[i])
      return false;

  return true;
}

static bool IsAPISet(const char *filename)
{
  size_t len = strlen(filename);
  rdcwstr wfn(len);

  // assume ASCII not UTF, just upcast plainly to wchar_t
  for(size_t i = 0; i < len; i++)
    wfn[i] = wchar_t(filename[i]);

  return IsAPISet(wfn.c_str());
}

static rdcstr CallerModuleForAddress(const void *addr)
{
  if(addr == NULL)
    return "<null>";

  HMODULE module = NULL;

  if(GetModuleHandleExW(
         GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
         (LPCWSTR)addr, &module) == FALSE ||
     module == NULL)
  {
    return "<unknown>";
  }

  wchar_t modulePathW[512] = {};
  GetModuleFileNameW(module, modulePathW, ARRAY_COUNT(modulePathW) - 1);

  rdcstr modulePath = StringFormat::Wide2UTF8(modulePathW);
  rdcstr moduleBase = get_basename(modulePath);
  uintptr_t offset = (uintptr_t)addr - (uintptr_t)module;
  char offsetStr[32] = {};
  snprintf(offsetStr, ARRAY_COUNT(offsetStr), "%llx", (unsigned long long)offset);

  return moduleBase + "+0x" + offsetStr;
}

static rdcstr CaptureStackModules(uint32_t framesToSkip, uint32_t framesToCapture)
{
  void *frames[32] = {};
  const USHORT maxFrames =
      (USHORT)(framesToCapture < ARRAY_COUNT(frames) ? framesToCapture : ARRAY_COUNT(frames));
  const USHORT numFrames = RtlCaptureStackBackTrace(framesToSkip, maxFrames, frames, NULL);

  if(numFrames == 0)
    return "<empty>";

  rdcstr ret;

  for(USHORT i = 0; i < numFrames; i++)
  {
    if(!ret.empty())
      ret += " <- ";

    ret += CallerModuleForAddress(frames[i]);
  }

  return ret;
}

HMODULE WINAPI Hooked_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE fileHandle, DWORD flags)
{
  bool dohook = true;

  if(s_HookData->libraryIntercept)
  {
    HMODULE ret = s_HookData->libraryIntercept(lpLibFileName, fileHandle, flags);
    if(ret)
      return ret;
    dohook = false;
  }

  if(flags == 0 && GetModuleHandleA(lpLibFileName))
    dohook = false;

  SetLastError(S_OK);

  // we can use the function naked, as when setting up the hook for LoadLibraryExA, our own module
  // was excluded from IAT patching
  HMODULE mod = LoadLibraryExA(lpLibFileName, fileHandle, flags);

  if(IsInterestingGraphicsModuleName(lpLibFileName))
    RDCLOG("LoadLibraryExA graphics module %s flags=0x%08x -> %p", lpLibFileName, flags, mod);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("LoadLibraryA(%s)", lpLibFileName);
#endif

  DWORD err = GetLastError();

  if(dohook && mod && !IsAPISet(lpLibFileName))
    HookAllModules();

  SetLastError(err);

  return mod;
}

HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE fileHandle, DWORD flags)
{
  void *caller = _ReturnAddress();
  rdcstr stack = CaptureStackModules(2, 32);
  bool dohook = true;

  if(s_HookData->libraryIntercept)
  {
    HMODULE ret =
        s_HookData->libraryIntercept(StringFormat::Wide2UTF8(lpLibFileName), fileHandle, flags);
    if(ret)
      return ret;
    dohook = false;
  }

  DWORD flagsExcludingSearchOrders = flags;

  // if this is a pure "filename.dll" load, don't care about search-order flags since loaded DLLs are
  // always returned first regardless of the search order and so we can detect the DLL is already loaded
  if(wcschr(lpLibFileName, L'\\') == 0 && wcschr(lpLibFileName, L'/') == 0)
  {
    flagsExcludingSearchOrders &= ~(LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                    LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_WITH_ALTERED_SEARCH_PATH);

#ifdef LOAD_LIBRARY_SAFE_CURRENT_DIRS
    flagsExcludingSearchOrders &= ~LOAD_LIBRARY_SAFE_CURRENT_DIRS;
#endif
  }

  // if there are no flags (possibly with search path flags excluded) and we already have the
  // library loaded, don't hook anything
  if(flagsExcludingSearchOrders == 0 && GetModuleHandleW(lpLibFileName))
    dohook = false;

  if(flags & (LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))
    dohook = false;

  SetLastError(S_OK);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("LoadLibraryW(%ls)", lpLibFileName);
#endif

  // we can use the function naked, as when setting up the hook for LoadLibraryExA, our own module
  // was excluded from IAT patching
  HMODULE mod = LoadLibraryExW(lpLibFileName, fileHandle, flags);

  rdcstr utf8Name = lpLibFileName ? StringFormat::Wide2UTF8(lpLibFileName) : "";
  if(IsInterestingGraphicsModuleName(utf8Name.c_str()))
    RDCLOG("LoadLibraryExW graphics module %s flags=0x%08x -> %p caller=%p (%s) stack=%s",
           utf8Name.c_str(), flags, mod, caller, CallerModuleForAddress(caller).c_str(),
           stack.c_str());

  DWORD err = GetLastError();

  if(dohook && mod && !IsAPISet(lpLibFileName))
    HookAllModules();

  SetLastError(err);

  return mod;
}

HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName)
{
  return Hooked_LoadLibraryExA(lpLibFileName, NULL, 0);
}

HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName)
{
  return Hooked_LoadLibraryExW(lpLibFileName, NULL, 0);
}

static bool OrdinalAsString(void *func)
{
  return uint64_t(func) <= 0xffff;
}

FARPROC WINAPI Hooked_GetProcAddress(HMODULE mod, LPCSTR func)
{
  if(mod == NULL || func == NULL || mod == s_HookData->ownmodule)
    return GetProcAddress(mod, func);

  rdcstr moduleName = DescribeModuleHandle(mod);
  bool interestingModule = IsInterestingGraphicsModuleName(moduleName.c_str());
  bool ordinal = OrdinalAsString((void *)func);
  bool interestingProc = !ordinal && IsInterestingGraphicsProcName(func);

  if(interestingModule && (interestingProc || ordinal))
  {
    if(ordinal)
      RDCLOG("GetProcAddress request module=%s ordinal=%u", moduleName.c_str(),
             (uint32_t)(uintptr_t(func) & 0xffff));
    else
      RDCLOG("GetProcAddress request module=%s func=%s", moduleName.c_str(), func);
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  if(OrdinalAsString((void *)func))
    RDCDEBUG("Hooked_GetProcAddress(%p, %p)", mod, func);
  else
    RDCDEBUG("Hooked_GetProcAddress(%p, %s)", mod, func);
#endif

  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
  {
    if(it->second.module == NULL)
    {
      it->second.module = GetModuleHandleA(it->first.c_str());
      if(it->second.module)
      {
        // fetch all function hooks here, since we want to fill out the original function pointer
        // even in case nothing imports from that function (which means it would not get filled
        // out through FunctionHook::ApplyHook)
        for(FunctionHook &hook : it->second.FunctionHooks)
        {
          if(hook.orig && *hook.orig == NULL)
            *hook.orig = GetProcAddress(it->second.module, hook.function.c_str());
        }

        it->second.FetchOrdinalNames();
      }
    }

    bool match = (mod == it->second.module);

    if(!match && !it->second.altmodules.empty())
    {
      for(size_t i = 0; !match && i < it->second.altmodules.size(); i++)
        match = (mod == it->second.altmodules[i]);
    }

    if(match)
    {
#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("Located module %s", it->first.c_str());
#endif

      if(OrdinalAsString((void *)func))
      {
#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Ordinal hook");
#endif

        uint32_t ordIndex = (uint16_t)(uintptr_t(func) & 0xffff);

        if(ordIndex < it->second.OrdinalBase)
        {
          RDCERR("Unexpected ordinal - lower than ordinalbase %u for %s",
                 (uint32_t)it->second.OrdinalBase, it->first.c_str());

          SetLastError(S_OK);
          return GetProcAddress(mod, func);
        }

        ordIndex -= it->second.OrdinalBase;

        if(ordIndex >= it->second.OrdinalNames.size())
        {
          RDCERR("Unexpected ordinal - higher than fetched ordinal names (%u) for %s",
                 (uint32_t)it->second.OrdinalNames.size(), it->first.c_str());

          SetLastError(S_OK);
          return GetProcAddress(mod, func);
        }

        func = it->second.OrdinalNames[ordIndex].c_str();

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("found ordinal %s", func);
#endif
      }

      FunctionHook search(func, NULL, NULL);

      auto found =
          std::lower_bound(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end(), search);
      if(found != it->second.FunctionHooks.end() && !(search < *found))
      {
        FARPROC realfunc = GetProcAddress(mod, func);

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Found hooked function, returning hook pointer %p", found->hook);
#endif

        SetLastError(S_OK);

        if(realfunc == NULL)
          return NULL;

        if(ShouldBypassHookForDiagnostics(it->first.c_str(), func))
        {
          RDCLOG("GetProcAddress diagnostic-bypass module=%s func=%s real=%p hook=%p",
                 moduleName.c_str(), func, realfunc, found->hook);
          return realfunc;
        }

        if(interestingModule && (interestingProc || ordinal))
        {
          if(ordinal)
            RDCLOG("GetProcAddress hook-hit module=%s ordinal=%u real=%p hook=%p",
                   moduleName.c_str(), (uint32_t)(uintptr_t(func) & 0xffff), realfunc, found->hook);
          else
            RDCLOG("GetProcAddress hook-hit module=%s func=%s real=%p hook=%p", moduleName.c_str(),
                   func, realfunc, found->hook);
        }

        return (FARPROC)found->hook;
      }
    }
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("No matching hook found, returning original");
#endif

  SetLastError(S_OK);

  FARPROC real = GetProcAddress(mod, func);

  if(interestingModule && (interestingProc || ordinal))
  {
    if(ordinal)
      RDCLOG("GetProcAddress passthrough module=%s ordinal=%u real=%p", moduleName.c_str(),
             (uint32_t)(uintptr_t(func) & 0xffff), real);
    else
      RDCLOG("GetProcAddress passthrough module=%s func=%s real=%p", moduleName.c_str(), func, real);
  }

  return real;
}
static void InitHookData()
{
  if(!s_HookData)
  {
    s_HookData = new CachedHookData;

    RDCASSERT(s_HookData->DllHooks.empty());
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryA", NULL, &Hooked_LoadLibraryA));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryW", NULL, &Hooked_LoadLibraryW));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryExA", NULL, &Hooked_LoadLibraryExA));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryExW", NULL, &Hooked_LoadLibraryExW));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("GetProcAddress", NULL, &Hooked_GetProcAddress));

    for(const char *apiset :
        {"api-ms-win-core-libraryloader-l1-1-0.dll", "api-ms-win-core-libraryloader-l1-1-1.dll",
         "api-ms-win-core-libraryloader-l1-1-2.dll", "api-ms-win-core-libraryloader-l1-2-0.dll",
         "api-ms-win-core-libraryloader-l1-2-1.dll"})
    {
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryA", NULL, &Hooked_LoadLibraryA));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryW", NULL, &Hooked_LoadLibraryW));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryExA", NULL, &Hooked_LoadLibraryExA));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryExW", NULL, &Hooked_LoadLibraryExW));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("GetProcAddress", NULL, &Hooked_GetProcAddress));
    }

    GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCTSTR)&s_HookData, &s_HookData->ownmodule);
  }
}

void LibraryHooks::RegisterFunctionHook(const char *libraryName, const FunctionHook &hook)
{
  if(!_stricmp(libraryName, "kernel32.dll"))
  {
    if(hook.function == "LoadLibraryA" || hook.function == "LoadLibraryW" ||
       hook.function == "LoadLibraryExA" || hook.function == "LoadLibraryExW" ||
       hook.function == "GetProcAddress")
    {
      RDCERR("Cannot hook LoadLibrary* or GetProcAddress, as these are hooked internally");
      return;
    }
  }
  s_HookData->DllHooks[strlower(rdcstr(libraryName))].FunctionHooks.push_back(hook);
}

void LibraryHooks::RegisterLibraryHook(const char *libraryName, FunctionLoadCallback loadedCallback)
{
  s_HookData->DllHooks[strlower(rdcstr(libraryName))].Callbacks.push_back(loadedCallback);
}

void LibraryHooks::IgnoreLibrary(const char *libraryName)
{
  rdcstr lowername = libraryName;

  for(size_t i = 0; i < lowername.size(); i++)
    lowername[i] = (char)tolower(lowername[i]);

  s_HookData->ignores.insert(lowername);
}

void LibraryHooks::BeginHookRegistration()
{
  InitHookData();
}

// hook all functions for currently loaded modules.
// some of these hooks (as above) will hook LoadLibrary/GetProcAddress, to protect
void LibraryHooks::EndHookRegistration()
{
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("Applying hooks");
#endif

  HookAllModules();

  if(s_HookData->missedOrdinals)
  {
#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("Missed ordinals - applying hooks again");
#endif

    // we need to do a second pass now that we know ordinal names to finally hook
    // some imports by ordinal only.
    HookAllModules();

    s_HookData->missedOrdinals = false;
  }
}

void LibraryHooks::Refresh()
{
  // don't need to refresh on windows
}

void LibraryHooks::ReplayInitialise()
{
}

void LibraryHooks::RemoveHooks()
{
  LibraryHooks::RemoveHookCallbacks();

  for(auto it = s_InstalledHooks.begin(); it != s_InstalledHooks.end(); ++it)
  {
    DWORD oldProtection = PAGE_EXECUTE;

    void **IATentry = it->first;

    BOOL success = VirtualProtect(IATentry, sizeof(void *), PAGE_READWRITE, &oldProtection);
    if(!success)
    {
      RDCERR("Failed to make IAT entry writeable 0x%p", IATentry);
      continue;
    }

    *IATentry = it->second;

    success = VirtualProtect(IATentry, sizeof(void *), oldProtection, &oldProtection);
    if(!success)
    {
      RDCERR("Failed to restore IAT entry protection 0x%p", IATentry);
      continue;
    }
  }
}

bool LibraryHooks::Detect(const char *identifier)
{
  bool ret = false;
  ForAllModules([&ret, identifier](const MODULEENTRY32 &me32) {
    if(GetProcAddress(me32.hModule, identifier) != NULL)
      ret = true;
  });
  return ret;
}

void Win32_RegisterManualModuleHooking()
{
  InitHookData();

  s_HookData->hookAll = false;
}

void Win32_InterceptLibraryLoads(std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> callback)
{
  s_HookData->libraryIntercept = callback;
}

void Win32_ManualHookModule(rdcstr modName, HMODULE module)
{
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

  modName = strlower(modName);

  s_HookData->DllHooks[modName].module = module;

  for(FunctionHook &hook : s_HookData->DllHooks[modName].FunctionHooks)
  {
    if(hook.orig)
      *hook.orig = GetProcAddress(module, hook.function.c_str());
  }

  s_HookData->ApplyHooks(modName.c_str(), module);
}

// android only hooking functions, not used on win32
ScopedSuppressHooking::ScopedSuppressHooking()
{
}

ScopedSuppressHooking::~ScopedSuppressHooking()
{
}
