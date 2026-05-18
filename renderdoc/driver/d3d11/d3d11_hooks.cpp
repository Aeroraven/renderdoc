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

#include "d3d11_hooks.h"
#include "driver/dxgi/dxgi_wrapped.h"
#include "hooks/hooks.h"
#include "d3d11_device.h"
#include <d3d11on12.h>
#include <dcomp.h>
#include <windows.graphics.directx.direct3d11.interop.h>

ID3DDevice *GetD3D11DeviceIfAlloc(IUnknown *dev)
{
  if(WrappedID3D11Device::IsAlloc(dev))
    return (WrappedID3D11Device *)dev;

  return NULL;
}

class D3D11Hook : LibraryHook
{
public:
  void RegisterHooks()
  {
    RDCLOG("Registering D3D11 hooks");
    RDCLOG("D3D11 diag marker 2026-05-14-B: suppress-ignore diagnostics enabled");

    WrappedIDXGISwapChain4::RegisterD3DDeviceCallback(GetD3D11DeviceIfAlloc);

    // also require d3dcompiler_??.dll
    if(GetD3DCompiler() == NULL)
    {
      RDCERR("Failed to load d3dcompiler_??.dll - not inserting D3D11 hooks.");
      return;
    }

    LibraryHooks::RegisterLibraryHook("d3d11.dll", NULL);
    LibraryHooks::RegisterLibraryHook("dcomp.dll", NULL);

    CreateDevice.Register("d3d11.dll", "D3D11CreateDevice", D3D11CreateDevice_hook);
    CreateDeviceAndSwapChain.Register("d3d11.dll", "D3D11CreateDeviceAndSwapChain",
                                      D3D11CreateDeviceAndSwapChain_hook);
    D3D11On12CreateDeviceFn.Register("d3d11.dll", "D3D11On12CreateDevice",
                                     D3D11On12CreateDevice_hook);
    CreateDirect3D11DeviceFromDXGIDeviceFn.Register(
        "d3d11.dll", "CreateDirect3D11DeviceFromDXGIDevice",
        CreateDirect3D11DeviceFromDXGIDevice_hook);
    CreateDirect3D11SurfaceFromDXGISurfaceFn.Register(
        "d3d11.dll", "CreateDirect3D11SurfaceFromDXGISurface",
        CreateDirect3D11SurfaceFromDXGISurface_hook);
    DCompositionCreateDeviceFn.Register("dcomp.dll", "DCompositionCreateDevice",
                                        DCompositionCreateDevice_hook);
    DCompositionCreateDevice2Fn.Register("dcomp.dll", "DCompositionCreateDevice2",
                                         DCompositionCreateDevice2_hook);
    DCompositionCreateDevice3Fn.Register("dcomp.dll", "DCompositionCreateDevice3",
                                         DCompositionCreateDevice3_hook);
    DCompositionCreateSurfaceHandleFn.Register("dcomp.dll", "DCompositionCreateSurfaceHandle",
                                               DCompositionCreateSurfaceHandle_hook);

    m_RecurseSlot = Threading::AllocateTLSSlot();
    Threading::SetTLSValue(m_RecurseSlot, NULL);
  }

private:
  static D3D11Hook d3d11hooks;

  HookedFunction<PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN> CreateDeviceAndSwapChain;
  HookedFunction<PFN_D3D11_CREATE_DEVICE> CreateDevice;
  HookedFunction<PFN_D3D11ON12_CREATE_DEVICE> D3D11On12CreateDeviceFn;
  HookedFunction<decltype(&CreateDirect3D11DeviceFromDXGIDevice)>
      CreateDirect3D11DeviceFromDXGIDeviceFn;
  HookedFunction<decltype(&CreateDirect3D11SurfaceFromDXGISurface)>
      CreateDirect3D11SurfaceFromDXGISurfaceFn;
  HookedFunction<decltype(&DCompositionCreateDevice)> DCompositionCreateDeviceFn;
  HookedFunction<decltype(&DCompositionCreateDevice2)> DCompositionCreateDevice2Fn;
  HookedFunction<decltype(&DCompositionCreateDevice3)> DCompositionCreateDevice3Fn;
  HookedFunction<decltype(&DCompositionCreateSurfaceHandle)> DCompositionCreateSurfaceHandleFn;

  // re-entrancy detection (can happen in rare cases with e.g. fraps)
  uint64_t m_RecurseSlot = 0;

  void EndRecurse() { Threading::SetTLSValue(m_RecurseSlot, NULL); }
  bool CheckRecurse()
  {
    if(Threading::GetTLSValue(m_RecurseSlot) == NULL)
    {
      Threading::SetTLSValue(m_RecurseSlot, (void *)1);
      return false;
    }

    return true;
  }

  friend HRESULT CreateD3D11_Internal(RealD3D11CreateFunction real, __in_opt IDXGIAdapter *pAdapter,
                                      D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
                                      __in_ecount_opt(FeatureLevels)
                                          CONST D3D_FEATURE_LEVEL *pFeatureLevels,
                                      UINT FeatureLevels, UINT SDKVersion,
                                      __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
                                      __out_opt IDXGISwapChain **ppSwapChain,
                                      __out_opt ID3D11Device **ppDevice,
                                      __out_opt D3D_FEATURE_LEVEL *pFeatureLevel,
                                      __out_opt ID3D11DeviceContext **ppImmediateContext);

  HRESULT Create_Internal(RealD3D11CreateFunction real, __in_opt IDXGIAdapter *pAdapter,
                          D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
                          __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels,
                          UINT FeatureLevels, UINT SDKVersion,
                          __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
                          __out_opt IDXGISwapChain **ppSwapChain, __out_opt ID3D11Device **ppDevice,
                          __out_opt D3D_FEATURE_LEVEL *pFeatureLevel,
                          __out_opt ID3D11DeviceContext **ppImmediateContext)
  {
    // if we're already inside a wrapped create, then DON'T do anything special. Just call onwards
    if(CheckRecurse())
    {
      return real(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
                  pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
    }

    RDCDEBUG("Call to Create_Internal Flags %x", Flags);
    RDCLOG("D3D11CreateDevice%s request adapter=%p driver=%u flags=0x%08x swapdesc=%p outDevice=%p outSwap=%p",
           pSwapChainDesc ? "AndSwapChain" : "", pAdapter, DriverType, Flags, pSwapChainDesc,
           ppDevice, ppSwapChain);

    // we should no longer go through here in the replay application
    RDCASSERT(!GuguGaga::Inst().IsReplayApp());

    if(GuguGaga::Inst().GetCaptureOptions().apiValidation)
      Flags |= D3D11_CREATE_DEVICE_DEBUG;
    else
      Flags &= ~D3D11_CREATE_DEVICE_DEBUG;

    DXGI_SWAP_CHAIN_DESC swapDesc;
    DXGI_SWAP_CHAIN_DESC *pUsedSwapDesc = NULL;

    if(pSwapChainDesc)
    {
      swapDesc = *pSwapChainDesc;
      pUsedSwapDesc = &swapDesc;
    }

    if(pUsedSwapDesc && !GuguGaga::Inst().GetCaptureOptions().allowFullscreen)
    {
      pUsedSwapDesc->Windowed = TRUE;
    }

    RDCDEBUG("Calling real createdevice...");

    // Hack for D3DGear which crashes if ppDevice is NULL
    ID3D11Device *dummydev = NULL;
    bool dummyUsed = false;
    if(ppDevice == NULL)
    {
      ppDevice = &dummydev;
      dummyUsed = true;
    }

    HRESULT ret = real(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels,
                       SDKVersion, pUsedSwapDesc, ppSwapChain, ppDevice, pFeatureLevel, NULL);

    RDCLOG("D3D11CreateDevice%s result hr=0x%08x realDevice=%p realSwap=%p",
           pSwapChainDesc ? "AndSwapChain" : "", ret, ppDevice ? *ppDevice : NULL,
           ppSwapChain ? *ppSwapChain : NULL);

    SAFE_RELEASE(dummydev);
    if(dummyUsed)
      ppDevice = NULL;

    RDCDEBUG("Called real createdevice...");

    bool suppress = false;

    suppress = (Flags & D3D11_CREATE_DEVICE_PREVENT_ALTERING_LAYER_SETTINGS_FROM_REGISTRY) != 0;

    if(suppress)
    {
      RDCLOG("Application requested not to be hooked. Ignoring suppress flag for diagnostics.");
    }

    if(SUCCEEDED(ret) && ppDevice)
    {
      RDCDEBUG("succeeded and hooking.");

      if(!WrappedID3D11Device::IsAlloc(*ppDevice))
      {
        D3D11InitParams params;
        params.DriverType = DriverType;
        params.Flags = Flags;
        params.SDKVersion = SDKVersion;
        params.NumFeatureLevels = FeatureLevels;
        if(FeatureLevels > 0)
          memcpy(params.FeatureLevels, pFeatureLevels, sizeof(D3D_FEATURE_LEVEL) * FeatureLevels);

        WrappedID3D11Device *wrap = new WrappedID3D11Device(*ppDevice, params);

        RDCDEBUG("created wrapped device.");
        RDCLOG("Wrapped D3D11 device real=%p wrapped=%p", *ppDevice, wrap);

        *ppDevice = wrap;

        wrap->GetImmediateContext(ppImmediateContext);

        if(ppSwapChain && *ppSwapChain)
        {
          RDCLOG("Wrapping D3D11 inline swapchain real=%p outputWindow=%p", *ppSwapChain,
                 pSwapChainDesc ? pSwapChainDesc->OutputWindow : NULL);
          *ppSwapChain = new WrappedIDXGISwapChain4(
              *ppSwapChain, pSwapChainDesc ? pSwapChainDesc->OutputWindow : NULL, wrap);
        }
      }
    }
    else if(SUCCEEDED(ret))
    {
      RDCLOG("Created wrapped D3D11 device.");
    }
    else
    {
      RDCDEBUG("failed. HRESULT: %s", ToStr(ret).c_str());
    }

    EndRecurse();

    return ret;
  }

  static HRESULT WINAPI D3D11CreateDevice_hook(
      __in_opt IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
      __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels,
      UINT SDKVersion, __out_opt ID3D11Device **ppDevice,
      __out_opt D3D_FEATURE_LEVEL *pFeatureLevel, __out_opt ID3D11DeviceContext **ppImmediateContext)
  {
    // just forward the call with NULL swapchain parameters
    return D3D11CreateDeviceAndSwapChain_hook(pAdapter, DriverType, Software, Flags, pFeatureLevels,
                                              FeatureLevels, SDKVersion, NULL, NULL, ppDevice,
                                              pFeatureLevel, ppImmediateContext);
  }

  static HRESULT WINAPI D3D11CreateDeviceAndSwapChain_hook(
      __in_opt IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
      __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels,
      UINT SDKVersion, __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
      __out_opt IDXGISwapChain **ppSwapChain, __out_opt ID3D11Device **ppDevice,
      __out_opt D3D_FEATURE_LEVEL *pFeatureLevel, __out_opt ID3D11DeviceContext **ppImmediateContext)
  {
    PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN createFunc = d3d11hooks.CreateDeviceAndSwapChain();

    if(createFunc == NULL)
    {
      RDCWARN("Call to D3D11CreateDeviceAndSwapChain_hook without onward function pointer");
      createFunc = (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetProcAddress(
          GetModuleHandleA("d3d11.dll"), "D3D11CreateDeviceAndSwapChain");
    }

    // shouldn't ever get here, we should either have it from procaddress or the hook function, but
    // let's be safe.
    if(createFunc == NULL)
    {
      RDCERR("Something went seriously wrong with the hooks!");
      return E_UNEXPECTED;
    }

    return d3d11hooks.Create_Internal(createFunc, pAdapter, DriverType, Software, Flags,
                                      pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc,
                                      ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
  }

  static HRESULT WINAPI D3D11On12CreateDevice_hook(
      _In_ IUnknown *pDevice, UINT Flags,
      _In_reads_opt_(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels,
      _In_reads_opt_(NumQueues) IUnknown *CONST *ppCommandQueues, UINT NumQueues, UINT NodeMask,
      _COM_Outptr_opt_ ID3D11Device **ppDevice,
      _COM_Outptr_opt_ ID3D11DeviceContext **ppImmediateContext,
      _Out_opt_ D3D_FEATURE_LEVEL *pChosenFeatureLevel)
  {
    PFN_D3D11ON12_CREATE_DEVICE createFunc = d3d11hooks.D3D11On12CreateDeviceFn();

    if(createFunc == NULL)
    {
      RDCWARN("Call to D3D11On12CreateDevice_hook without onward function pointer");
      createFunc = (PFN_D3D11ON12_CREATE_DEVICE)GetProcAddress(GetModuleHandleA("d3d11.dll"),
                                                               "D3D11On12CreateDevice");
    }

    if(createFunc == NULL)
    {
      RDCERR("Something went seriously wrong with the D3D11On12 hooks!");
      return E_UNEXPECTED;
    }

    RDCLOG("D3D11On12CreateDevice request device=%p flags=0x%08x featureLevels=%u queues=%u nodeMask=0x%08x outDevice=%p",
           pDevice, Flags, FeatureLevels, NumQueues, NodeMask, ppDevice);

    RealD3D11CreateFunction real =
        [createFunc, pDevice, ppCommandQueues, NumQueues, NodeMask](
            IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT HookFlags,
            CONST D3D_FEATURE_LEVEL *HookFeatureLevels, UINT HookFeatureLevelsCount, UINT SDKVersion,
            CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc, IDXGISwapChain **ppSwapChain,
            ID3D11Device **ppOutDevice, D3D_FEATURE_LEVEL *pFeatureLevel,
            ID3D11DeviceContext **ppImmediateContext) -> HRESULT {
          if(pAdapter != NULL || DriverType != D3D_DRIVER_TYPE_UNKNOWN || Software != NULL ||
             SDKVersion != D3D11_SDK_VERSION || pSwapChainDesc != NULL || ppSwapChain != NULL)
          {
            RDCWARN("Unexpected parameters routed into D3D11On12CreateDevice thunk: adapter=%p driver=%u software=%p sdk=%u swapdesc=%p swapout=%p",
                    pAdapter, DriverType, Software, SDKVersion, pSwapChainDesc, ppSwapChain);
          }

          return createFunc(pDevice, HookFlags, HookFeatureLevels, HookFeatureLevelsCount,
                            ppCommandQueues, NumQueues, NodeMask, ppOutDevice, ppImmediateContext,
                            pFeatureLevel);
        };

    HRESULT ret = d3d11hooks.Create_Internal(real, NULL, D3D_DRIVER_TYPE_UNKNOWN, NULL, Flags,
                                             pFeatureLevels, FeatureLevels, D3D11_SDK_VERSION, NULL,
                                             NULL, ppDevice, pChosenFeatureLevel,
                                             ppImmediateContext);

    RDCLOG("D3D11On12CreateDevice result hr=0x%08x wrappedDevice=%p", ret,
           ppDevice ? *ppDevice : NULL);
    return ret;
  }

  static HRESULT WINAPI CreateDirect3D11DeviceFromDXGIDevice_hook(IDXGIDevice *dxgiDevice,
                                                                  IInspectable **graphicsDevice)
  {
    RDCLOG("CreateDirect3D11DeviceFromDXGIDevice request dxgiDevice=%p out=%p", dxgiDevice,
           graphicsDevice);

    HRESULT ret =
        d3d11hooks.CreateDirect3D11DeviceFromDXGIDeviceFn()(dxgiDevice, graphicsDevice);

    RDCLOG("CreateDirect3D11DeviceFromDXGIDevice result hr=0x%08x graphicsDevice=%p", ret,
           graphicsDevice ? *graphicsDevice : NULL);
    return ret;
  }

  static HRESULT WINAPI CreateDirect3D11SurfaceFromDXGISurface_hook(IDXGISurface *dxgiSurface,
                                                                    IInspectable **graphicsSurface)
  {
    RDCLOG("CreateDirect3D11SurfaceFromDXGISurface request dxgiSurface=%p out=%p", dxgiSurface,
           graphicsSurface);

    HRESULT ret =
        d3d11hooks.CreateDirect3D11SurfaceFromDXGISurfaceFn()(dxgiSurface, graphicsSurface);

    RDCLOG("CreateDirect3D11SurfaceFromDXGISurface result hr=0x%08x graphicsSurface=%p", ret,
           graphicsSurface ? *graphicsSurface : NULL);
    return ret;
  }

  static HRESULT WINAPI DCompositionCreateDevice_hook(IDXGIDevice *dxgiDevice, REFIID iid,
                                                      void **dcompositionDevice)
  {
    RDCLOG("DCompositionCreateDevice request dxgiDevice=%p iid=%s out=%p", dxgiDevice,
           ToStr(iid).c_str(), dcompositionDevice);
    HRESULT ret = d3d11hooks.DCompositionCreateDeviceFn()(dxgiDevice, iid, dcompositionDevice);
    RDCLOG("DCompositionCreateDevice result hr=0x%08x device=%p", ret,
           dcompositionDevice ? *dcompositionDevice : NULL);
    return ret;
  }

  static HRESULT WINAPI DCompositionCreateDevice2_hook(IUnknown *renderingDevice, REFIID iid,
                                                       void **dcompositionDevice)
  {
    RDCLOG("DCompositionCreateDevice2 request renderingDevice=%p iid=%s out=%p", renderingDevice,
           ToStr(iid).c_str(), dcompositionDevice);
    HRESULT ret =
        d3d11hooks.DCompositionCreateDevice2Fn()(renderingDevice, iid, dcompositionDevice);
    RDCLOG("DCompositionCreateDevice2 result hr=0x%08x device=%p", ret,
           dcompositionDevice ? *dcompositionDevice : NULL);
    return ret;
  }

  static HRESULT WINAPI DCompositionCreateDevice3_hook(IUnknown *renderingDevice, REFIID iid,
                                                       void **dcompositionDevice)
  {
    RDCLOG("DCompositionCreateDevice3 request renderingDevice=%p iid=%s out=%p", renderingDevice,
           ToStr(iid).c_str(), dcompositionDevice);
    HRESULT ret =
        d3d11hooks.DCompositionCreateDevice3Fn()(renderingDevice, iid, dcompositionDevice);
    RDCLOG("DCompositionCreateDevice3 result hr=0x%08x device=%p", ret,
           dcompositionDevice ? *dcompositionDevice : NULL);
    return ret;
  }

  static HRESULT WINAPI DCompositionCreateSurfaceHandle_hook(DWORD desiredAccess,
                                                             SECURITY_ATTRIBUTES *securityAttributes,
                                                             HANDLE *surfaceHandle)
  {
    RDCLOG("DCompositionCreateSurfaceHandle request access=0x%08x attrs=%p out=%p", desiredAccess,
           securityAttributes, surfaceHandle);
    HRESULT ret = d3d11hooks.DCompositionCreateSurfaceHandleFn()(desiredAccess, securityAttributes,
                                                                 surfaceHandle);
    RDCLOG("DCompositionCreateSurfaceHandle result hr=0x%08x handle=%p", ret,
           surfaceHandle ? *surfaceHandle : NULL);
    return ret;
  }
};

D3D11Hook D3D11Hook::d3d11hooks;

HRESULT CreateD3D11_Internal(RealD3D11CreateFunction real, __in_opt IDXGIAdapter *pAdapter,
                             D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags,
                             __in_ecount_opt(FeatureLevels) CONST D3D_FEATURE_LEVEL *pFeatureLevels,
                             UINT FeatureLevels, UINT SDKVersion,
                             __in_opt CONST DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
                             __out_opt IDXGISwapChain **ppSwapChain,
                             __out_opt ID3D11Device **ppDevice,
                             __out_opt D3D_FEATURE_LEVEL *pFeatureLevel,
                             __out_opt ID3D11DeviceContext **ppImmediateContext)
{
  return D3D11Hook::d3d11hooks.Create_Internal(
      real, pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion,
      pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
}
