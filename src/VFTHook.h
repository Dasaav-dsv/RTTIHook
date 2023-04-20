#pragma once

#include <mutex>
#include <immintrin.h>

#include "RTTIScanner.h"

/// <summary>
/// A managed hook template.
/// The assembly can be modified without hurting functionality or compatibility
/// with other VFTHook instances, so long as the data section layout is preserved.
/// Any additional data, structs or class instances can be referenced by the "extra" pointer.
/// Without modification to the assembly, all function arguments passed to the original function
/// will be preserved when calling the hook function, besides those directly passed on the stack.
/// Calling delete on a hook instance automatically unhooks it.
/// </summary>
class VFTHook {
public:
	/// <summary>
	/// Places a hook function instead of a virtual function from a class found by name at a given index.
	/// </summary>
	/// <param name="className">: full name of the class</param>
	/// <param name="vftIndex">: index of the virtual function inside of the virtual function table</param>
	/// <param name="function">: function to call from the hook</param>
	template <typename F> VFTHook(const char* className, const unsigned int vftIndex, F* function)
	{
		RTTIScanner::RTTI* pClass = RTTIScanner::getClassRTTI(className);
		if (!pClass) return;

		hook(pClass->pVirtualFunctionTable, vftIndex, function);
	}

	/// <summary>
	/// Places a hook function instead of a virtual function in a virtual function table at a given index.
	/// </summary>
	/// <param name="pVirtualFunctionTable">: pointer to the virtual function table</param>
	/// <param name="vftIndex">: index of the virtual function inside of the virtual function table</param>
	/// <param name="function">: function to call from the hook</param>
	template <typename Vft, typename F> VFTHook(Vft* pVirtualFunctionTable, const unsigned int vftIndex, F* function)
	{
		hook(pVirtualFunctionTable, vftIndex, function);
	}

	/// <summary>
	/// Unhooks a virtual function, restoring the original function pointer while preserving the hook chain (if it exists)
	/// </summary>
	virtual ~VFTHook()
	{
		HookLayout* hook = reinterpret_cast<HookLayout*>(allocationBase);
		if (!hook) return;

		// find the topmost in the chain hook
		HookLayout* topHook = hook;
		while (topHook->hookData.previous->hookData.magic == hook->hookData.magic) {
			topHook = topHook->hookData.previous;
		}

		// lock top hook's mutex when hooking and unhooking
		std::mutex& mutex = *topHook->hookData.mutex;
		mutex.lock();

		// the hook data is above the actual hook function pointed at
		HookLayout* nextHook = reinterpret_cast<HookLayout*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookLayout::HookData));
		HookLayout* prevHook = hook->hookData.previous;

		// if the hook to be removed is in a chain, the reference to it is removed from the chain
		if (hook->hookData.magic == nextHook->hookData.magic) {
			VFTHook::rdataWrite(&nextHook->hookData.previous, prevHook);
		}

		// if the previous function is a hook, replace the function it hooks (the current hook) 
		// with the function the current hook hooked. If it's not a hook, unhook the virtual function table.
		if (hook->hookData.magic == prevHook->hookData.magic) {
			VFTHook::rdataWrite(&prevHook->hookData.fnHooked, hook->hookData.fnHooked);
		}
		else {
			VFTHook::rdataWrite(prevHook, hook->hookData.fnHooked);
		}

		// the hook is freed, we can unlock
		mutex.unlock();

		VirtualFree(this->allocationBase, NULL, MEM_RELEASE);
	}

	/// <summary>
	/// Write a pointer to potentially read-only memory, restoring the protection flags afterwards.
	/// </summary>
	/// <param name="pAddress">: a pointer to the address in memory to be written to</param>
	/// <param name="pointer">: a pointer to write to memory</param>
	/// <returns>true on a successful write, otherwise false</returns>
	template <typename T1, typename T2> static bool rdataWrite(T1* pAddress, T2* pointer)
	{
		DWORD oldProtect;
		if (!VirtualProtect(reinterpret_cast<void*>(pAddress), sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
		_mm_mfence();
		*reinterpret_cast<uintptr_t*>(pAddress) = reinterpret_cast<uintptr_t>(pointer);
		return VirtualProtect(reinterpret_cast<void*>(pAddress), sizeof(uintptr_t), oldProtect, &oldProtect);
	}

private:
	template <typename Vft, typename F> void hook(Vft* pVirtualFunctionTable, const unsigned int vftIndex, F* function)
	{
		// allocate executable memory for the hook
		void* allocationBase = VirtualAlloc(nullptr, sizeof(HookLayout), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!allocationBase) return;

		this->allocationBase = allocationBase;
		HookLayout* hook = reinterpret_cast<HookLayout*>(std::memcpy(allocationBase, &hookLayout, sizeof(HookLayout)));

		void** vftEntry = &reinterpret_cast<void**>(pVirtualFunctionTable)[vftIndex];

		// set up new hook data
		hook->hookData.mutex.reset(new std::mutex);
		hook->hookData.fnHooked = *vftEntry;
		hook->hookData.previous = reinterpret_cast<HookLayout*>(vftEntry);
		hook->hookData.fnNew = reinterpret_cast<void*>(function);

		// get and check for any previously placed hooks, which will need to be chained together
		// the hook data is above the actual hook function pointed to
		HookLayout* prevHook = reinterpret_cast<HookLayout*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookLayout::HookData));
		if (hook->hookData.magic == prevHook->hookData.magic) {
			// lock top hook's mutex when hooking and unhooking
			std::mutex& mutex = *prevHook->hookData.mutex;
			mutex.lock();

			// update hook pointers
			_mm_mfence();
			if (hook->hookData.fnHooked != *vftEntry) {
				hook->hookData.fnHooked = *vftEntry;
				prevHook = reinterpret_cast<HookLayout*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookLayout::HookData));
			}
			VFTHook::rdataWrite(&prevHook->hookData.previous, hook);
			VFTHook::rdataWrite(vftEntry, &hook->asmRaw);

			// unlock the mutex
			mutex.unlock();
		}
		else {
			_mm_mfence();
			if (hook->hookData.fnHooked != *vftEntry) hook->hookData.fnHooked = *vftEntry;

			// write a pointer to the hook to the virtual function table
			VFTHook::rdataWrite(vftEntry, &hook->asmRaw);
		}
	}

	void* allocationBase = nullptr;

	struct HookLayout {
		HookLayout() {}

		//data:
		struct HookData {
			HookData() {}

			const unsigned long long magic = 0x6B6F6F48544656ull; // magic: "VFTHook\0"
			std::shared_ptr<std::mutex> mutex = nullptr;
			HookLayout* previous = nullptr;
			void* fnNew = nullptr;
			void* fnHooked = nullptr;
			void* extra = nullptr;
		} hookData;

		// assembly:
		unsigned char asmRaw[114] = {
		0x48, 0x8D, 0x44, 0x24, 0xA0,       // lea    rax,[rsp-0x60]
		0x24, 0xF0,                   		// and    al,0xF0
		0x0F, 0x29, 0x40, 0x50,             // movaps [rax+0x50],xmm0
		0x0F, 0x29, 0x48, 0x40,             // movaps [rax+0x40],xmm1
		0x0F, 0x29, 0x50, 0x30,             // movaps [rax+0x30],xmm2
		0x0F, 0x29, 0x58, 0x20,             // movaps [rax+0x20],xmm3
		0x0F, 0x29, 0x60, 0x10,             // movaps [rax+0x10],xmm4
		0x0F, 0x29, 0x28,                	// movaps [rax],xmm5
		0x48, 0x89, 0x60, 0xF0,             // mov    [rax-0x10],rsp
		0x48, 0x89, 0x48, 0xE8,             // mov    [rax-0x18],rcx
		0x48, 0x89, 0x50, 0xE0,             // mov    [rax-0x20],rdx
		0x4C, 0x89, 0x40, 0xD8,             // mov    [rax-0x28],r8
		0x4C, 0x89, 0x48, 0xD0,             // mov    [rax-0x30],r9
		0x48, 0x8D, 0x60, 0xB0,             // lea    rsp,[rax-0x50]
		0xFF, 0x15, 0xAC, 0xFF, 0xFF, 0xFF, // call   [fnNew]
		0x48, 0x8D, 0x44, 0x24, 0x50,       // lea    rax,[rsp+0x50]
		0x4C, 0x8B, 0x48, 0xD0,             // mov    r9,[rax-0x30]
		0x4C, 0x8B, 0x40, 0xD8,             // mov    r8,[rax-0x28]
		0x48, 0x8B, 0x50, 0xE0,             // mov    rdx,[rax-0x20]
		0x48, 0x8B, 0x48, 0xE8,             // mov    rcx,[rax-0x18]
		0x0F, 0x28, 0x28,                	// movaps xmm5,[rax]
		0x0F, 0x28, 0x60, 0x10,             // movaps xmm4,[rax+0x10]
		0x0F, 0x28, 0x58, 0x20,             // movaps xmm3,[rax+0x20]
		0x0F, 0x28, 0x50, 0x30,             // movaps xmm2,[rax+0x30]
		0x0F, 0x28, 0x48, 0x40,             // movaps xmm1,[rax+0x40]
		0x0F, 0x28, 0x40, 0x50,             // movaps xmm0,[rax+0x50]
		0x48, 0x8B, 0x60, 0xF0,             // mov    rsp,[rax-0x10]
		0xFF, 0x25, 0x7E, 0xFF, 0xFF, 0xFF, // jmp    [fnHooked]
		};
	};

	static inline HookLayout hookLayout = {};
};
