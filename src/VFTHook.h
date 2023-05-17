#pragma once

#include <mutex>
#include <immintrin.h>

#include "RTTIScanner.h"
#include "HookTemplates.h"

/// <summary>
/// A managed hook template.
/// The assembly can be modified without hurting functionality or compatibility
/// with other VFTHookTemplate instances, so long as the data section layout is preserved.
/// Any additional data, structs or class instances can be referenced by the "extra" pointer.
/// Without modification to the assembly, all function arguments passed to the original function
/// will be preserved when calling the hook function, besides those directly passed on the stack.
/// Calling delete on a hook instance automatically unhooks it.
/// </summary>
template <typename HookType> class VFTHookTemplate {
public:
	/// <summary>
	/// Places a hook function instead of a virtual function from a class found by name at a given index.
	/// </summary>
	/// <param name="className">: full name of the class</param>
	/// <param name="vftIndex">: index of the virtual function inside of the virtual function table</param>
	/// <param name="function">: function to call from the hook</param>
	template <typename F> VFTHookTemplate(const char* className, const unsigned int vftIndex, F* function)
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
	template <typename Vft, typename F> VFTHookTemplate(Vft* pVirtualFunctionTable, const unsigned int vftIndex, F* function)
	{
		hook(pVirtualFunctionTable, vftIndex, function);
	}

	/// <summary>
	/// Unhooks a virtual function, restoring the original function pointer while preserving the hook chain (if it exists)
	/// </summary>
	virtual ~VFTHookTemplate()
	{
		HookType* hook = reinterpret_cast<HookType*>(allocationBase);
		if (!hook) return;

		// find the topmost in the chain hook
		HookType* topHook = hook;
		while (reinterpret_cast<HookType*>(topHook->hookData.previous)->hookData.magic == hook->hookData.magic) {
			topHook = reinterpret_cast<HookType*>(topHook->hookData.previous);
		}

		// lock top hook's mutex when hooking and unhooking
		std::mutex& mutex = *topHook->hookData.mutex;
		mutex.lock();

		// the hook data is above the actual hook function pointed at
		HookType* nextHook = reinterpret_cast<HookType*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookBase));
		HookType* prevHook = reinterpret_cast<HookType*>(hook->hookData.previous);

		// if the hook to be removed is in a chain, the reference to it is removed from the chain
		if (hook->hookData.magic == nextHook->hookData.magic) {
			VFTHookTemplate::rdataWrite(&nextHook->hookData.previous, prevHook);
		}

		// if the previous function is a hook, replace the function it hooks (the current hook) 
		// with the function the current hook hooked. If it's not a hook, unhook the virtual function table.
		if (hook->hookData.magic == prevHook->hookData.magic) {
			VFTHookTemplate::rdataWrite(&prevHook->hookData.fnHooked, hook->hookData.fnHooked);
		}
		else {
			VFTHookTemplate::rdataWrite(prevHook, hook->hookData.fnHooked);
		}

		// the hook is freed, we can unlock
		mutex.unlock();

		// destroy the hook and free the memory.
		hook->~HookType();
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
		void* allocationBase = VirtualAlloc(nullptr, sizeof(HookType), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!allocationBase) return;

		this->allocationBase = allocationBase;
		HookType* hook = new(allocationBase) HookType{};

		void** vftEntry = &reinterpret_cast<void**>(pVirtualFunctionTable)[vftIndex];

		// set up new hook data
		hook->hookData.mutex.reset(new std::mutex);
		hook->hookData.fnHooked = *vftEntry;
		hook->hookData.previous = reinterpret_cast<void*>(vftEntry);
		hook->hookData.fnNew = reinterpret_cast<void*>(function);

		// get and check for any previously placed hooks, which will need to be chained together
		// the hook data is above the actual hook function pointed to
		HookType* prevHook = reinterpret_cast<HookType*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookBase));
		if (hook->hookData.magic == prevHook->hookData.magic) {
			// lock top hook's mutex when hooking and unhooking
			std::mutex& mutex = *prevHook->hookData.mutex;
			mutex.lock();

			// update hook pointers
			_mm_mfence();
			if (hook->hookData.fnHooked != *vftEntry) {
				hook->hookData.fnHooked = *vftEntry;
				prevHook = reinterpret_cast<HookType*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookBase));
			}
			VFTHookTemplate::rdataWrite(&prevHook->hookData.previous, hook);
			VFTHookTemplate::rdataWrite(vftEntry, reinterpret_cast<uint8_t*>(hook) + sizeof(HookBase));

			// unlock the mutex
			mutex.unlock();
		}
		else {
			_mm_mfence();
			if (hook->hookData.fnHooked != *vftEntry) hook->hookData.fnHooked = *vftEntry;

			// write a pointer to the hook to the virtual function table
			VFTHookTemplate::rdataWrite(vftEntry, reinterpret_cast<uint8_t*>(hook) + sizeof(HookBase));
		}
	}

	void* allocationBase = nullptr;
};

using VFTHook = VFTHookTemplate<EntryHook>;
