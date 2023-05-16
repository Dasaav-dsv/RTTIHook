#pragma once

#include <mutex>
#include <memory>
#include <cstdint>

// A struct for holding the combined context of (most of) the registers.
// It is allocated automatically by hook templates.
struct alignas(16) HookContext {
	using reg64 = int[2];
	using imm256 = float[8];
	reg64 rax;
	reg64 rbx;
	reg64 rcx;
	reg64 rdx;
	reg64 rsp;
	reg64 rbp;
	reg64 rsi;
	reg64 rdi;
	reg64 r8;
	reg64 r9;
	reg64 r10;
	reg64 r11;
	reg64 r12;
	reg64 r13;
	reg64 r14;
	reg64 r15;
	imm256 imm0;
	imm256 imm1;
	imm256 imm2;
	imm256 imm3;
	imm256 imm4;
	imm256 imm5;
	imm256 imm6;
	imm256 imm7;
	imm256 imm8;
	imm256 imm9;
	imm256 imm10;
	imm256 imm11;
	imm256 imm12;
	imm256 imm13;
	imm256 imm14;
	imm256 imm15;
};

// The struct at the beginning of every hook instance.
// It is entirely managed by the hooking system, 
// setting these values yourself will certainly break things.
struct HookData {
	HookData() {}

	const unsigned long long magic = 0x6B6F6F48696E55ull; // magic: "UniHook\0".
	uint64_t : 64;
	std::shared_ptr<std::mutex> mutex = nullptr;
	std::unique_ptr<HookContext> allocator = std::make_unique<HookContext>(); // Using a unique_ptr as a pseudoallocator.
	HookContext* context = allocator.get(); // Although you could access the unique_ptr contents directly through the pointer above, it would be UB.
	void* previous = nullptr; // Pointer to the previous hook in a chain of hooks.
	void* fnNew = nullptr; // Pointer to the user-defined hooking function.
	void* fnHooked = nullptr; // Pointer to the hooked function.
	void* extra = nullptr; // An extra pointer field, used mostly to store return addresses.
};

// The default hook type.
// The hooking function is executed before the hooked function.
// The default Microsoft x86-64 calling convention is assumed: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
// Use EntryHookV for vectorcall functions.
struct EntryHook {
	EntryHook() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[79] = {
	0x4C, 0x8D, 0x15, 0xD1, 0xFF, 0xFF, 0xFF, // lea    r10,[context]
	0x49, 0x8B, 0x02,                         // mov    rax,[context]
	0x48, 0x89, 0x48, 0x10,                   // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                   // mov    [reg64_rdx],rdx
	0x4C, 0x89, 0x40, 0x40,                   // mov    [reg64_r8],r8 
	0x4C, 0x89, 0x48, 0x48,                   // mov    [reg64_r9],r9
	0x49, 0x8D, 0x42, 0x54,                   // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                   // xchg   [old_return],rax
	0x49, 0x89, 0x42, 0x20,                   // mov    [extra],rax
	0xFF, 0x25, 0xBC, 0xFF, 0xFF, 0xFF,       // jmp    [fnNew]
	0x4C, 0x8B, 0x15, 0xA5, 0xFF, 0xFF, 0xFF, // mov    r10,[context] <- new_return
	0x49, 0x8B, 0x4A, 0x10,                   // mov    rcx,[reg64_rcx]
	0x49, 0x8B, 0x52, 0x18,                   // mov    rdx,[reg64_rdx]
	0x4D, 0x8B, 0x42, 0x40,                   // mov    r8,[reg64_r8] 
	0x4D, 0x8B, 0x4A, 0x48,                   // mov    r9,[reg64_r9]
	0xFF, 0x35, 0xAF, 0xFF, 0xFF, 0xFF,       // push   [extra]
	0xFF, 0x25, 0xA1, 0xFF, 0xFF, 0xFF,       // jmp    [fnHooked]
	};
};

// A hook that executes the hooked function before the hooking one.
// The return value of the hooked function is preserved, use ReturnHook to override it.
// The default Microsoft x86-64 calling convention is assumed: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
// Use ExitHookV for vectorcall functions.
struct ExitHook {
	ExitHook() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[92] = {
	0x4C, 0x8D, 0x15, 0xD1, 0xFF, 0xFF, 0xFF, // lea    r10,[context]
	0x49, 0x8B, 0x02,                         // mov    rax,[context]
	0x48, 0x89, 0x48, 0x10,                   // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                   // mov    [reg64_rdx],rdx
	0x4C, 0x89, 0x40, 0x40,                   // mov    [reg64_r8],r8 
	0x4C, 0x89, 0x48, 0x48,                   // mov    [reg64_r9],r9
	0x49, 0x8D, 0x42, 0x54,                   // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                   // xchg   [old_return],rax
	0x49, 0x89, 0x42, 0x20,                   // mov    [extra],rax
	0xFF, 0x25, 0xC4, 0xFF, 0xFF, 0xFF,       // jmp    [fnHooked]
	0x4C, 0x8B, 0x15, 0xA5, 0xFF, 0xFF, 0xFF, // mov    r10,[context] <- new_return
	0x49, 0x89, 0x02,                         // mov    [reg64_rax],rax
	0x49, 0x8B, 0x4A, 0x10,                   // mov    rcx,[reg64_rcx]
	0x49, 0x8B, 0x52, 0x18,                   // mov    rdx,[reg64_rdx]
	0x4D, 0x8B, 0x42, 0x40,                   // mov    r8,[reg64_r8] 
	0x4D, 0x8B, 0x4A, 0x48,                   // mov    r9,[reg64_r9]
	0xFF, 0x15, 0x9C, 0xFF, 0xFF, 0xFF,       // call   [fnNew]
	0x48, 0x8B, 0x05, 0x85, 0xFF, 0xFF, 0xFF, // mov    rax,[context]
	0x48, 0x8B, 0x00,                         // mov    rax,[reg64_rax]
	0xFF, 0x25, 0x9C, 0xFF, 0xFF, 0xFF        // jmp    [extra]
	};
};

// A hook that executes the hooked function before the hooking one.
// The return value of the hooked function is overriden, make your hooking function has a fitting return value.
// The default Microsoft x86-64 calling convention is assumed: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
// Use ReturnHookV for vectorcall functions.
struct ReturnHook {
	ReturnHook() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[79] = {
	0x4C, 0x8D, 0x15, 0xD1, 0xFF, 0xFF, 0xFF, // lea    r10,[context]
	0x49, 0x8B, 0x02,                         // mov    rax,[context]
	0x48, 0x89, 0x48, 0x10,                   // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                   // mov    [reg64_rdx],rdx
	0x4C, 0x89, 0x40, 0x40,                   // mov    [reg64_r8],r8 
	0x4C, 0x89, 0x48, 0x48,                   // mov    [reg64_r9],r9
	0x49, 0x8D, 0x42, 0x54,                   // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                   // xchg   [old_return],rax
	0x49, 0x89, 0x42, 0x20,                   // mov    [extra],rax
	0xFF, 0x25, 0xC4, 0xFF, 0xFF, 0xFF,       // jmp    [fnHooked]
	0x4C, 0x8B, 0x15, 0xA5, 0xFF, 0xFF, 0xFF, // mov    r10,[context] <- new_return
	0x49, 0x8B, 0x4A, 0x10,                   // mov    rcx,[reg64_rcx]
	0x49, 0x8B, 0x52, 0x18,                   // mov    rdx,[reg64_rdx]
	0x4D, 0x8B, 0x42, 0x40,                   // mov    r8,[reg64_r8] 
	0x4D, 0x8B, 0x4A, 0x48,                   // mov    r9,[reg64_r9]
	0xFF, 0x35, 0xAF, 0xFF, 0xFF, 0xFF,       // push   [extra]
	0xFF, 0x25, 0x99, 0xFF, 0xFF, 0xFF,       // jmp    [fnNew]
	};
};

// A special hook template that loads all integer registers into the context structure,
// then passes a pointer to it to the hooking function as its first parameter.
// This allows modifying any register by accessing them inside the struct.
// Hooking function signature:
// void (*)(HookContext*)
// Does not include SIMD registers, use ContextHookV for that.
struct ContextHook {
	ContextHook() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[168] = {
	0x50,                                           // push   rax
	0x48, 0x8B, 0x05, 0xD0, 0xFF, 0xFF, 0xFF,       // mov    rax,[context]
	0x8F, 0x00,                                     // pop    [reg64_rax]
	0x48, 0x89, 0x58, 0x08,                         // mov    [reg64_rbx],rbx
	0x48, 0x89, 0x48, 0x10,                         // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                         // mov    [reg64_rdx],rdx
	0x48, 0x89, 0x60, 0x20,                         // mov    [reg64_rsp],rsp
	0x48, 0x89, 0x68, 0x28,                         // mov    [reg64_rbp],rbp
	0x48, 0x89, 0x70, 0x30,                         // mov    [reg64_rsi],rsi
	0x48, 0x89, 0x78, 0x38,                         // mov    [reg64_rdi],rdi
	0x4C, 0x89, 0x40, 0x40,                         // mov    [reg64_r8],r8
	0x4C, 0x89, 0x48, 0x48,                         // mov    [reg64_r9],r9
	0x4C, 0x89, 0x50, 0x50,                         // mov    [reg64_r10],r10
	0x4C, 0x89, 0x58, 0x58,                         // mov    [reg64_r11],r11
	0x4C, 0x89, 0x60, 0x60,                         // mov    [reg64_r12],r12
	0x4C, 0x89, 0x68, 0x68,                         // mov    [reg64_r13],r13
	0x4C, 0x89, 0x70, 0x70,                         // mov    [reg64_r14],r14
	0x4C, 0x89, 0x78, 0x78,                         // mov    [reg64_r15],r15
	0x48, 0x89, 0xC1,                               // mov    rcx,rax
	0x48, 0x8D, 0x05, 0x11, 0x00, 0x00, 0x00,       // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                         // xchg   [old_return],rax
	0x48, 0x87, 0x05, 0x9D, 0xFF, 0xFF, 0xFF,       // xchg   [extra],rax
	0xFF, 0x25, 0x87, 0xFF, 0xFF, 0xFF,             // jmp    [fnNew]
	0x48, 0x8B, 0x05, 0x70, 0xFF, 0xFF, 0xFF,       // mov    rax,[context]
	0x48, 0x8B, 0x58, 0x08,                         // mov    rbx,[reg64_rbx]
	0x48, 0x8B, 0x48, 0x10,                         // mov    rcx,[reg64_rcx]
	0x48, 0x8B, 0x50, 0x18,                         // mov    rdx,[reg64_rdx]
	0x48, 0x8B, 0x68, 0x28,                         // mov    rbp,[reg64_rbp]
	0x48, 0x8B, 0x70, 0x30,                         // mov    rsi,[reg64_rsi]
	0x48, 0x8B, 0x78, 0x38,                         // mov    rdi,[reg64_rdi]
	0x4C, 0x8B, 0x40, 0x40,                         // mov    r8,[reg64_r8]
	0x4C, 0x8B, 0x48, 0x48,                         // mov    r9,[reg64_r9]
	0x4C, 0x8B, 0x60, 0x60,                         // mov    r12,[reg64_r12]
	0x4C, 0x8B, 0x68, 0x68,                         // mov    r13,[reg64_r13]
	0x4C, 0x8B, 0x70, 0x70,                         // mov    r14,[reg64_r14]
	0x4C, 0x8B, 0x78, 0x78,                         // mov    r15,[reg64_r15]
	0xFF, 0x35, 0x5A, 0xFF, 0xFF, 0xFF,             // push   [extra]
	0xFF, 0x25, 0x4C, 0xFF, 0xFF, 0xFF,             // jmp    [fnHooked]
	};
};

// The hooking function is executed before the hooked function.
// The vectorcall Microsoft calling convention is assumed: https://learn.microsoft.com/en-us/cpp/cpp/vectorcall?view=msvc-170
// Can be used for non-vectorcall functions, however it would be unnecessary and slower than normal EntryHook.
struct EntryHookV {
	EntryHookV() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[163] = {
	0x4C, 0x8D, 0x15, 0xD1, 0xFF, 0xFF, 0xFF, // lea    r10,[context]
	0x49, 0x8B, 0x02,                         // mov    rax,[context]
	0x48, 0x89, 0x48, 0x10,                   // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                   // mov    [reg64_rdx],rdx
	0x4C, 0x89, 0x40, 0x40,                   // mov    [reg64_r8],r8 
	0x4C, 0x89, 0x48, 0x48,                   // mov    [reg64_r9],r9
	0x0F, 0x29, 0x80, 0x80, 0x00, 0x00, 0x00, // movaps [imm256_xmm0],xmm0
	0x0F, 0x29, 0x88, 0xA0, 0x00, 0x00, 0x00, // movaps [imm256_xmm1],xmm1
	0x0F, 0x29, 0x90, 0xC0, 0x00, 0x00, 0x00, // movaps [imm256_xmm2],xmm2
	0x0F, 0x29, 0x98, 0xE0, 0x00, 0x00, 0x00, // movaps [imm256_xmm3],xmm3
	0x0F, 0x29, 0xA0, 0x00, 0x01, 0x00, 0x00, // movaps [imm256_xmm4],xmm4
	0x0F, 0x29, 0xA8, 0x20, 0x01, 0x00, 0x00, // movaps [imm256_xmm5],xmm5
	0x49, 0x8D, 0x42, 0x7E,                   // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                   // xchg   [old_return],rax
	0x49, 0x89, 0x42, 0x20,                   // mov    [extra],rax
	0xFF, 0x25, 0x92, 0xFF, 0xFF, 0xFF,       // jmp    [fnNew]
	0x48, 0x8B, 0x05, 0x7B, 0xFF, 0xFF, 0xFF, // mov    rax,[context] <- new_return
	0x48, 0x8B, 0x48, 0x10,                   // mov    rcx,[reg64_rcx]
	0x48, 0x8B, 0x50, 0x18,                   // mov    rdx,[reg64_rdx]
	0x4C, 0x8B, 0x40, 0x40,                   // mov    r8,[reg64_r8] 
	0x4C, 0x8B, 0x48, 0x48,                   // mov    r9,[reg64_r9]
	0x0F, 0x28, 0x80, 0x80, 0x00, 0x00, 0x00, // movaps xmm0,[imm256_xmm0]
	0x0F, 0x28, 0x88, 0xA0, 0x00, 0x00, 0x00, // movaps xmm1,[imm256_xmm1]
	0x0F, 0x28, 0x90, 0xC0, 0x00, 0x00, 0x00, // movaps xmm2,[imm256_xmm2]
	0x0F, 0x28, 0x98, 0xE0, 0x00, 0x00, 0x00, // movaps xmm3,[imm256_xmm3]
	0x0F, 0x28, 0xA0, 0x00, 0x01, 0x00, 0x00, // movaps xmm4,[imm256_xmm4]
	0x0F, 0x28, 0xA8, 0x20, 0x01, 0x00, 0x00, // movaps xmm5,[imm256_xmm5]
	0xFF, 0x35, 0x5B, 0xFF, 0xFF, 0xFF,       // push   [extra]
	0xFF, 0x25, 0x4D, 0xFF, 0xFF, 0xFF,       // jmp    [fnHooked]
	};
};

// A hook that executes the hooked function before the hooking one.
// The return value of the hooked function is preserved, use ReturnHookV to override it.
// The vectorcall Microsoft calling convention is assumed: https://learn.microsoft.com/en-us/cpp/cpp/vectorcall?view=msvc-170
// Can be used for non-vectorcall functions, however it would be unnecessary and slower than normal ExitHook.
struct ExitHookV {
	ExitHookV() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[235] = {
	0x4C, 0x8D, 0x15, 0xD1, 0xFF, 0xFF, 0xFF, // lea    r10,[context]
	0x49, 0x8B, 0x02,                         // mov    rax,[context]
	0x48, 0x89, 0x48, 0x10,                   // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                   // mov    [reg64_rdx],rdx
	0x4C, 0x89, 0x40, 0x40,                   // mov    [reg64_r8],r8 
	0x4C, 0x89, 0x48, 0x48,                   // mov    [reg64_r9],r9
	0x0F, 0x29, 0x80, 0x80, 0x00, 0x00, 0x00, // movaps [imm256_xmm0],xmm0
	0x0F, 0x29, 0x88, 0xA0, 0x00, 0x00, 0x00, // movaps [imm256_xmm1],xmm1
	0x0F, 0x29, 0x90, 0xC0, 0x00, 0x00, 0x00, // movaps [imm256_xmm2],xmm2
	0x0F, 0x29, 0x98, 0xE0, 0x00, 0x00, 0x00, // movaps [imm256_xmm3],xmm3
	0x0F, 0x29, 0xA0, 0x00, 0x01, 0x00, 0x00, // movaps [imm256_xmm4],xmm4
	0x0F, 0x29, 0xA8, 0x20, 0x01, 0x00, 0x00, // movaps [imm256_xmm5],xmm5
	0x49, 0x8D, 0x42, 0x7E,                   // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                   // xchg   [old_return],rax
	0x49, 0x89, 0x42, 0x20,                   // mov    [extra],rax
	0xFF, 0x25, 0x9A, 0xFF, 0xFF, 0xFF,       // jmp    [fnHooked]
	0x4C, 0x8B, 0x15, 0x7B, 0xFF, 0xFF, 0xFF, // mov    r10,[context] <- new_return
	0x49, 0x89, 0x02,                         // mov    [reg64_rax],rax
	0x48, 0x8B, 0x48, 0x10,                   // mov    rcx,[reg64_rcx]
	0x48, 0x8B, 0x50, 0x18,                   // mov    rdx,[reg64_rdx]
	0x4C, 0x8B, 0x40, 0x40,                   // mov    r8,[reg64_r8] 
	0x4C, 0x8B, 0x48, 0x48,                   // mov    r9,[reg64_r9]
	0x4C, 0x89, 0xD0,                         // mov    rax,r10
	0x0F, 0x29, 0x80, 0x40, 0x01, 0x00, 0x00, // movaps [imm256_xmm6],xmm0
	0x0F, 0x29, 0x88, 0x60, 0x01, 0x00, 0x00, // movaps [imm256_xmm7],xmm1
	0x0F, 0x29, 0x90, 0x80, 0x01, 0x00, 0x00, // movaps [imm256_xmm8],xmm2
	0x0F, 0x29, 0x98, 0xA0, 0x01, 0x00, 0x00, // movaps [imm256_xmm9],xmm3
	0x0F, 0x28, 0x80, 0x80, 0x00, 0x00, 0x00, // movaps xmm0,[imm256_xmm0]
	0x0F, 0x28, 0x88, 0xA0, 0x00, 0x00, 0x00, // movaps xmm1,[imm256_xmm1]
	0x0F, 0x28, 0x90, 0xC0, 0x00, 0x00, 0x00, // movaps xmm2,[imm256_xmm2]
	0x0F, 0x28, 0x98, 0xE0, 0x00, 0x00, 0x00, // movaps xmm3,[imm256_xmm3]
	0x0F, 0x28, 0xA0, 0x00, 0x01, 0x00, 0x00, // movaps xmm4,[imm256_xmm4]
	0x0F, 0x28, 0xA8, 0x20, 0x01, 0x00, 0x00, // movaps xmm5,[imm256_xmm5]
	0xFF, 0x15, 0x45, 0xFF, 0xFF, 0xFF,       // call   [fnNew]
	0x48, 0x8B, 0x05, 0x12, 0xFF, 0xFF, 0xFF, // mov    rax,[context]
	0x0F, 0x28, 0x80, 0x40, 0x01, 0x00, 0x00, // movaps xmm0,[imm256_xmm6]
	0x0F, 0x28, 0x88, 0x60, 0x01, 0x00, 0x00, // movaps xmm1,[imm256_xmm7]
	0x0F, 0x28, 0x90, 0x80, 0x01, 0x00, 0x00, // movaps xmm2,[imm256_xmm8]
	0x0F, 0x28, 0x98, 0xA0, 0x01, 0x00, 0x00, // movaps xmm3,[imm256_xmm9]
	0x48, 0x8B, 0x00,                         // mov    rax,[reg64_rax]
	0xFF, 0x25, 0x0D, 0xFF, 0xFF, 0xFF        // jmp    [extra]
	};
};

// A hook that executes the hooked function before the hooking one.
// The return value of the hooked function is overriden, make your hooking function has a fitting return value.
// The vectorcall Microsoft calling convention is assumed: https://learn.microsoft.com/en-us/cpp/cpp/vectorcall?view=msvc-170
// Can be used for non-vectorcall functions, however it would be unnecessary and slower than normal ReturnHook.
struct ReturnHookV {
	ReturnHookV() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[169] = {
	0x4C, 0x8D, 0x15, 0xD1, 0xFF, 0xFF, 0xFF, // lea    r10,[context]
	0x49, 0x8B, 0x02,                         // mov    rax,[context]
	0x48, 0x89, 0x48, 0x10,                   // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                   // mov    [reg64_rdx],rdx
	0x4C, 0x89, 0x40, 0x40,                   // mov    [reg64_r8],r8 
	0x4C, 0x89, 0x48, 0x48,                   // mov    [reg64_r9],r9
	0x0F, 0x29, 0x80, 0x80, 0x00, 0x00, 0x00, // movaps [imm256_xmm0],xmm0
	0x0F, 0x29, 0x88, 0xA0, 0x00, 0x00, 0x00, // movaps [imm256_xmm1],xmm1
	0x0F, 0x29, 0x90, 0xC0, 0x00, 0x00, 0x00, // movaps [imm256_xmm2],xmm2
	0x0F, 0x29, 0x98, 0xE0, 0x00, 0x00, 0x00, // movaps [imm256_xmm3],xmm3
	0x0F, 0x29, 0xA0, 0x00, 0x01, 0x00, 0x00, // movaps [imm256_xmm4],xmm4
	0x0F, 0x29, 0xA8, 0x20, 0x01, 0x00, 0x00, // movaps [imm256_xmm5],xmm5
	0x49, 0x8D, 0x42, 0x7E,                   // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                   // xchg   [old_return],rax
	0x49, 0x89, 0x42, 0x20,                   // mov    [extra],rax
	0xFF, 0x25, 0x9A, 0xFF, 0xFF, 0xFF,       // jmp    [fnHooked]
	0x4C, 0x8B, 0x15, 0x7B, 0xFF, 0xFF, 0xFF, // mov    r10,[context] <- new_return
	0x49, 0x89, 0x02,                         // mov    [reg64_rax],rax
	0x49, 0x8B, 0x4A, 0x10,                   // mov    rcx,[reg64_rcx]
	0x49, 0x8B, 0x52, 0x18,                   // mov    rdx,[reg64_rdx]
	0x4D, 0x8B, 0x42, 0x40,                   // mov    r8,[reg64_r8] 
	0x4D, 0x8B, 0x4A, 0x48,                   // mov    r9,[reg64_r9]
	0x4C, 0x89, 0xD0,                         // mov    rax,r10
	0x0F, 0x28, 0x80, 0x80, 0x00, 0x00, 0x00, // movaps xmm0,[imm256_xmm0]
	0x0F, 0x28, 0x88, 0xA0, 0x00, 0x00, 0x00, // movaps xmm1,[imm256_xmm1]
	0x0F, 0x28, 0x90, 0xC0, 0x00, 0x00, 0x00, // movaps xmm2,[imm256_xmm2]
	0x0F, 0x28, 0x98, 0xE0, 0x00, 0x00, 0x00, // movaps xmm3,[imm256_xmm3]
	0x0F, 0x28, 0xA0, 0x00, 0x01, 0x00, 0x00, // movaps xmm4,[imm256_xmm4]
	0x0F, 0x28, 0xA8, 0x20, 0x01, 0x00, 0x00, // movaps xmm5,[imm256_xmm5]
	0xFF, 0x35, 0x55, 0xFF, 0xFF, 0xFF,       // push   [extra]
	0xFF, 0x25, 0x3F, 0xFF, 0xFF, 0xFF,       // jmp    [fnNew]
	};
};

// A special hook template that loads all integer registers into the context structure,
// then passes a pointer to it to the hooking function as its first parameter.
// This allows modifying any register by accessing them inside the struct.
// Hooking function signature:
// void (*)(HookContext*)
// Includes SIMD registers (and is therefore quite large). 
// Use ContextHook if you only.
struct ContextHookV {
	ContextHookV() {}

	//data:
	HookData hookData{};

	// assembly:
	unsigned char asmRaw[408] = {
	0x50,                                           // push   rax
	0x48, 0x8B, 0x05, 0xD0, 0xFF, 0xFF, 0xFF,       // mov    rax,[context]
	0x8F, 0x00,                                     // pop    [reg64_rax]
	0x48, 0x89, 0x58, 0x08,                         // mov    [reg64_rbx],rbx
	0x48, 0x89, 0x48, 0x10,                         // mov    [reg64_rcx],rcx
	0x48, 0x89, 0x50, 0x18,                         // mov    [reg64_rdx],rdx
	0x48, 0x89, 0x60, 0x20,                         // mov    [reg64_rsp],rsp
	0x48, 0x89, 0x68, 0x28,                         // mov    [reg64_rbp],rbp
	0x48, 0x89, 0x70, 0x30,                         // mov    [reg64_rsi],rsi
	0x48, 0x89, 0x78, 0x38,                         // mov    [reg64_rdi],rdi
	0x4C, 0x89, 0x40, 0x40,                         // mov    [reg64_r8],r8
	0x4C, 0x89, 0x48, 0x48,                         // mov    [reg64_r9],r9
	0x4C, 0x89, 0x50, 0x50,                         // mov    [reg64_r10],r10
	0x4C, 0x89, 0x58, 0x58,                         // mov    [reg64_r11],r11
	0x4C, 0x89, 0x60, 0x60,                         // mov    [reg64_r12],r12
	0x4C, 0x89, 0x68, 0x68,                         // mov    [reg64_r13],r13
	0x4C, 0x89, 0x70, 0x70,                         // mov    [reg64_r14],r14
	0x4C, 0x89, 0x78, 0x78,                         // mov    [reg64_r15],r15
	0x0F, 0x29, 0x80, 0x80, 0x00, 0x00, 0x00,       // movaps [imm256_xmm0],xmm0
	0x0F, 0x29, 0x88, 0xA0, 0x00, 0x00, 0x00,       // movaps [imm256_xmm1],xmm1
	0x0F, 0x29, 0x90, 0xC0, 0x00, 0x00, 0x00,       // movaps [imm256_xmm2],xmm2
	0x0F, 0x29, 0x98, 0xE0, 0x00, 0x00, 0x00,       // movaps [imm256_xmm3],xmm3
	0x0F, 0x29, 0xA0, 0x00, 0x01, 0x00, 0x00,       // movaps [imm256_xmm4],xmm4
	0x0F, 0x29, 0xA8, 0x20, 0x01, 0x00, 0x00,       // movaps [imm256_xmm5],xmm5
	0x0F, 0x29, 0xB0, 0x40, 0x01, 0x00, 0x00,       // movaps [imm256_xmm6],xmm6
	0x0F, 0x29, 0xB8, 0x60, 0x01, 0x00, 0x00,       // movaps [imm256_xmm7],xmm7
	0x44, 0x0F, 0x29, 0x80, 0x80, 0x01, 0x00, 0x00, // movaps [imm256_xmm8],xmm8
	0x44, 0x0F, 0x29, 0x88, 0xA0, 0x01, 0x00, 0x00, // movaps [imm256_xmm9],xmm9
	0x44, 0x0F, 0x29, 0x90, 0xC0, 0x01, 0x00, 0x00, // movaps [imm256_xmm10],xmm10
	0x44, 0x0F, 0x29, 0x98, 0xE0, 0x01, 0x00, 0x00, // movaps [imm256_xmm11],xmm11
	0x44, 0x0F, 0x29, 0xA0, 0x00, 0x02, 0x00, 0x00, // movaps [imm256_xmm12],xmm12
	0x44, 0x0F, 0x29, 0xA8, 0x20, 0x02, 0x00, 0x00, // movaps [imm256_xmm13],xmm13
	0x44, 0x0F, 0x29, 0xB0, 0x40, 0x02, 0x00, 0x00, // movaps [imm256_xmm14],xmm14
	0x44, 0x0F, 0x29, 0xB8, 0x60, 0x02, 0x00, 0x00, // movaps [imm256_xmm15],xmm15
	0x48, 0x89, 0xC1,                               // mov    rcx,rax
	0x48, 0x8D, 0x05, 0x11, 0x00, 0x00, 0x00,       // lea    rax,[new_return]
	0x48, 0x87, 0x04, 0x24,                         // xchg   [old_return],rax
	0x48, 0x87, 0x05, 0x25, 0xFF, 0xFF, 0xFF,       // xchg   [extra],rax
	0xFF, 0x25, 0x0F, 0xFF, 0xFF, 0xFF,             // jmp    [fnNew]
	0x48, 0x8B, 0x05, 0xF8, 0xFE, 0xFF, 0xFF,       // mov    rax,[context]
	0x48, 0x8B, 0x58, 0x08,                         // mov    rbx,[reg64_rbx]
	0x48, 0x8B, 0x48, 0x10,                         // mov    rcx,[reg64_rcx]
	0x48, 0x8B, 0x50, 0x18,                         // mov    rdx,[reg64_rdx]
	0x48, 0x8B, 0x68, 0x28,                         // mov    rbp,[reg64_rbp]
	0x48, 0x8B, 0x70, 0x30,                         // mov    rsi,[reg64_rsi]
	0x48, 0x8B, 0x78, 0x38,                         // mov    rdi,[reg64_rdi]
	0x4C, 0x8B, 0x40, 0x40,                         // mov    r8,[reg64_r8]
	0x4C, 0x8B, 0x48, 0x48,                         // mov    r9,[reg64_r9]
	0x4C, 0x8B, 0x60, 0x60,                         // mov    r12,[reg64_r12]
	0x4C, 0x8B, 0x68, 0x68,                         // mov    r13,[reg64_r13]
	0x4C, 0x8B, 0x70, 0x70,                         // mov    r14,[reg64_r14]
	0x4C, 0x8B, 0x78, 0x78,                         // mov    r15,[reg64_r15]
	0x0F, 0x28, 0x80, 0x80, 0x00, 0x00, 0x00,       // movaps xmm0,[imm256_xmm0]
	0x0F, 0x28, 0x88, 0xA0, 0x00, 0x00, 0x00,       // movaps xmm1,[imm256_xmm1]
	0x0F, 0x28, 0x90, 0xC0, 0x00, 0x00, 0x00,       // movaps xmm2,[imm256_xmm2]
	0x0F, 0x28, 0x98, 0xE0, 0x00, 0x00, 0x00,       // movaps xmm3,[imm256_xmm3]
	0x0F, 0x28, 0xA0, 0x00, 0x01, 0x00, 0x00,       // movaps xmm4,[imm256_xmm4]
	0x0F, 0x28, 0xA8, 0x20, 0x01, 0x00, 0x00,       // movaps xmm5,[imm256_xmm5]
	0x0F, 0x28, 0xB0, 0x40, 0x01, 0x00, 0x00,       // movaps xmm6,[imm256_xmm6]
	0x0F, 0x28, 0xB8, 0x60, 0x01, 0x00, 0x00,       // movaps xmm7,[imm256_xmm7]
	0x44, 0x0F, 0x28, 0x80, 0x80, 0x01, 0x00, 0x00, // movaps xmm8,[imm256_xmm8]
	0x44, 0x0F, 0x28, 0x88, 0xA0, 0x01, 0x00, 0x00, // movaps xmm9,[imm256_xmm9]
	0x44, 0x0F, 0x28, 0x90, 0xC0, 0x01, 0x00, 0x00, // movaps xmm10,[imm256_xmm10]
	0x44, 0x0F, 0x28, 0x98, 0xE0, 0x01, 0x00, 0x00, // movaps xmm11,[imm256_xmm11]
	0x44, 0x0F, 0x28, 0xA0, 0x00, 0x02, 0x00, 0x00, // movaps xmm12,[imm256_xmm12]
	0x44, 0x0F, 0x28, 0xA8, 0x20, 0x02, 0x00, 0x00, // movaps xmm13,[imm256_xmm13]
	0x44, 0x0F, 0x28, 0xB0, 0x40, 0x02, 0x00, 0x00, // movaps xmm14,[imm256_xmm14]
	0x44, 0x0F, 0x28, 0xB8, 0x60, 0x02, 0x00, 0x00, // movaps xmm15,[imm256_xmm15]
	0xFF, 0x35, 0x6A, 0xFE, 0xFF, 0xFF,             // push   [extra]
	0xFF, 0x25, 0x5C, 0xFE, 0xFF, 0xFF,             // jmp    [fnHooked]
	};
};
