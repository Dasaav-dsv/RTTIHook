#include "../VFTHook.h"

/// <summary>
/// Not a good example of a pointer traversal function, it's here just for the sake of the demonstration :P
/// </summary>
template <typename T> inline unsigned char* p(T* base, int offset)
{
    return reinterpret_cast<unsigned char*>(*reinterpret_cast<void**>((reinterpret_cast<unsigned char*>(base) + offset)));
}

/// <summary>
/// An example hook function. Virtual functions are thiscall by definition, so the first argument 
/// will always be a class instance. Since we hook CS::PlayerIns, it is an instance of that class.
/// This example function turns the player character (and other NPCs) upside down.
/// </summary>
/// <param name="PlayerIns"></param>
void exampleHook(void* PlayerIns) 
{
    // this pointer goes through many structs, which are besides the point of this demo, 
    // before reaching the struct we need
    auto base = p(p(p(p(p(p(PlayerIns, 0x190), 0x28), 0x10), 0x30), 0x38), 0x0);

    // the offset to the root bone coordinates from a struct offset
    int offset = *reinterpret_cast<int*>(base + 0x54);
    float* rootPos = reinterpret_cast<float*>(base + offset);

    // raise the bone coordinates by 1.6 units
    rootPos[1] += 1.6f;

    // store quaternion components of the bone's orientation, invert Z
    // (fromsoftware operates in an XZYW coordinate system)
    float qZ = rootPos[5] * -1.0f;
    float qW = rootPos[7];

    // clear quaternion
    for (int i = 0; i < 4; i++) {
        rootPos[4 + i] = 0.0f;
    }

    // write components, -Z to X and W to Y
    rootPos[4] = qZ;
    rootPos[6] = qW;
}

// a static declaration of a hook instance to be used in both placeExampleHook and removeExampleHook
static VFTHook* hook;

/// <summary>
/// This is all that is needed to place a hook.
/// It is also possible to pass a pointer to a PEParser::ProcessInfo struct to RTTIScanner::scan
/// to set custom process details.
/// </summary>
void placeExampleHook()
{
    // create a new scanner instance. Only one instance is supported at a time.
    RTTIScanner* scanner = new RTTIScanner();

    // scan for RTTI. RTTIScanner::scan returns false if something goes wrong, and it's not a
    // bad idea to make sure the scan succeeds before hooking.
    if (scanner->scan()) {
        // create a new hook. Note how this is all that's needed to place it
        hook = new VFTHook("CS::PlayerIns", 20, exampleHook);
    }
}

void removeExampleHook()
{
    // to remove the hook, it is enough to delete the object - it will unhook automatically
    if (!!hook) delete hook;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        placeExampleHook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        removeExampleHook();
        break;
    }
    return TRUE;
}

