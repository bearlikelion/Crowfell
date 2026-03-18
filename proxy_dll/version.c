/*
 * version.dll proxy for Crowfall server emulator
 *
 * Hooks two Deserialize<T> instantiations in GameAssembly.dll:
 *
 *   1. Deserialize<CharacterListResponse>  (RVA 0x011F3930) — struct, trampoline
 *      Replaces the function entirely to construct a valid empty response
 *      using il2cpp APIs, bypassing JsonFx's broken struct deserialization.
 *
 *   2. Shared Deserialize<T> for reference types (RVA 0x011F3B10) — 5-byte patch
 *      Bypasses il2cpp_object_iscast check so the non-generic Deserialize
 *      result is returned directly.  Fixes ScenarioListResponse and ~35 other types.
 *
 * Patching runs lazily from the game's own thread (via proxy function calls)
 * to avoid spawning a background thread that would trigger Boehm GC assertions.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -shared -o version.dll version.c version.def \
 *       -lkernel32 -luser32 -O2 -s
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

/* ── logging (Win32 API only — no CRT stdio) ────────────────────────── */

static HANDLE log_handle = INVALID_HANDLE_VALUE;

static void log_open(void) {
    if (log_handle == INVALID_HANDLE_VALUE) {
        log_handle = CreateFileA("crowfall_proxy.log",
                                 FILE_APPEND_DATA,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 NULL, OPEN_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL, NULL);
    }
}

static void logmsg(const char *fmt, ...) {
    if (log_handle == INVALID_HANDLE_VALUE) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    if (n > 0) {
        buf[n] = '\n';
        DWORD written;
        WriteFile(log_handle, buf, n + 1, &written, NULL);
    }
}

/* ── version.dll forwarding ──────────────────────────────────────────── */

static HMODULE real_version = NULL;

static HMODULE load_real_version(void) {
    if (real_version) return real_version;
    char syspath[MAX_PATH];
    GetSystemDirectoryA(syspath, sizeof(syspath));
    strcat(syspath, "\\version.dll");
    real_version = LoadLibraryA(syspath);
    return real_version;
}

/* Forward declaration — try_apply_patches is called from each proxy */
static void try_apply_patches(void);

#define PROXY(name)                                           \
    typedef void (__stdcall *pfn_##name##_t)(void);           \
    static pfn_##name##_t pfn_##name = NULL;                  \
    void __stdcall proxy_##name(void) {                       \
        try_apply_patches();                                  \
        if (!pfn_##name) {                                    \
            load_real_version();                              \
            pfn_##name = (pfn_##name##_t)                     \
                GetProcAddress(real_version, #name);          \
        }                                                     \
        if (pfn_##name) pfn_##name();                         \
    }

PROXY(GetFileVersionInfoA)
PROXY(GetFileVersionInfoByHandle)
PROXY(GetFileVersionInfoExA)
PROXY(GetFileVersionInfoExW)
PROXY(GetFileVersionInfoSizeA)
PROXY(GetFileVersionInfoSizeExA)
PROXY(GetFileVersionInfoSizeExW)
PROXY(GetFileVersionInfoSizeW)
PROXY(GetFileVersionInfoW)
PROXY(VerFindFileA)
PROXY(VerFindFileW)
PROXY(VerInstallFileA)
PROXY(VerInstallFileW)
PROXY(VerLanguageNameA)
PROXY(VerLanguageNameW)
PROXY(VerQueryValueA)
PROXY(VerQueryValueW)

/* ── memory helpers ──────────────────────────────────────────────────── */

static BOOL safe_write(void *addr, const uint8_t *bytes, size_t len) {
    DWORD old_prot;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old_prot))
        return FALSE;
    memcpy(addr, bytes, len);
    VirtualProtect(addr, len, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return TRUE;
}

static void *alloc_executable(size_t len) {
    return VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

static void write_abs_jump(uint8_t *dst, const void *target) {
    uint64_t addr = (uint64_t)(uintptr_t)target;
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    memcpy(dst + 6, &addr, 8);
}

/* ── il2cpp API ──────────────────────────────────────────────────────── */

typedef void  Il2CppDomain;
typedef void  Il2CppAssembly;
typedef void  Il2CppImage;
typedef void  Il2CppClass;
typedef void  Il2CppObject;
typedef void  Il2CppString;
typedef void  Il2CppMethodInfo;

typedef void  Il2CppArray;

typedef Il2CppDomain*    (*fn_domain_get)(void);
typedef Il2CppAssembly** (*fn_domain_get_assemblies)(Il2CppDomain*, size_t*);
typedef Il2CppImage*     (*fn_assembly_get_image)(Il2CppAssembly*);
typedef const char*      (*fn_image_get_filename)(Il2CppImage*);
typedef Il2CppClass*     (*fn_class_from_name)(Il2CppImage*, const char*, const char*);
typedef Il2CppObject*    (*fn_object_new)(Il2CppClass*);
typedef Il2CppObject*    (*fn_runtime_invoke)(Il2CppMethodInfo*, void*, void**, Il2CppObject**);
typedef Il2CppMethodInfo*(*fn_class_get_method_from_name)(Il2CppClass*, const char*, int);
typedef Il2CppString*    (*fn_string_new)(const char*);
typedef size_t           (*fn_image_get_class_count)(Il2CppImage*);
typedef Il2CppClass*     (*fn_image_get_class)(Il2CppImage*, size_t);
typedef const char*      (*fn_class_get_name)(Il2CppClass*);
typedef const char*      (*fn_class_get_namespace)(Il2CppClass*);
typedef uint16_t*        (*fn_string_chars)(Il2CppString*);
typedef int              (*fn_string_length)(Il2CppString*);
typedef Il2CppArray*     (*fn_array_new)(Il2CppClass*, size_t);
typedef Il2CppClass*     (*fn_class_get_element_class)(Il2CppClass*);
typedef size_t           (*fn_array_length)(Il2CppArray*);

static fn_domain_get                 p_domain_get;
static fn_domain_get_assemblies      p_domain_get_assemblies;
static fn_assembly_get_image         p_assembly_get_image;
static fn_image_get_filename         p_image_get_filename;
static fn_class_from_name            p_class_from_name;
static fn_object_new                 p_object_new;
static fn_runtime_invoke             p_runtime_invoke;
static fn_class_get_method_from_name p_class_get_method_from_name;
static fn_string_new                 p_string_new;
static fn_image_get_class_count      p_image_get_class_count;
static fn_image_get_class            p_image_get_class;
static fn_class_get_name             p_class_get_name;
static fn_class_get_namespace        p_class_get_namespace;
static fn_string_chars               p_string_chars;
static fn_string_length              p_string_length;
static fn_array_new                  p_array_new;
static fn_class_get_element_class    p_class_get_element_class;
static fn_array_length               p_array_length;

static HMODULE ga_module = NULL;
static uint8_t *ga_base = NULL;

static int load_il2cpp_api(void) {
    #define LOAD(name) do { \
        p_##name = (fn_##name)(void*)GetProcAddress(ga_module, "il2cpp_" #name); \
        if (!p_##name) { logmsg("ERROR: il2cpp_%s not found", #name); return 0; } \
    } while(0)

    LOAD(domain_get);
    LOAD(domain_get_assemblies);
    LOAD(assembly_get_image);
    LOAD(image_get_filename);
    LOAD(class_from_name);
    LOAD(object_new);
    LOAD(runtime_invoke);
    LOAD(class_get_method_from_name);
    LOAD(string_new);
    LOAD(image_get_class_count);
    LOAD(image_get_class);
    LOAD(class_get_name);
    LOAD(class_get_namespace);
    LOAD(string_chars);
    LOAD(string_length);
    LOAD(array_new);
    LOAD(class_get_element_class);
    LOAD(array_length);
    #undef LOAD
    return 1;
}

/* ── type resolution ─────────────────────────────────────────────────── */

static Il2CppClass *klass_CharacterListResponse = NULL;
static Il2CppClass *klass_CharList = NULL;
static Il2CppClass *klass_CharacterEntry = NULL;
static Il2CppClass *klass_StringID = NULL;
static Il2CppClass *klass_PhysicsConnectionRequest = NULL;
static Il2CppClass *klass_MemoryStream = NULL;
static Il2CppClass *klass_BinaryWriter = NULL;
static Il2CppMethodInfo *method_StringID_MakeStringID = NULL;
static Il2CppMethodInfo *method_PhysicsConnectionRequest_ctor = NULL;
static Il2CppMethodInfo *method_PhysicsConnectionRequest_WriteMessage = NULL;
static Il2CppMethodInfo *method_MemoryStream_ctor = NULL;
static Il2CppMethodInfo *method_MemoryStream_ToArray = NULL;
static Il2CppMethodInfo *method_BinaryWriter_ctor = NULL;
static Il2CppMethodInfo *method_BinaryWriter_Flush = NULL;
static int logged_string_ids = 0;
static int logged_request_payload = 0;
static int logged_loadingworld_request = 0;
static int logged_loadingworld_auth = 0;
static int logged_loadingworld_worldready = 0;
static int logged_ingame_enteredzone = 0;
static int logged_ingame_physdisc = 0;
static int logged_ingame_zonetransfer = 0;
static int logged_ingame_playerleft = 0;
static int logged_ingame_transitionin = 0;
static int logged_view_prep = 0;
static int logged_view_initdock = 0;
static int logged_basicheader_read = 0;
static int logged_scene_load = 0;
static int logged_clientloadscene = 0;

#define RVA_LOADINGWORLD_ONPHYSICSREQUEST 0x32C7430
typedef void (__attribute__((ms_abi)) *fn_loadingworld_onphysicsrequest_t)(void *self, void *request);
static fn_loadingworld_onphysicsrequest_t original_loadingworld_onphysicsrequest = NULL;

#define RVA_LOADINGWORLD_ONPHYSACTIONCONFIRMATION 0x32C7220
typedef void (__attribute__((ms_abi)) *fn_loadingworld_onphysauth_t)(void *self, void *msg);
static fn_loadingworld_onphysauth_t original_loadingworld_onphysauth = NULL;

#define RVA_LOADINGWORLD_ONWORLDREADY 0x32C86A0
typedef void (__attribute__((ms_abi)) *fn_loadingworld_onworldready_t)(void *self, int value);
static fn_loadingworld_onworldready_t original_loadingworld_onworldready = NULL;

#define RVA_INGAME_ONENTEREDZONEANDLOADINGSCREENHIDDEN 0x32C5260
typedef void (__attribute__((ms_abi)) *fn_ingame_onenteredzone_t)(void *self, int notifications);
static fn_ingame_onenteredzone_t original_ingame_onenteredzone = NULL;

#define RVA_INGAME_ONPLAYERLEFTPHYSICS 0x32C5650
typedef void (__attribute__((ms_abi)) *fn_ingame_onplayerleft_t)(void *self, void *msg);
static fn_ingame_onplayerleft_t original_ingame_onplayerleft = NULL;

#define RVA_INGAME_ONPHYSICSDISCONNECT 0x32C52C0
typedef void (__attribute__((ms_abi)) *fn_ingame_onphysicsdisconnect_t)(void *self);
static fn_ingame_onphysicsdisconnect_t original_ingame_onphysicsdisconnect = NULL;

#define RVA_INGAME_ONZONETRANSFERBEGIN 0x32C62B0
typedef void (__attribute__((ms_abi)) *fn_ingame_onzonetransferbegin_t)(void *self, void *msg);
static fn_ingame_onzonetransferbegin_t original_ingame_onzonetransferbegin = NULL;

#define RVA_INGAME_ONTRANSITIONIN 0x32C5810
typedef void (__attribute__((ms_abi)) *fn_ingame_ontransitionin_t)(void *self, void *prevState);
static fn_ingame_ontransitionin_t original_ingame_ontransitionin = NULL;

#define RVA_VIEWMANAGER_PREPGAMEWINDOWS 0x5183D0
typedef void (__attribute__((ms_abi)) *fn_viewmanager_prepgamewindows_t)(void *self);
static fn_viewmanager_prepgamewindows_t original_viewmanager_prepgamewindows = NULL;

#define RVA_VIEWMANAGER_INITIALIZEDOCKANDFLOATINGWINDOWS 0x50F810
typedef void (__attribute__((ms_abi)) *fn_viewmanager_initdock_t)(void *self, void *prefab);
static fn_viewmanager_initdock_t original_viewmanager_initdock = NULL;

#define RVA_ANIMDESTRUCTIBLE_TICK 0xAC63C0

#define RVA_BASICHEADER_READ 0x10765D0
typedef int (__attribute__((ms_abi)) *fn_basicheader_read_t)(void *self, Il2CppArray *sourceBuffer, int offset);
static fn_basicheader_read_t original_basicheader_read = NULL;

#define RVA_SCENE_LOAD_WRAPPER 0x1B765F0
typedef void *(__attribute__((ms_abi)) *fn_scene_load_wrapper_t)(Il2CppString *sceneName, int mode, int mustCompleteNextFrame);
static fn_scene_load_wrapper_t original_scene_load_wrapper = NULL;

#define RVA_CLIENTLOADSCENE_MOVENEXT 0x32FD8F0
typedef int (__attribute__((ms_abi)) *fn_clientloadscene_movenext_t)(void *self);
static fn_clientloadscene_movenext_t original_clientloadscene_movenext = NULL;

static char *il2cpp_string_to_utf8(Il2CppString *str, int *out_len);

static int resolve_types(void) {
    Il2CppDomain *domain = p_domain_get();
    if (!domain) return 0;

    size_t asm_count = 0;
    Il2CppAssembly **assemblies = p_domain_get_assemblies(domain, &asm_count);
    if (!assemblies || asm_count == 0) return 0;

    Il2CppImage *target_img = NULL;

    for (size_t a = 0; a < asm_count; a++) {
        Il2CppImage *img = p_assembly_get_image(assemblies[a]);
        if (!img) continue;
        Il2CppClass *cls = p_class_from_name(img, "", "CharacterListResponse");
        if (cls) {
            klass_CharacterListResponse = cls;
            target_img = img;
            logmsg("Found CharacterListResponse in %s", p_image_get_filename(img));
            break;
        }
    }

    if (!target_img) {
        logmsg("ERROR: CharacterListResponse not found in any assembly");
        return 0;
    }

    /* Find CharacterList (nested in PlayerManager, extends List<CharacterEntry>) */
    size_t cc = p_image_get_class_count(target_img);
    for (size_t i = 0; i < cc; i++) {
        Il2CppClass *c = p_image_get_class(target_img, i);
        if (!c) continue;
        const char *n = p_class_get_name(c);
        if (n && strcmp(n, "CharacterList") == 0) {
            klass_CharList = c;
            logmsg("Found CharacterList class: %p (ns=%s)",
                   c, p_class_get_namespace(c));
            break;
        }
    }

    if (!klass_CharList) {
        logmsg("WARNING: CharacterList not found — empty list will be null");
    }

    /* Find CharacterEntry class — may be in a different assembly than
       CharacterListResponse, so search all assemblies. */
    for (size_t a = 0; a < asm_count && !klass_CharacterEntry; a++) {
        Il2CppImage *img = p_assembly_get_image(assemblies[a]);
        if (!img) continue;
        klass_CharacterEntry = p_class_from_name(img,
            "CrowfallCommonUtilities", "CharacterEntry");
        if (klass_CharacterEntry) {
            logmsg("Found CharacterEntry in %s: %p",
                   p_image_get_filename(img), klass_CharacterEntry);
        }
    }
    if (!klass_CharacterEntry) {
        logmsg("WARNING: CharacterEntry not found — characters won't populate");
    }

    for (size_t a = 0; a < asm_count && !klass_StringID; a++) {
        Il2CppImage *img = p_assembly_get_image(assemblies[a]);
        if (!img) continue;
        klass_StringID = p_class_from_name(img, "CrowfallCommonUtilities.Utils", "StringID");
        if (klass_StringID) {
            logmsg("Found StringID in %s: %p",
                   p_image_get_filename(img), klass_StringID);
        }
    }
    if (!klass_StringID) {
        logmsg("WARNING: StringID not found");
    } else {
        method_StringID_MakeStringID =
            p_class_get_method_from_name(klass_StringID, "MakeStringID", 1);
        if (!method_StringID_MakeStringID) {
            logmsg("WARNING: StringID.MakeStringID(string) not found");
        } else {
            logmsg("Found StringID.MakeStringID: %p", method_StringID_MakeStringID);
        }
    }

    for (size_t a = 0; a < asm_count && !klass_PhysicsConnectionRequest; a++) {
        Il2CppImage *img = p_assembly_get_image(assemblies[a]);
        if (!img) continue;
        klass_PhysicsConnectionRequest =
            p_class_from_name(img, "NewMessages", "PhysicsConnectionRequest");
        if (klass_PhysicsConnectionRequest) {
            logmsg("Found PhysicsConnectionRequest in %s: %p",
                   p_image_get_filename(img), klass_PhysicsConnectionRequest);
        }
    }
    if (klass_PhysicsConnectionRequest) {
        method_PhysicsConnectionRequest_ctor =
            p_class_get_method_from_name(klass_PhysicsConnectionRequest, ".ctor", 0);
        method_PhysicsConnectionRequest_WriteMessage =
            p_class_get_method_from_name(klass_PhysicsConnectionRequest, "WriteMessage", 2);
    }

    for (size_t a = 0; a < asm_count && (!klass_MemoryStream || !klass_BinaryWriter); a++) {
        Il2CppImage *img = p_assembly_get_image(assemblies[a]);
        if (!img) continue;
        if (!klass_MemoryStream) {
            klass_MemoryStream = p_class_from_name(img, "System.IO", "MemoryStream");
            if (klass_MemoryStream) {
                logmsg("Found MemoryStream in %s: %p",
                       p_image_get_filename(img), klass_MemoryStream);
            }
        }
        if (!klass_BinaryWriter) {
            klass_BinaryWriter = p_class_from_name(img, "System.IO", "BinaryWriter");
            if (klass_BinaryWriter) {
                logmsg("Found BinaryWriter in %s: %p",
                       p_image_get_filename(img), klass_BinaryWriter);
            }
        }
    }
    if (klass_MemoryStream) {
        method_MemoryStream_ctor = p_class_get_method_from_name(klass_MemoryStream, ".ctor", 0);
        method_MemoryStream_ToArray = p_class_get_method_from_name(klass_MemoryStream, "ToArray", 0);
    }
    if (klass_BinaryWriter) {
        method_BinaryWriter_ctor = p_class_get_method_from_name(klass_BinaryWriter, ".ctor", 1);
        method_BinaryWriter_Flush = p_class_get_method_from_name(klass_BinaryWriter, "Flush", 0);
    }

    return 1;
}

static void log_runtime_string_ids(void) {
    if (logged_string_ids) return;
    if (!method_StringID_MakeStringID || !p_string_new || !p_runtime_invoke) return;

    static const char *names[] = {
        "PhysicsConnectionRequest",
        "PhysicsConnectionResponse",
        "PhysicsAuthenticationConfirmation",
        "PhysicsCloseLoadScreenMessage",
        "PhysicsPingMsg",
        "PhysicsPingReplyMsg",
    };

    logged_string_ids = 1;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        Il2CppString *name = p_string_new(names[i]);
        void *args[1];
        Il2CppObject *exc = NULL;
        int value = 0;
        args[0] = name;
        Il2CppObject *ret = p_runtime_invoke(method_StringID_MakeStringID, NULL, args, &exc);
        if (exc) {
            logmsg("StringID.MakeStringID(%s) threw exception %p", names[i], exc);
            continue;
        }
        if (!ret) {
            logmsg("StringID.MakeStringID(%s) returned null", names[i]);
            continue;
        }
        value = *(int *)((uint8_t *)ret + sizeof(void *) * 2);
        logmsg("StringID.MakeStringID(%s) = %d (0x%08X)",
               names[i], value, (unsigned int)value);
    }
}

static void log_request_payload_bytes(void) {
    if (logged_request_payload) return;
    if (!klass_PhysicsConnectionRequest || !klass_MemoryStream || !klass_BinaryWriter) return;
    if (!method_PhysicsConnectionRequest_ctor || !method_PhysicsConnectionRequest_WriteMessage) return;
    if (!method_MemoryStream_ctor || !method_MemoryStream_ToArray || !method_BinaryWriter_ctor) return;

    logged_request_payload = 1;

    Il2CppObject *exc = NULL;
    Il2CppObject *request = p_object_new(klass_PhysicsConnectionRequest);
    Il2CppObject *ms = p_object_new(klass_MemoryStream);
    Il2CppObject *bw = p_object_new(klass_BinaryWriter);
    if (!request || !ms || !bw) {
        logmsg("Unable to allocate request serialization objects");
        return;
    }

    p_runtime_invoke(method_PhysicsConnectionRequest_ctor, request, NULL, &exc);
    if (exc) { logmsg("PhysicsConnectionRequest ctor threw %p", exc); return; }
    p_runtime_invoke(method_MemoryStream_ctor, ms, NULL, &exc);
    if (exc) { logmsg("MemoryStream ctor threw %p", exc); return; }

    {
        void *args[1];
        args[0] = ms;
        exc = NULL;
        p_runtime_invoke(method_BinaryWriter_ctor, bw, args, &exc);
        if (exc) { logmsg("BinaryWriter ctor threw %p", exc); return; }
    }

    {
        void *args[2];
        args[0] = ms;
        args[1] = bw;
        exc = NULL;
        p_runtime_invoke(method_PhysicsConnectionRequest_WriteMessage, request, args, &exc);
        if (exc) { logmsg("PhysicsConnectionRequest.WriteMessage threw %p", exc); return; }
    }

    if (method_BinaryWriter_Flush) {
        exc = NULL;
        p_runtime_invoke(method_BinaryWriter_Flush, bw, NULL, &exc);
        if (exc) { logmsg("BinaryWriter.Flush threw %p", exc); return; }
    }

    exc = NULL;
    Il2CppArray *bytes = (Il2CppArray *)p_runtime_invoke(method_MemoryStream_ToArray, ms, NULL, &exc);
    if (exc) { logmsg("MemoryStream.ToArray threw %p", exc); return; }
    if (!bytes) { logmsg("MemoryStream.ToArray returned null"); return; }

    {
        size_t len = p_array_length(bytes);
        uint8_t *data = (uint8_t *)bytes + 0x20;
        char line[256];
        logmsg("PhysicsConnectionRequest payload from client runtime (%u bytes):", (unsigned int)len);
        for (size_t i = 0; i < len; i += 16) {
            int pos = 0;
            pos += wsprintfA(line + pos, "  %04X:", (unsigned int)i);
            for (size_t j = i; j < len && j < i + 16; j++) {
                pos += wsprintfA(line + pos, " %02X", data[j]);
            }
            logmsg("%s", line);
        }
    }
}

static void __attribute__((ms_abi))
hook_loadingworld_onphysicsrequest(void *self, void *request) {
    if (!logged_loadingworld_request) {
        logged_loadingworld_request = 1;
        logmsg("GameStateLoadingWorld.OnPhysicsConnectionRequest entered self=%p request=%p",
               self, request);
    } else {
        logmsg("GameStateLoadingWorld.OnPhysicsConnectionRequest entered self=%p request=%p",
               self, request);
    }
    if (original_loadingworld_onphysicsrequest) {
        original_loadingworld_onphysicsrequest(self, request);
    }
}

static void __attribute__((ms_abi))
hook_loadingworld_onphysauth(void *self, void *msg) {
    Il2CppString *session_guid = msg ? *(Il2CppString **)((uint8_t *)msg + 0x78) : NULL;
    int len = 0;
    char *guid = il2cpp_string_to_utf8(session_guid, &len);
    char *zone = self ? il2cpp_string_to_utf8(*(Il2CppString **)((uint8_t *)self + 0x58), &len) : NULL;

    if (!logged_loadingworld_auth) {
        logged_loadingworld_auth = 1;
    }
    logmsg("GameStateLoadingWorld.OnPhysicsAuthenticationConfirmation self=%p msg=%p session=%s zone=%s context=%d registeredDisconnect=%d",
           self, msg,
           guid ? guid : "<null>",
           zone ? zone : "<null>",
           self ? *(int *)((uint8_t *)self + 0x60) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x64) : -1);

    if (original_loadingworld_onphysauth) {
        original_loadingworld_onphysauth(self, msg);
    }

    if (guid) HeapFree(GetProcessHeap(), 0, guid);
    if (zone) HeapFree(GetProcessHeap(), 0, zone);
}

static void __attribute__((ms_abi))
hook_loadingworld_onworldready(void *self, int value) {
    if (!logged_loadingworld_worldready) {
        logged_loadingworld_worldready = 1;
    }
    logmsg("GameStateLoadingWorld.OnWorldReady self=%p value=%d zone=%p context=%d registeredDisconnect=%d",
           self, value,
           self ? *(void **)((uint8_t *)self + 0x58) : NULL,
           self ? *(int *)((uint8_t *)self + 0x60) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x64) : -1);

    if (original_loadingworld_onworldready) {
        original_loadingworld_onworldready(self, value);
    }
}

static void __attribute__((ms_abi))
hook_ingame_onenteredzone(void *self, int notifications) {
    logged_ingame_enteredzone = 1;
    logmsg("GameStateInGame.OnEnteredZoneAndLoadingScreenHidden self=%p notifications=%d enteredZone=%d isLoggingOut=%d",
           self, notifications,
           self ? *(uint8_t *)((uint8_t *)self + 0x52) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x60) : -1);
    if (original_ingame_onenteredzone) {
        original_ingame_onenteredzone(self, notifications);
    }
}

static void __attribute__((ms_abi))
hook_ingame_onphysicsdisconnect(void *self) {
    logged_ingame_physdisc = 1;
    logmsg("GameStateInGame.OnPhysicsDisconnect self=%p enteredZone=%d isLoggingOut=%d inRuneGateQueue=%d",
           self,
           self ? *(uint8_t *)((uint8_t *)self + 0x52) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x60) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x61) : -1);
    if (original_ingame_onphysicsdisconnect) {
        original_ingame_onphysicsdisconnect(self);
    }
}

static void __attribute__((ms_abi))
hook_ingame_onplayerleft(void *self, void *msg) {
    logged_ingame_playerleft = 1;
    logmsg("GameStateInGame.OnPlayerLeftPhysics self=%p msg=%p", self, msg);
    if (original_ingame_onplayerleft) {
        original_ingame_onplayerleft(self, msg);
    }
}

static void __attribute__((ms_abi))
hook_ingame_onzonetransferbegin(void *self, void *msg) {
    logged_ingame_zonetransfer = 1;
    logmsg("GameStateInGame.OnZoneTransferBegin self=%p msg=%p", self, msg);
    if (original_ingame_onzonetransferbegin) {
        original_ingame_onzonetransferbegin(self, msg);
    }
}

static void __attribute__((ms_abi))
hook_ingame_ontransitionin(void *self, void *prevState) {
    logged_ingame_transitionin = 1;
    logmsg("GameStateInGame.OnTransitionIn enter self=%p prev=%p disconnectTime=%f warnTime=%f usesAfk=%d timeoutWarn=%d enteredZone=%d isLoggingOut=%d",
           self, prevState,
           self ? *(float *)((uint8_t *)self + 0x48) : 0.0f,
           self ? *(float *)((uint8_t *)self + 0x4C) : 0.0f,
           self ? *(uint8_t *)((uint8_t *)self + 0x50) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x51) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x52) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x60) : -1);
    if (original_ingame_ontransitionin) {
        original_ingame_ontransitionin(self, prevState);
    }
    /* Without a real entity spawn from the zone server, _enteredZone never becomes 1.
     * Force it here so PhysicsCloseLoadScreenMessage's handler will call
     * OnEnteredZoneAndLoadingScreenHidden and close the loading screen. */
    if (self) {
        *(uint8_t *)((uint8_t *)self + 0x52) = 1;
        logmsg("GameStateInGame.OnTransitionIn forced _enteredZone=1");
    }
    logmsg("GameStateInGame.OnTransitionIn exit self=%p enteredZone=%d isLoggingOut=%d inRuneGateQueue=%d",
           self,
           self ? *(uint8_t *)((uint8_t *)self + 0x52) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x60) : -1,
           self ? *(uint8_t *)((uint8_t *)self + 0x61) : -1);
}

static void __attribute__((ms_abi))
hook_viewmanager_prepgamewindows(void *self) {
    logged_view_prep = 1;
    logmsg("ViewManager.PrepGameWindows enter self=%p floatingMaster=%p dockRoot=%p",
           self,
           self ? *(void **)((uint8_t *)self + 0x180) : NULL,
           self ? *(void **)((uint8_t *)self + 0x3F0) : NULL);
    if (original_viewmanager_prepgamewindows) {
        original_viewmanager_prepgamewindows(self);
    }
    logmsg("ViewManager.PrepGameWindows exit self=%p floatingMasterAfter=%p",
           self, self ? *(void **)((uint8_t *)self + 0x428) : NULL);
}

static void __attribute__((ms_abi))
hook_viewmanager_initdock(void *self, void *prefab) {
    logged_view_initdock = 1;
    logmsg("ViewManager.InitializeDockAndFloatingWindows enter self=%p prefab=%p floatingMaster=%p dockRoot=%p",
           self, prefab,
           self ? *(void **)((uint8_t *)self + 0x428) : NULL,
           self ? *(void **)((uint8_t *)self + 0x3F0) : NULL);
    if (original_viewmanager_initdock) {
        original_viewmanager_initdock(self, prefab);
    }
    logmsg("ViewManager.InitializeDockAndFloatingWindows exit self=%p floatingMaster=%p",
           self, self ? *(void **)((uint8_t *)self + 0x428) : NULL);
}

static int __attribute__((ms_abi))
hook_basicheader_read(void *self, Il2CppArray *sourceBuffer, int offset) {
    int result = 0;

    if (original_basicheader_read) {
        result = original_basicheader_read(self, sourceBuffer, offset);
    }

    if (result && self) {
        int message_length = *(int *)((uint8_t *)self + 0x10);
        int message_type = *(int *)((uint8_t *)self + 0x14);
        int message_number = *(int *)((uint8_t *)self + 0x18);
        uint8_t byte1 = *(uint8_t *)((uint8_t *)self + 0x1C);
        uint8_t byte2 = *(uint8_t *)((uint8_t *)self + 0x1D);

        logmsg("BasicHeader.Read success offset=%d b1=%02X b2=%02X len=%d type=%d (0x%08X) num=%d",
               offset, byte1, byte2, message_length, message_type, (unsigned int)message_type, message_number);

        if (sourceBuffer && p_array_length) {
            size_t len = p_array_length(sourceBuffer);
            if ((size_t)offset < len) {
                uint8_t *data = (uint8_t *)sourceBuffer + 0x20 + offset;
                size_t remain = len - (size_t)offset;
                size_t count = remain < 16 ? remain : 16;
                char line[256];
                int pos = 0;
                pos += wsprintfA(line + pos, "  source:");
                for (size_t i = 0; i < count; i++) {
                    pos += wsprintfA(line + pos, " %02X", data[i]);
                }
                logmsg("%s", line);
            }
        }
        logged_basicheader_read = 1;
    }

    return result;
}

static void * __attribute__((ms_abi))
hook_scene_load_wrapper(Il2CppString *sceneName, int mode, int mustCompleteNextFrame) {
    void *result;
    int len = 0;
    char *name = il2cpp_string_to_utf8(sceneName, &len);

    if (name && len > 0) {
        logmsg("Scene load request name=%s mode=%d mustCompleteNextFrame=%d",
               name, mode, mustCompleteNextFrame);
    } else {
        logmsg("Scene load request name=<null> mode=%d mustCompleteNextFrame=%d",
               mode, mustCompleteNextFrame);
    }
    logged_scene_load = 1;

    result = original_scene_load_wrapper ? original_scene_load_wrapper(sceneName, mode, mustCompleteNextFrame) : NULL;

    if (name && len > 0) {
        logmsg("Scene load result name=%s async=%p", name, result);
        if (lstrcmpiA(name, "KingdomMainClient") == 0 && result) {
            uint8_t *raw = (uint8_t *)result;
            logmsg("  KingdomMainClient AsyncOperation raw=%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                   raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                   raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
        }
    } else {
        logmsg("Scene load result name=<null> async=%p", result);
    }

    if (name) HeapFree(GetProcessHeap(), 0, name);
    return result;
}

static int __attribute__((ms_abi))
hook_clientloadscene_movenext(void *self) {
    int result;
    int state = self ? *(int *)((uint8_t *)self + 0x10) : -999;
    Il2CppString *zone_scene = self ? *(Il2CppString **)((uint8_t *)self + 0x20) : NULL;
    void *zone_manager = self ? *(void **)((uint8_t *)self + 0x28) : NULL;
    void *callback = self ? *(void **)((uint8_t *)self + 0x30) : NULL;
    void *streaming_zone = self ? *(void **)((uint8_t *)self + 0x38) : NULL;
    void *world_transform = self ? *(void **)((uint8_t *)self + 0x40) : NULL;
    void *async_load = self ? *(void **)((uint8_t *)self + 0x48) : NULL;
    void *async_unload = self ? *(void **)((uint8_t *)self + 0x50) : NULL;
    int zone_len = 0;
    int addon_len = 0;
    int main_len = 0;
    int current_len = 0;
    char *zone_name = il2cpp_string_to_utf8(zone_scene, &zone_len);
    char *addon_name = NULL;
    char *main_zone_name = NULL;
    char *current_scene_name = NULL;

    if (streaming_zone) {
        addon_name = il2cpp_string_to_utf8(*(Il2CppString **)((uint8_t *)streaming_zone + 0x18), &addon_len);
    }
    if (zone_manager) {
        main_zone_name = il2cpp_string_to_utf8(*(Il2CppString **)((uint8_t *)zone_manager + 0x18), &main_len);
        current_scene_name = il2cpp_string_to_utf8(*(Il2CppString **)((uint8_t *)zone_manager + 0x38), &current_len);
    }

    logmsg("ClientLoadScene.MoveNext state=%d zone=%s manager=%p callback=%p stream=%p world=%p aload=%p aunload=%p",
           state,
           (zone_name && zone_len > 0) ? zone_name : "<null>",
           zone_manager, callback, streaming_zone, world_transform, async_load, async_unload);

    if (zone_manager) {
        logmsg("  ZoneManager main=%s current=%s flags loaded=%d addons=%d error=%d sceneLoaded=%d clientObjects=%p loadingOp=%p",
               (main_zone_name && main_len > 0) ? main_zone_name : "<null>",
               (current_scene_name && current_len > 0) ? current_scene_name : "<null>",
               *(uint8_t *)((uint8_t *)zone_manager + 0x30),
               *(uint8_t *)((uint8_t *)zone_manager + 0x31),
               *(uint8_t *)((uint8_t *)zone_manager + 0x32),
               *(uint8_t *)((uint8_t *)zone_manager + 0x40),
               *(void **)((uint8_t *)zone_manager + 0x48),
               *(void **)((uint8_t *)zone_manager + 0x50));
    }

    if (streaming_zone) {
        logmsg("  StreamingZone addon=%s", (addon_name && addon_len > 0) ? addon_name : "<null>");
    }

    if (zone_name) HeapFree(GetProcessHeap(), 0, zone_name);
    if (addon_name) HeapFree(GetProcessHeap(), 0, addon_name);
    if (main_zone_name) HeapFree(GetProcessHeap(), 0, main_zone_name);
    if (current_scene_name) HeapFree(GetProcessHeap(), 0, current_scene_name);

    logged_clientloadscene = 1;
    result = original_clientloadscene_movenext ? original_clientloadscene_movenext(self) : 0;
    logmsg("ClientLoadScene.MoveNext result=%d next_state=%d", result, self ? *(int *)((uint8_t *)self + 0x10) : -999);
    return result;
}

/* ── Hook 1: Deserialize<CharacterListResponse> trampoline ───────────── */
/*
 * RVA 0x011F3930 — struct return type, hidden output pointer.
 *
 * Signature (x64 Windows ABI):
 *   CharacterListResponse* fn(CharacterListResponse *out, Il2CppString *json, void *minfo)
 *   RCX=out  RDX=json  R8=minfo  → RAX=out
 */

#define RVA_DESERIALIZE_STRUCT  0x011F3930

typedef struct {
    uint8_t  success;
    uint8_t  _pad[7];
    void    *message;       /* Il2CppString* */
    void    *characters;    /* Il2CppObject* (List<CharacterEntry>) */
} CharacterListResponse;

/* ── Minimal JSON helpers for the charlist hook ──────────────────────── */

/* Log the full JSON to the log file (bypasses logmsg's 1024-byte limit). */
static void log_full_json(const char *buf, int len) {
    if (log_handle == INVALID_HANDLE_VALUE) return;
    const char prefix[] = "  JSON: ";
    const char newline[] = "\n";
    DWORD written;
    WriteFile(log_handle, prefix, sizeof(prefix) - 1, &written, NULL);
    WriteFile(log_handle, buf, len, &written, NULL);
    WriteFile(log_handle, newline, 1, &written, NULL);
}

/* Convert Il2CppString to a heap-allocated UTF-8 C string.  Caller must HeapFree. */
static char *il2cpp_string_to_utf8(Il2CppString *str, int *out_len) {
    if (!str) { *out_len = 0; return NULL; }
    int len = p_string_length(str);
    uint16_t *chars = p_string_chars(str);
    if (!chars || len <= 0) { *out_len = 0; return NULL; }
    char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, len + 1);
    if (!buf) { *out_len = 0; return NULL; }
    for (int i = 0; i < len; i++) buf[i] = (char)(chars[i] & 0xFF);
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

/* Find the next JSON object '{...}' in src starting at *pos.
 * Returns a pointer to the '{' and sets *end to one past '}'.
 * Returns NULL if no object found. */
static char *json_next_object(char *src, int len, int *pos, int *end) {
    int depth = 0;
    int start = -1;
    for (int i = *pos; i < len; i++) {
        if (src[i] == '{') {
            if (depth == 0) start = i;
            depth++;
        } else if (src[i] == '}') {
            depth--;
            if (depth == 0 && start >= 0) {
                *pos = start;
                *end = i + 1;
                return src + start;
            }
        }
    }
    return NULL;
}

/* Extract a JSON string value for a given key from an object.
 * Writes into out_buf (max out_buf_size-1 chars + NUL).
 * Returns 1 on success, 0 if not found. */
static int json_get_string(const char *obj, int obj_len,
                           const char *key, char *out_buf, int out_buf_size) {
    /* Build search pattern: "key" */
    char pattern[128];
    int klen = lstrlenA(key);
    if (klen + 3 > (int)sizeof(pattern)) return 0;
    pattern[0] = '"';
    memcpy(pattern + 1, key, klen);
    pattern[klen + 1] = '"';
    pattern[klen + 2] = '\0';

    /* Find key in object */
    const char *p = obj;
    const char *obj_end = obj + obj_len;
    while (p < obj_end) {
        const char *found = strstr(p, pattern);
        if (!found || found >= obj_end) return 0;
        /* Skip to colon then to opening quote of value */
        const char *c = found + klen + 2;
        while (c < obj_end && (*c == ' ' || *c == ':' || *c == '\t')) c++;
        if (c < obj_end && *c == '"') {
            c++; /* skip opening quote */
            int i = 0;
            while (c < obj_end && *c != '"' && i < out_buf_size - 1) {
                out_buf[i++] = *c++;
            }
            out_buf[i] = '\0';
            return 1;
        }
        p = found + 1; /* try next occurrence */
    }
    return 0;
}

/* Extract a JSON integer value for a given key. Returns 0 if not found. */
static int json_get_int(const char *obj, int obj_len, const char *key, int *out) {
    char pattern[128];
    int klen = lstrlenA(key);
    if (klen + 3 > (int)sizeof(pattern)) return 0;
    pattern[0] = '"';
    memcpy(pattern + 1, key, klen);
    pattern[klen + 1] = '"';
    pattern[klen + 2] = '\0';

    const char *p = obj;
    const char *obj_end = obj + obj_len;
    while (p < obj_end) {
        const char *found = strstr(p, pattern);
        if (!found || found >= obj_end) return 0;
        const char *c = found + klen + 2;
        while (c < obj_end && (*c == ' ' || *c == ':' || *c == '\t')) c++;
        if (c < obj_end && (*c == '-' || (*c >= '0' && *c <= '9'))) {
            int val = 0, sign = 1;
            if (*c == '-') { sign = -1; c++; }
            while (c < obj_end && *c >= '0' && *c <= '9') {
                val = val * 10 + (*c - '0');
                c++;
            }
            *out = val * sign;
            return 1;
        }
        p = found + 1;
    }
    return 0;
}

/* ── CharacterEntry field offsets (from dump.cs) ─────────────────────── */
/*
 *  CharacterEntry is a class (reference type), so field offsets include
 *  the Il2CppObject header (16 bytes: klass ptr + monitor ptr).
 *
 *  name              string   0x10
 *  object_guid       string   0x18
 *  clone_guid        string   0x20
 *  scenario_type     string   0x28
 *  scenario_uuid     string   0x30
 *  scenario_name     string   0x38
 *  scenario_archived bool     0x40
 *  scenario_locking  bool     0x41
 *  faction           int      0x44
 *  archetype_name    string   0x48
 *  race_name         string   0x50
 *  gender_id         int      0x58
 *  customization_tints  List  0x60
 *  customization_features List 0x68
 *  level             int      0x70
 *  equipment_items   List     0x78
 *  inventory_items   List     0x80
 *  vessel_template_id int     0x88
 *  vessel_template_name string 0x90
 *  vessel_quality    int/enum 0x98
 */

#define CE_OFF_NAME           0x10
#define CE_OFF_OBJECT_GUID    0x18
#define CE_OFF_CLONE_GUID     0x20
#define CE_OFF_SCENARIO_TYPE  0x28
#define CE_OFF_SCENARIO_UUID  0x30
#define CE_OFF_SCENARIO_NAME  0x38
#define CE_OFF_ARCHETYPE_NAME 0x48
#define CE_OFF_RACE_NAME      0x50
#define CE_OFF_GENDER_ID      0x58
#define CE_OFF_LEVEL          0x70
#define CE_OFF_VESSEL_TEMPLATE_NAME 0x90
#define CE_OFF_VESSEL_QUALITY 0x98

static void ce_set_string(Il2CppObject *obj, int offset, const char *val) {
    *(void **)((uint8_t *)obj + offset) = p_string_new(val);
}

static void ce_set_int(Il2CppObject *obj, int offset, int val) {
    *(int *)((uint8_t *)obj + offset) = val;
}

/* Build a CharacterEntry from a JSON object substring. */
static Il2CppObject *build_character_entry(const char *obj, int obj_len) {
    if (!klass_CharacterEntry) return NULL;

    Il2CppObject *entry = p_object_new(klass_CharacterEntry);
    if (!entry) { logmsg("  object_new(CharacterEntry) failed"); return NULL; }

    char buf[256];

    /* String fields — set empty defaults for all string fields first */
    ce_set_string(entry, CE_OFF_NAME, "");
    ce_set_string(entry, CE_OFF_OBJECT_GUID, "");
    ce_set_string(entry, CE_OFF_CLONE_GUID, "");
    ce_set_string(entry, CE_OFF_SCENARIO_TYPE, "");
    ce_set_string(entry, CE_OFF_SCENARIO_UUID, "");
    ce_set_string(entry, CE_OFF_SCENARIO_NAME, "");
    ce_set_string(entry, CE_OFF_ARCHETYPE_NAME, "");
    ce_set_string(entry, CE_OFF_RACE_NAME, "");
    ce_set_string(entry, CE_OFF_VESSEL_TEMPLATE_NAME, "");

    /* Parse and set actual values */
    if (json_get_string(obj, obj_len, "name", buf, sizeof(buf)))
        ce_set_string(entry, CE_OFF_NAME, buf);
    if (json_get_string(obj, obj_len, "object_guid", buf, sizeof(buf)))
        ce_set_string(entry, CE_OFF_OBJECT_GUID, buf);
    if (json_get_string(obj, obj_len, "archetype_name", buf, sizeof(buf)))
        ce_set_string(entry, CE_OFF_ARCHETYPE_NAME, buf);
    if (json_get_string(obj, obj_len, "race_name", buf, sizeof(buf)))
        ce_set_string(entry, CE_OFF_RACE_NAME, buf);

    int ival;
    if (json_get_int(obj, obj_len, "gender_id", &ival))
        ce_set_int(entry, CE_OFF_GENDER_ID, ival);
    if (json_get_int(obj, obj_len, "level", &ival))
        ce_set_int(entry, CE_OFF_LEVEL, ival);
    if (json_get_int(obj, obj_len, "vessel_quality", &ival))
        ce_set_int(entry, CE_OFF_VESSEL_QUALITY, ival);

    logmsg("  built CharacterEntry: %p", entry);
    return entry;
}

/* Create a CharacterList populated with entries parsed from JSON.
 *
 * List<T> internal layout (IL2CPP):
 *   0x10: _items  (Il2CppArray*)
 *   0x18: _size   (int32_t)
 *   0x20: _version (int32_t)
 */
static Il2CppObject *create_character_list(const char *json_buf, int json_len) {
    if (!klass_CharList || !klass_CharacterEntry) {
        logmsg("  missing CharacterList or CharacterEntry class");
        return NULL;
    }

    /* Count character objects in the "characters" array */
    const char *chars_key = strstr(json_buf, "\"characters\"");
    if (!chars_key) {
        logmsg("  no 'characters' key in JSON — returning empty list");
        Il2CppObject *list = p_object_new(klass_CharList);
        return list; /* zero-init = empty list */
    }

    /* Collect character objects */
    #define MAX_CHARS 32
    Il2CppObject *entries[MAX_CHARS];
    int count = 0;

    /* Find the '[' after "characters" */
    const char *arr_start = strchr(chars_key + 12, '[');
    if (!arr_start) {
        Il2CppObject *list = p_object_new(klass_CharList);
        return list;
    }

    int arr_offset = (int)(arr_start - json_buf);
    int pos = arr_offset;
    while (count < MAX_CHARS) {
        int end = 0;
        char *obj = json_next_object((char *)json_buf, json_len, &pos, &end);
        if (!obj) break;
        Il2CppObject *entry = build_character_entry(obj, end - pos);
        if (entry) entries[count++] = entry;
        pos = end;
    }

    logmsg("  parsed %d character(s) from JSON", count);

    /* Create the list */
    Il2CppObject *list = p_object_new(klass_CharList);
    if (!list) { logmsg("  object_new(CharacterList) failed"); return NULL; }

    if (count > 0) {
        /* Create array for _items */
        Il2CppArray *arr = p_array_new(klass_CharacterEntry, count);
        if (arr) {
            /* Array elements start at offset 0x20 (header=0x10, max_length=0x08,
             * then bounds ptr = 0x08).  Actually for szarray: header(0x10) +
             * max_length(size_t=8) = 0x18.  Elements at 0x20 for ref types.
             * Let's use the standard IL2CPP szarray layout. */
            void **elements = (void **)((uint8_t *)arr + 0x20);
            for (int i = 0; i < count; i++) {
                elements[i] = entries[i];
            }
            /* Set list internals */
            *(void **)((uint8_t *)list + 0x10) = arr;    /* _items */
            *(int *)((uint8_t *)list + 0x18) = count;    /* _size */
            *(int *)((uint8_t *)list + 0x20) = count;    /* _version */
        } else {
            logmsg("  array_new failed");
        }
    }

    return list;
    #undef MAX_CHARS
}

CharacterListResponse * __attribute__((ms_abi))
hook_deserialize_charlist(CharacterListResponse *out, Il2CppString *json, void *minfo) {
    (void)minfo;
    logmsg("hook_deserialize_charlist called");

    int json_len = 0;
    char *json_buf = il2cpp_string_to_utf8(json, &json_len);

    if (json_buf && json_len > 0) {
        log_full_json(json_buf, json_len);
    }

    out->success = 1;
    memset(out->_pad, 0, sizeof(out->_pad));
    out->message = p_string_new("");

    if (json_buf && json_len > 0 && strstr(json_buf, "\"characters\"")) {
        out->characters = create_character_list(json_buf, json_len);
    } else {
        /* No characters key — return empty list */
        if (klass_CharList) {
            out->characters = p_object_new(klass_CharList);
        } else {
            out->characters = NULL;
        }
    }

    logmsg("  -> success=1  characters=%p", out->characters);

    if (json_buf) HeapFree(GetProcessHeap(), 0, json_buf);
    return out;
}

static int install_charlist_trampoline(void) {
    uint8_t *target = ga_base + RVA_DESERIALIZE_STRUCT;

    /* Verify prologue: 48 89 5C 24 08 = mov [rsp+8],rbx */
    if (target[0] != 0x48 || target[1] != 0x89 || target[2] != 0x5C) {
        logmsg("ERROR: Unexpected prologue at CharacterListResponse Deserialize");
        return 0;
    }

    /* 14-byte absolute JMP:  FF 25 00 00 00 00 [8-byte addr] */
    uint8_t jmp[14] = { 0xFF, 0x25, 0, 0, 0, 0 };
    uint64_t addr = (uint64_t)(uintptr_t)hook_deserialize_charlist;
    memcpy(&jmp[6], &addr, 8);

    if (!safe_write(target, jmp, 14)) {
        logmsg("ERROR: Failed to write charlist trampoline");
        return 0;
    }
    logmsg("Installed charlist trampoline at %p", target);
    return 1;
}

/* ── Hook 1b: Deserialize<CreateCharacterResponse> trampoline ─────────── */
/*
 * RVA 0x011F3E40 — struct return type, hidden output pointer.
 *
 * dump.cs:
 *   public struct CreateCharacterResponse {
 *       public bool success;       // 0x0
 *       public string message;     // 0x8
 *       public string object_guid; // 0x10
 *   }
 *
 * Same calling convention as CharacterListResponse:
 *   RCX=out  RDX=json  R8=minfo  → RAX=out
 */

#define RVA_DESERIALIZE_CREATECHAR  0x011F3E40

typedef struct {
    uint8_t  success;
    uint8_t  _pad[7];
    void    *message;       /* Il2CppString* */
    void    *object_guid;   /* Il2CppString* */
} CreateCharacterResponse;

CreateCharacterResponse * __attribute__((ms_abi))
hook_deserialize_createchar(CreateCharacterResponse *out, Il2CppString *json, void *minfo) {
    (void)minfo;
    logmsg("hook_deserialize_createchar called");

    /* Log full JSON body */
    if (json) {
        int len = p_string_length(json);
        uint16_t *chars = p_string_chars(json);
        if (chars && len > 0) {
            char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, len + 1);
            if (buf) {
                for (int i = 0; i < len; i++) buf[i] = (char)(chars[i] & 0xFF);
                buf[len] = '\0';
                if (log_handle != INVALID_HANDLE_VALUE) {
                    const char prefix[] = "  JSON: ";
                    const char newline[] = "\n";
                    DWORD written;
                    WriteFile(log_handle, prefix, sizeof(prefix) - 1, &written, NULL);
                    WriteFile(log_handle, buf, len, &written, NULL);
                    WriteFile(log_handle, newline, 1, &written, NULL);
                }

                /* Parse object_guid from JSON (simple scan for "object_guid":"...") */
                Il2CppString *guid_str = p_string_new("");
                char *p = strstr(buf, "\"object_guid\"");
                if (p) {
                    /* skip to value */
                    p = strchr(p + 13, '"');  /* opening quote of key's colon-value */
                    if (p) {
                        p++;  /* skip colon-side quote — but might hit : first */
                        /* skip ': ' */
                        while (*p == ':' || *p == ' ' || *p == '"') p++;
                        char *end = strchr(p, '"');
                        if (end) {
                            char saved = *end;
                            *end = '\0';
                            guid_str = p_string_new(p);
                            *end = saved;
                            logmsg("  parsed object_guid: %s", p);
                        }
                    }
                }

                HeapFree(GetProcessHeap(), 0, buf);
                out->object_guid = guid_str;
            } else {
                out->object_guid = p_string_new("");
            }
        } else {
            out->object_guid = p_string_new("");
        }
    } else {
        out->object_guid = p_string_new("");
    }

    out->success = 1;
    memset(out->_pad, 0, sizeof(out->_pad));
    out->message = p_string_new("");
    logmsg("  -> success=1  object_guid=%p", out->object_guid);
    return out;
}

static int install_createchar_trampoline(void) {
    uint8_t *target = ga_base + RVA_DESERIALIZE_CREATECHAR;

    /* Verify prologue: 48 89 5C 24 08 = mov [rsp+8],rbx */
    if (target[0] != 0x48 || target[1] != 0x89 || target[2] != 0x5C) {
        logmsg("ERROR: Unexpected prologue at CreateCharacterResponse Deserialize: %02X %02X %02X",
               target[0], target[1], target[2]);
        return 0;
    }

    /* 14-byte absolute JMP:  FF 25 00 00 00 00 [8-byte addr] */
    uint8_t jmp[14] = { 0xFF, 0x25, 0, 0, 0, 0 };
    uint64_t addr = (uint64_t)(uintptr_t)hook_deserialize_createchar;
    memcpy(&jmp[6], &addr, 8);

    if (!safe_write(target, jmp, 14)) {
        logmsg("ERROR: Failed to write createchar trampoline");
        return 0;
    }
    logmsg("Installed createchar trampoline at %p", target);
    return 1;
}

/* ── Hook 2: Shared Deserialize<T> for reference types ───────────────── */
/*
 * RVA 0x011F3B10 — shared generic for ~35 class types.
 *
 * At +0xA3 the function sets up and calls il2cpp_object_iscast:
 *   +0xA3: mov rdx, rbx       ; target class
 *   +0xA6: mov rcx, rdi       ; object (pre-iscast result)
 *   +0xA9: call iscast
 *   +0xAE: test rax, rax
 *   +0xB1: jne → +0x93        ; return if cast succeeded
 *   +0xB3: (throw InvalidCastException)
 *
 * iscast fails for many types in the shared generic context because the
 * klass metadata doesn't match.  We replace this 16-byte block (+0xA3
 * through +0xB2) with:
 *
 *   mov rax, rdi              ; use the pre-iscast object directly
 *   cmp rax, 0xFFFF           ; pointer validity check
 *   ja  → +0x93 (epilogue)    ; if valid pointer (>0xFFFF), return it
 *   xor eax, eax              ; else return NULL (catches rdi=0 or bad small values)
 *   jmp → +0x93 (epilogue)
 *
 * This returns the original deserialized object for valid pointers,
 * while safely returning NULL for non-pointer values (e.g., rdi=1
 * from boxed boolean results during character creation).
 */

#define RVA_DESERIALIZE_REFTYPE  0x011F3B10
#define REFTYPE_PATCH_START      0xA3  /* start of iscast setup: mov rdx, rbx */

static int install_reftype_patch(void) {
    uint8_t *func = ga_base + RVA_DESERIALIZE_REFTYPE;
    uint8_t *patch_addr = func + REFTYPE_PATCH_START;

    /* Verify expected bytes at +0xA3: 48 8B D3 48 8B CF E8 ... */
    if (patch_addr[0] != 0x48 || patch_addr[1] != 0x8B || patch_addr[2] != 0xD3 ||
        patch_addr[3] != 0x48 || patch_addr[4] != 0x8B || patch_addr[5] != 0xCF) {
        logmsg("ERROR: Unexpected bytes at reftype patch site +0xA3: %02X %02X %02X %02X %02X %02X",
               patch_addr[0], patch_addr[1], patch_addr[2],
               patch_addr[3], patch_addr[4], patch_addr[5]);
        return 0;
    }

    /* 16-byte replacement:
     *   48 89 F8              mov rax, rdi          (3)
     *   48 3D FF FF 00 00     cmp rax, 0xFFFF       (6)
     *   77 E5                 ja  → +0x93           (2)  [from +0xAE: 0x93 - 0xAE = -0x1B = 0xE5]
     *   33 C0                 xor eax, eax          (2)
     *   EB E1                 jmp → +0x93           (2)  [from +0xB2: 0x93 - 0xB2 = -0x1F = 0xE1]
     *   CC                    int3 (padding)         (1)
     *                                          total: 16 bytes
     */
    uint8_t patch[16] = {
        0x48, 0x89, 0xF8,                   /* mov rax, rdi            */
        0x48, 0x3D, 0xFF, 0xFF, 0x00, 0x00, /* cmp rax, 0xFFFF        */
        0x77, 0xE5,                          /* ja  → +0x93 (epilogue) */
        0x33, 0xC0,                          /* xor eax, eax           */
        0xEB, 0xE1,                          /* jmp → +0x93 (epilogue) */
        0xCC,                                /* int3                   */
    };

    if (!safe_write(patch_addr, patch, sizeof(patch))) {
        logmsg("ERROR: Failed to write reftype patch");
        return 0;
    }

    logmsg("Installed reftype iscast bypass at %p (+0xA3, 16 bytes)", func);
    logmsg("  Skips iscast, returns rdi if valid pointer, NULL otherwise");
    return 1;
}

/* ── Hook 3: Skip addon scene loading in ZoneManager.ClientLoadScene ──── */
/*
 * Inside <ClientLoadScene>d__50.MoveNext coroutine.
 *
 * The coroutine loads the main zone scene (works), then tries to load
 * addon scenes via StreamingZone.ClientAddonSceneName.  These addon
 * scenes were CDN-streamed in production and don't exist locally,
 * causing a Unity native crash in SceneManager.LoadSceneAsync.
 *
 * Two patches work together:
 *
 * Patch 3a — NOP the LoadSceneAsync call (RVA 0x32FDFF4, 5 bytes)
 *   Original: E8 F7 85 87 FE  (call SceneManager.LoadSceneAsync)
 *   Patched:  33 C0 90 90 90  (xor eax, eax; nop; nop; nop)
 *   Effect:   rax = 0 (null AsyncOperation)
 *
 * Patch 3b — Redirect the null-AsyncOperation error JE (RVA 0x32FE018, 6 bytes)
 *   After the call, the code checks if the AsyncOperation is null.
 *   Original JE goes to an error handler that throws.
 *   We redirect it to the success cleanup code instead.
 *
 *   Original: 0F 84 37 02 00 00  (JE +0x237 → error handler @ 0x32FD255)
 *   Patched:  E9 03 02 00 00 90  (JMP +0x203 → ZoneLoaded=true @ 0x32FD220)
 *
 * The JMP target (RVA 0x32FE220) sets ZoneLoaded=true, calls the
 * callback with success=true, and returns false (coroutine done).
 * ClientAddonsLoaded was already set to true earlier in the coroutine
 * (at RVA 0x32FDEF3), before the LoadSceneAsync call.
 */

#define RVA_ADDON_CALL   0x032FDFF4  /* call LoadSceneAsync */
#define RVA_ADDON_NULLJE 0x032FE018  /* je after null check on AsyncOperation */

static int install_addon_skip_patch(void) {
    uint8_t *call_addr = ga_base + RVA_ADDON_CALL;
    uint8_t *je_addr   = ga_base + RVA_ADDON_NULLJE;

    /* Verify call instruction: E8 F7 85 87 FE */
    if (call_addr[0] != 0xE8 || call_addr[1] != 0xF7 ||
        call_addr[2] != 0x85 || call_addr[3] != 0x87 || call_addr[4] != 0xFE) {
        logmsg("ERROR: Unexpected bytes at addon call site: %02X %02X %02X %02X %02X",
               call_addr[0], call_addr[1], call_addr[2], call_addr[3], call_addr[4]);
        return 0;
    }

    /* Verify JE instruction: 0F 84 37 02 00 00 */
    if (je_addr[0] != 0x0F || je_addr[1] != 0x84 ||
        je_addr[2] != 0x37 || je_addr[3] != 0x02) {
        logmsg("ERROR: Unexpected bytes at addon JE site: %02X %02X %02X %02X",
               je_addr[0], je_addr[1], je_addr[2], je_addr[3]);
        return 0;
    }

    /* Patch 3a: NOP the LoadSceneAsync call → return null */
    uint8_t nop_call[5] = { 0x33, 0xC0, 0x90, 0x90, 0x90 };  /* xor eax,eax; nop; nop; nop */
    if (!safe_write(call_addr, nop_call, sizeof(nop_call))) {
        logmsg("ERROR: Failed to NOP addon LoadSceneAsync call");
        return 0;
    }

    /* Patch 3b: Redirect null-check JE to success cleanup
     *   JMP from RVA 0x32FE018, next_ip = 0x32FE01D
     *   Target = RVA 0x32FE220 (ZoneLoaded=true + callback + return)
     *   Displacement = 0x32FE220 - 0x32FE01D = 0x203
     */
    uint8_t jmp_patch[6] = { 0xE9, 0x03, 0x02, 0x00, 0x00, 0x90 };  /* jmp +0x203; nop */
    if (!safe_write(je_addr, jmp_patch, sizeof(jmp_patch))) {
        logmsg("ERROR: Failed to redirect addon null-check JE");
        return 0;
    }

    logmsg("Installed addon skip: NOP call at %p, JMP at %p → success path", call_addr, je_addr);
    return 1;
}

/* ── Hook 4: Log entry into GameStateLoadingWorld.OnPhysicsConnectionRequest ── */

static int install_loadingworld_onphysicsrequest_hook(void) {
    uint8_t *target = ga_base + RVA_LOADINGWORLD_ONPHYSICSREQUEST;
    uint8_t *trampoline;
    uint8_t *p;
    uint64_t addr;

    /* Verify the exact prologue we reverse engineered. */
    if (target[0] != 0x40 || target[1] != 0x53 ||
        target[2] != 0x48 || target[3] != 0x83 || target[4] != 0xEC || target[5] != 0x20 ||
        target[6] != 0x80 || target[7] != 0x3D) {
        logmsg("ERROR: Unexpected bytes at LoadingWorld.OnPhysicsConnectionRequest: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }

    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) {
        logmsg("ERROR: Failed to allocate trampoline for LoadingWorld.OnPhysicsConnectionRequest");
        return 0;
    }

    p = trampoline;

    /* push rbx ; sub rsp, 0x20 */
    *p++ = 0x40; *p++ = 0x53;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;

    /* mov rax, <flag_addr> ; cmp byte ptr [rax], 0 */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E58);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;

    /* jne branch_taken */
    *p++ = 0x75; *p++ = 0x0C;

    /* mov rax, <original+0x0f> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x0F);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    /* branch_taken: mov rax, <original+0x82> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x82);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    original_loadingworld_onphysicsrequest = (fn_loadingworld_onphysicsrequest_t)trampoline;

    {
        uint8_t jmp[14];
        write_abs_jump(jmp, hook_loadingworld_onphysicsrequest);
        if (!safe_write(target, jmp, sizeof(jmp))) {
            logmsg("ERROR: Failed to patch LoadingWorld.OnPhysicsConnectionRequest");
            return 0;
        }
    }

    logmsg("Installed LoadingWorld.OnPhysicsConnectionRequest hook at %p (trampoline=%p)",
           target, trampoline);
    return 1;
}

static int install_loadingworld_onphysauth_hook(void) {
    uint8_t *target = ga_base + RVA_LOADINGWORLD_ONPHYSACTIONCONFIRMATION;
    uint8_t *trampoline;
    uint8_t *p;
    uint64_t addr;

    if (target[0] != 0x40 || target[1] != 0x53 ||
        target[2] != 0x48 || target[3] != 0x83 || target[4] != 0xEC || target[5] != 0x20 ||
        target[6] != 0x80 || target[7] != 0x3D) {
        logmsg("ERROR: Unexpected bytes at LoadingWorld.OnPhysicsAuthenticationConfirmation: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }

    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) {
        logmsg("ERROR: Failed to allocate trampoline for LoadingWorld.OnPhysicsAuthenticationConfirmation");
        return 0;
    }

    p = trampoline;

    /* push rbx ; sub rsp, 0x20 */
    *p++ = 0x40; *p++ = 0x53;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;

    /* mov rax, <flag_addr> ; cmp byte ptr [rax], 0 */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E59);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;

    /* mov rbx, rdx */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xDA;

    /* jne branch_taken */
    *p++ = 0x75; *p++ = 0x0C;

    /* mov rax, <original+0x12> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x12);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    /* branch_taken: mov rax, <original+0x79> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x79);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    original_loadingworld_onphysauth = (fn_loadingworld_onphysauth_t)trampoline;

    {
        uint8_t jmp[14];
        write_abs_jump(jmp, hook_loadingworld_onphysauth);
        if (!safe_write(target, jmp, sizeof(jmp))) {
            logmsg("ERROR: Failed to patch LoadingWorld.OnPhysicsAuthenticationConfirmation");
            return 0;
        }
    }

    logmsg("Installed LoadingWorld.OnPhysicsAuthenticationConfirmation hook at %p (trampoline=%p)",
           target, trampoline);
    return 1;
}

static int install_loadingworld_onworldready_hook(void) {
    uint8_t *target = ga_base + RVA_LOADINGWORLD_ONWORLDREADY;
    uint8_t *trampoline;
    uint8_t *p;
    uint64_t addr;

    if (target[0] != 0x48 || target[1] != 0x89 || target[2] != 0x5C || target[3] != 0x24 ||
        target[4] != 0x08 || target[5] != 0x57 || target[6] != 0x48 || target[7] != 0x83) {
        logmsg("ERROR: Unexpected bytes at LoadingWorld.OnWorldReady: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }

    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) {
        logmsg("ERROR: Failed to allocate trampoline for LoadingWorld.OnWorldReady");
        return 0;
    }

    p = trampoline;

    /* mov [rsp+0x08],rbx ; push rdi ; sub rsp,0x20 */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x5C; *p++ = 0x24; *p++ = 0x08;
    *p++ = 0x57;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;

    /* mov rax, <flag_addr> ; cmp byte ptr [rax], 0 */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E5A);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;

    /* mov rdi, rcx */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xF9;

    /* jne branch_taken */
    *p++ = 0x75; *p++ = 0x0C;

    /* mov rax, <original+0x16> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x16);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    /* branch_taken: mov rax, <original+0x29> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x29);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    original_loadingworld_onworldready = (fn_loadingworld_onworldready_t)trampoline;

    {
        uint8_t patch[14];
        write_abs_jump(patch, hook_loadingworld_onworldready);
        if (!safe_write(target, patch, sizeof(patch))) {
            logmsg("ERROR: Failed to patch LoadingWorld.OnWorldReady");
            return 0;
        }
    }

    logmsg("Installed LoadingWorld.OnWorldReady hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_ingame_onenteredzone_hook(void) {
    uint8_t *target = ga_base + RVA_INGAME_ONENTEREDZONEANDLOADINGSCREENHIDDEN;
    uint8_t *trampoline, *p; uint64_t addr;
    if (target[0] != 0x40 || target[1] != 0x53 || target[2] != 0x48 || target[3] != 0x83 ||
        target[4] != 0xEC || target[5] != 0x20 || target[6] != 0x80 || target[7] != 0x3D) {
        logmsg("ERROR: Unexpected bytes at InGame.OnEnteredZoneAndLoadingScreenHidden: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }
    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) return 0;
    p = trampoline;
    *p++ = 0x40; *p++ = 0x53;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E46); memcpy(p,&addr,8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xD9;
    *p++ = 0x75; *p++ = 0x0C;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x10); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x25); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    original_ingame_onenteredzone = (fn_ingame_onenteredzone_t)trampoline;
    { uint8_t jmp[14]; write_abs_jump(jmp, hook_ingame_onenteredzone); if (!safe_write(target, jmp, sizeof(jmp))) return 0; }
    logmsg("Installed InGame.OnEnteredZoneAndLoadingScreenHidden hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_ingame_onphysicsdisconnect_hook(void) {
    uint8_t *target = ga_base + RVA_INGAME_ONPHYSICSDISCONNECT;
    uint8_t *trampoline, *p; uint64_t addr;
    if (target[0] != 0x40 || target[1] != 0x57 || target[2] != 0x48 || target[3] != 0x83 ||
        target[4] != 0xEC || target[5] != 0x20 || target[6] != 0x80 || target[7] != 0x3D) {
        logmsg("ERROR: Unexpected bytes at InGame.OnPhysicsDisconnect: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }
    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) return 0;
    p = trampoline;
    *p++ = 0x40; *p++ = 0x57;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E4B); memcpy(p,&addr,8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xF9;
    *p++ = 0x75; *p++ = 0x0C;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x10); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x85); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    original_ingame_onphysicsdisconnect = (fn_ingame_onphysicsdisconnect_t)trampoline;
    { uint8_t jmp[14]; write_abs_jump(jmp, hook_ingame_onphysicsdisconnect); if (!safe_write(target, jmp, sizeof(jmp))) return 0; }
    logmsg("Installed InGame.OnPhysicsDisconnect hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_ingame_onplayerleft_hook(void) {
    uint8_t *target = ga_base + RVA_INGAME_ONPLAYERLEFTPHYSICS;
    uint8_t *trampoline, *p; uint64_t addr;
    if (target[0] != 0x48 || target[1] != 0x83 || target[2] != 0xEC || target[3] != 0x28 ||
        target[4] != 0x80 || target[5] != 0x3D) {
        logmsg("ERROR: Unexpected bytes at InGame.OnPlayerLeftPhysics: %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5]);
        return 0;
    }
    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) return 0;
    p = trampoline;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x28;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E4A); memcpy(p,&addr,8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;
    *p++ = 0x75; *p++ = 0x0C;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x0B); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x50); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    original_ingame_onplayerleft = (fn_ingame_onplayerleft_t)trampoline;
    { uint8_t jmp[14]; write_abs_jump(jmp, hook_ingame_onplayerleft); if (!safe_write(target, jmp, sizeof(jmp))) return 0; }
    logmsg("Installed InGame.OnPlayerLeftPhysics hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_ingame_onzonetransferbegin_hook(void) {
    uint8_t *target = ga_base + RVA_INGAME_ONZONETRANSFERBEGIN;
    uint8_t *trampoline, *p; uint64_t addr;
    if (target[0] != 0x40 || target[1] != 0x53 || target[2] != 0x41 || target[3] != 0x54 ||
        target[4] != 0x48 || target[5] != 0x83 || target[6] != 0xEC || target[7] != 0x48) {
        logmsg("ERROR: Unexpected bytes at InGame.OnZoneTransferBegin: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }
    trampoline = (uint8_t *)alloc_executable(160);
    if (!trampoline) return 0;
    p = trampoline;
    *p++ = 0x40; *p++ = 0x53; *p++ = 0x41; *p++ = 0x54;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x48;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E49); memcpy(p,&addr,8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xDA;
    *p++ = 0x4C; *p++ = 0x8B; *p++ = 0xE1;
    *p++ = 0x75; *p++ = 0x0C;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x15); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    *p++ = 0x48; *p++ = 0xB8; addr = (uint64_t)(uintptr_t)(target + 0x7E); memcpy(p,&addr,8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    original_ingame_onzonetransferbegin = (fn_ingame_onzonetransferbegin_t)trampoline;
    { uint8_t jmp[14]; write_abs_jump(jmp, hook_ingame_onzonetransferbegin); if (!safe_write(target, jmp, sizeof(jmp))) return 0; }
    logmsg("Installed InGame.OnZoneTransferBegin hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_ingame_ontransitionin_hook(void) {
    uint8_t *target = ga_base + RVA_INGAME_ONTRANSITIONIN;
    uint8_t *trampoline;
    uint8_t *p;
    uint64_t addr;

    if (target[0] != 0x48 || target[1] != 0x89 || target[2] != 0x5C || target[3] != 0x24 ||
        target[4] != 0x10 || target[5] != 0x57 || target[6] != 0x48 || target[7] != 0x83) {
        logmsg("ERROR: Unexpected bytes at InGame.OnTransitionIn: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }

    trampoline = (uint8_t *)alloc_executable(160);
    if (!trampoline) return 0;
    p = trampoline;

    /* mov [rsp+0x10],rbx ; push rdi ; sub rsp,0x20 */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x5C; *p++ = 0x24; *p++ = 0x10;
    *p++ = 0x57;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x20;

    /* mov rax, <flag_addr> ; cmp byte ptr [rax], 0 */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(ga_base + 0x04471E45);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;

    /* mov rbx, rdx ; mov rdi, rcx */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xDA;
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xF9;

    /* jne branch_taken */
    *p++ = 0x75; *p++ = 0x0C;

    /* mov rax, <original+0x1d> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x1D);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    /* branch_taken: mov rax, <original+0x120> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x120);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    original_ingame_ontransitionin = (fn_ingame_ontransitionin_t)trampoline;

    {
        uint8_t patch[29];
        write_abs_jump(patch, hook_ingame_ontransitionin);
        memset(patch + 14, 0x90, sizeof(patch) - 14);
        if (!safe_write(target, patch, sizeof(patch))) return 0;
    }

    logmsg("Installed InGame.OnTransitionIn hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_viewmanager_prepgamewindows_hook(void) {
    uint8_t *target = ga_base + RVA_VIEWMANAGER_PREPGAMEWINDOWS;
    uint8_t *trampoline = (uint8_t *)alloc_executable(64);
    if (!trampoline) return 0;
    if (target[0] != 0x48 || target[1] != 0x89 || target[2] != 0x5C || target[3] != 0x24 ||
        target[4] != 0x08 || target[5] != 0x57 || target[6] != 0x48 || target[7] != 0x83) {
        logmsg("ERROR: Unexpected bytes at ViewManager.PrepGameWindows: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }
    memcpy(trampoline, target, 14);
    write_abs_jump(trampoline + 14, target + 14);
    original_viewmanager_prepgamewindows = (fn_viewmanager_prepgamewindows_t)trampoline;
    { uint8_t patch[14]; write_abs_jump(patch, hook_viewmanager_prepgamewindows); if (!safe_write(target, patch, sizeof(patch))) return 0; }
    logmsg("Installed ViewManager.PrepGameWindows hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_viewmanager_initdock_hook(void) {
    uint8_t *target = ga_base + RVA_VIEWMANAGER_INITIALIZEDOCKANDFLOATINGWINDOWS;
    uint8_t *trampoline = (uint8_t *)alloc_executable(80);
    if (!trampoline) return 0;
    if (target[0] != 0x48 || target[1] != 0x89 || target[2] != 0x5C || target[3] != 0x24 ||
        target[4] != 0x08 || target[5] != 0x48 || target[6] != 0x89 || target[7] != 0x6C) {
        logmsg("ERROR: Unexpected bytes at ViewManager.InitializeDockAndFloatingWindows: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }
    memcpy(trampoline, target, 20);
    write_abs_jump(trampoline + 20, target + 20);
    original_viewmanager_initdock = (fn_viewmanager_initdock_t)trampoline;
    { uint8_t patch[14]; write_abs_jump(patch, hook_viewmanager_initdock); if (!safe_write(target, patch, sizeof(patch))) return 0; }
    logmsg("Installed ViewManager.InitializeDockAndFloatingWindows hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_basicheader_read_hook(void) {
    uint8_t *target = ga_base + RVA_BASICHEADER_READ;
    uint8_t *trampoline;
    uint8_t *p;
    uint64_t addr;

    if (target[0] != 0x40 || target[1] != 0x55 ||
        target[2] != 0x56 || target[3] != 0x57 ||
        target[4] != 0x48 || target[5] != 0x83 || target[6] != 0xEC || target[7] != 0x40) {
        logmsg("ERROR: Unexpected bytes at BasicHeader.Read: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }

    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) {
        logmsg("ERROR: Failed to allocate trampoline for BasicHeader.Read");
        return 0;
    }

    p = trampoline;

    /* push rbp; push rsi; push rdi; sub rsp, 0x40 */
    *p++ = 0x40; *p++ = 0x55;
    *p++ = 0x56;
    *p++ = 0x57;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x40;

    /* mov rax, <flag_addr> ; cmp byte ptr [rax], 0 */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(ga_base + 0x0445B9F0);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;

    /* mov rax, <original+0x0f> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x0F);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    original_basicheader_read = (fn_basicheader_read_t)trampoline;

    {
        uint8_t patch[15];
        write_abs_jump(patch, hook_basicheader_read);
        patch[14] = 0x90;
        if (!safe_write(target, patch, sizeof(patch))) {
            logmsg("ERROR: Failed to patch BasicHeader.Read");
            return 0;
        }
    }

    logmsg("Installed BasicHeader.Read hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_scene_load_wrapper_hook(void) {
    uint8_t *target = ga_base + RVA_SCENE_LOAD_WRAPPER;
    uint8_t *trampoline;
    uint8_t *p;
    uint64_t addr;

    if (target[0] != 0x48 || target[1] != 0x89 || target[2] != 0x5C || target[3] != 0x24 ||
        target[4] != 0x10 || target[5] != 0x57 || target[6] != 0x48 || target[7] != 0x83) {
        logmsg("ERROR: Unexpected bytes at scene load wrapper: %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7]);
        return 0;
    }

    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) {
        logmsg("ERROR: Failed to allocate trampoline for scene load wrapper");
        return 0;
    }

    p = trampoline;

    /* mov [rsp+0x10],rbx ; push rdi ; sub rsp,0x30 */
    *p++ = 0x48; *p++ = 0x89; *p++ = 0x5C; *p++ = 0x24; *p++ = 0x10;
    *p++ = 0x57;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x30;

    /* mov rax, <flag_addr> ; cmp byte ptr [rax], 0 */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(ga_base + 0x044624AD);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;

    /* mov rax, <original+0x11> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 0x11);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    original_scene_load_wrapper = (fn_scene_load_wrapper_t)trampoline;

    {
        uint8_t patch[17];
        write_abs_jump(patch, hook_scene_load_wrapper);
        patch[14] = 0x90;
        patch[15] = 0x90;
        patch[16] = 0x90;
        if (!safe_write(target, patch, sizeof(patch))) {
            logmsg("ERROR: Failed to patch scene load wrapper");
            return 0;
        }
    }

    logmsg("Installed scene load wrapper hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

static int install_clientloadscene_movenext_hook(void) {
    uint8_t *target = ga_base + RVA_CLIENTLOADSCENE_MOVENEXT;
    uint8_t *trampoline;
    uint8_t *p;
    uint64_t addr;

    if (target[0] != 0x40 || target[1] != 0x56 || target[2] != 0x57 ||
        target[3] != 0x41 || target[4] != 0x57 || target[5] != 0x48 ||
        target[6] != 0x83 || target[7] != 0xEC || target[8] != 0x30) {
        logmsg("ERROR: Unexpected bytes at ClientLoadScene.MoveNext: %02X %02X %02X %02X %02X %02X %02X %02X %02X",
               target[0], target[1], target[2], target[3], target[4], target[5], target[6], target[7], target[8]);
        return 0;
    }

    trampoline = (uint8_t *)alloc_executable(128);
    if (!trampoline) {
        logmsg("ERROR: Failed to allocate trampoline for ClientLoadScene.MoveNext");
        return 0;
    }

    p = trampoline;

    /* push rsi ; push rdi ; push r15 ; sub rsp,0x30 */
    *p++ = 0x40; *p++ = 0x56;
    *p++ = 0x57;
    *p++ = 0x41; *p++ = 0x57;
    *p++ = 0x48; *p++ = 0x83; *p++ = 0xEC; *p++ = 0x30;

    /* mov rax, <flag_addr> ; cmp byte ptr [rax], 0 */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(ga_base + 0x04471FD4);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0x80; *p++ = 0x38; *p++ = 0x00;

    /* mov rdi, rcx */
    *p++ = 0x48; *p++ = 0x8B; *p++ = 0xF9;

    /* mov rax, <original+19> ; jmp rax */
    *p++ = 0x48; *p++ = 0xB8;
    addr = (uint64_t)(uintptr_t)(target + 19);
    memcpy(p, &addr, 8); p += 8;
    *p++ = 0xFF; *p++ = 0xE0;

    original_clientloadscene_movenext = (fn_clientloadscene_movenext_t)trampoline;

    {
        uint8_t patch[19];
        write_abs_jump(patch, hook_clientloadscene_movenext);
        patch[14] = 0x90;
        patch[15] = 0x90;
        patch[16] = 0x90;
        patch[17] = 0x90;
        patch[18] = 0x90;
        if (!safe_write(target, patch, sizeof(patch))) {
            logmsg("ERROR: Failed to patch ClientLoadScene.MoveNext");
            return 0;
        }
    }

    logmsg("Installed ClientLoadScene.MoveNext hook at %p (trampoline=%p)", target, trampoline);
    return 1;
}

/* ── Lazy init from game thread (no background thread) ───────────────── */
/*
 * Patching is triggered from proxy function calls, which run on the
 * game's own threads (already registered with the Boehm GC).
 * This avoids the "Collecting from unknown thread" GC assertion
 * that occurs when a CreateThread-spawned thread exists alongside IL2CPP.
 *
 * States:  0 = not started,  1 = done,  2 = failed/too early (retry later)
 */

static volatile int patch_state = 0;

/* Patch: NOP AnimatedDestructible.PlayablePreparerTask.Tick so it never processes
 * its request queue.  Without a real asset server, DoLoad/DoSpawn produce dangling
 * delegate invocation list entries that crash RequestCompleteHandler.Invoke. */
static int install_animdestructible_tick_nop(void) {
    uint8_t *target = ga_base + RVA_ANIMDESTRUCTIBLE_TICK;
    if (target[0] == 0xC3) {
        logmsg("AnimDestructible.PlayablePreparerTask.Tick already patched");
        return 1;
    }
    uint8_t ret_patch[1] = { 0xC3 };
    if (!safe_write(target, ret_patch, sizeof(ret_patch))) {
        logmsg("ERROR: Failed to NOP AnimDestructible.PlayablePreparerTask.Tick at %p", target);
        return 0;
    }
    logmsg("Patched AnimDestructible.PlayablePreparerTask.Tick -> RET at %p", target);
    return 1;
}

static void try_apply_patches(void) {
    if (patch_state == 1) return;  /* already done */

    /* Check if GameAssembly.dll is loaded yet */
    if (!ga_module) {
        ga_module = GetModuleHandleA("GameAssembly.dll");
        if (!ga_module) return;  /* too early — will retry on next proxy call */
        ga_base = (uint8_t *)ga_module;

        log_open();
        logmsg("=== Crowfall proxy DLL loaded ===");
        logmsg("GameAssembly.dll base: %p", ga_base);

        if (!load_il2cpp_api()) {
            logmsg("ERROR: Failed to load il2cpp API");
            patch_state = 1;  /* give up */
            return;
        }
        logmsg("IL2CPP API loaded");
    }

    /* Check if IL2CPP domain is ready */
    Il2CppDomain *domain = p_domain_get();
    if (!domain) return;  /* too early — will retry */

    /* Try to resolve types (need assemblies loaded) */
    if (!resolve_types()) return;  /* assemblies not ready yet — will retry */

    /* Install all hooks */
    int ok1 = install_charlist_trampoline();
    int ok1b = install_createchar_trampoline();
    int ok2 = install_reftype_patch();
    int ok3 = install_addon_skip_patch();
    int ok4 = install_loadingworld_onphysicsrequest_hook();
    int ok4b = install_loadingworld_onphysauth_hook();
    int ok4c = install_loadingworld_onworldready_hook();
    int ok4d = install_ingame_onenteredzone_hook();
    int ok4e = install_ingame_onphysicsdisconnect_hook();
    int ok4f = install_ingame_onzonetransferbegin_hook();
    int ok4g = install_ingame_onplayerleft_hook();
    int ok4j = install_ingame_ontransitionin_hook();
    int ok4h = 1; /* disabled: naive trampoline copy was unstable here */
    int ok4i = 1; /* disabled: naive trampoline copy was unstable here */
    int ok_animd = install_animdestructible_tick_nop();
    int ok5 = install_basicheader_read_hook();
    int ok6 = install_scene_load_wrapper_hook();
    int ok7 = 1; /* disabled while reducing scene-load hook footprint */
    log_runtime_string_ids();
    log_request_payload_bytes();

    logmsg("=== Patches: charlist=%s  createchar=%s  reftype=%s  addon_skip=%s  loadingworld_onphysics=%s  loadingworld_auth=%s  loadingworld_worldready=%s  ingame_enteredzone=%s  ingame_physdisc=%s  ingame_zonetransfer=%s  ingame_playerleft=%s  ingame_transitionin=%s  view_prep=%s  view_initdock=%s  animd_tick=%s  basicheader_read=%s  scene_load=%s  clientloadscene=%s ===",
           ok1 ? "OK" : "FAIL", ok1b ? "OK" : "FAIL",
           ok2 ? "OK" : "FAIL", ok3 ? "OK" : "FAIL", ok4 ? "OK" : "FAIL",
           ok4b ? "OK" : "FAIL", ok4c ? "OK" : "FAIL",
           ok4d ? "OK" : "FAIL", ok4e ? "OK" : "FAIL", ok4f ? "OK" : "FAIL", ok4g ? "OK" : "FAIL", ok4j ? "OK" : "FAIL",
           ok4h ? "DISABLED" : "FAIL", ok4i ? "DISABLED" : "FAIL",
           ok_animd ? "OK" : "FAIL",
           ok5 ? "OK" : "FAIL", ok6 ? "OK" : "FAIL", ok7 ? "DISABLED" : "FAIL");

    patch_state = 1;  /* done — stop retrying */
}

/* ── DLL entry point ─────────────────────────────────────────────────── */

static int is_game_process(void) {
    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, sizeof(path));
    if (len == 0) return 0;
    char *name = path + len;
    while (name > path && name[-1] != '\\' && name[-1] != '/') name--;
    return (lstrcmpiA(name, "CrowfallClient.exe") == 0);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        /* Patching happens lazily from proxy function calls.
           No background thread — avoids Boehm GC "unknown thread" assertion. */
        if (!is_game_process()) {
            patch_state = 1;  /* skip patching for non-game processes */
        }
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        if (real_version) FreeLibrary(real_version);
        if (log_handle != INVALID_HANDLE_VALUE) CloseHandle(log_handle);
    }
    return TRUE;
}
