#pragma once

#ifdef _WIN32
#	define __rescalll __thiscall
#else
#	define __rescalll __attribute__((__cdecl__))
#	define __stdcall
#endif

#define SEEK_DIR_CUR std::ios_base::cur

#ifdef _WIN32
#	define MODULE_EXTENSION ".dll"
#	define __rescall __thiscall
#	define DLL_EXPORT extern "C" __declspec(dllexport)
#	define STDCALL_NAME(base, param_bytes) "_" base "@" #param_bytes

#	define DECL_DETOUR(name, ...)                                   \
		using _##name = int(__rescall *)(void *thisptr, ##__VA_ARGS__); \
		static _##name name;                                            \
		static int __fastcall name##_Hook(void *thisptr, int edx, ##__VA_ARGS__)
#	define DECL_DETOUR_T(type, name, ...)                            \
		using _##name = type(__rescall *)(void *thisptr, ##__VA_ARGS__); \
		static _##name name;                                             \
		static type __fastcall name##_Hook(void *thisptr, int edx, ##__VA_ARGS__)
#	define DECL_DETOUR_B(name, ...)                                 \
		using _##name = int(__rescall *)(void *thisptr, ##__VA_ARGS__); \
		static _##name name;                                            \
		static _##name name##Base;                                      \
		static int __fastcall name##_Hook(void *thisptr, int edx, ##__VA_ARGS__)

#	define DETOUR(name, ...) \
		int __fastcall name##_Hook(void *thisptr, int edx, ##__VA_ARGS__)
#	define DETOUR_T(type, name, ...) \
		type __fastcall name##_Hook(void *thisptr, int edx, ##__VA_ARGS__)
#	define DETOUR_B(name, ...) \
		int __fastcall name##_Hook(void *thisptr, int edx, ##__VA_ARGS__)

#else
#	define MODULE_EXTENSION ".so"
#	define __rescall __attribute__((__cdecl__))
#	define __cdecl __attribute__((__cdecl__))
#	define __fastcall __attribute__((__fastcall__))
#	define DLL_EXPORT extern "C" __attribute__((visibility("default")))
//#	define SEEK_DIR_CUR std::ios_base::seekdir::_S_cur
#	define STDCALL_NAME(base, param_bytes) base

#	define DECL_DETOUR(name, ...)                                   \
		using _##name = int(__rescall *)(void *thisptr, ##__VA_ARGS__); \
		static _##name name;                                            \
		static int __rescall name##_Hook(void *thisptr, ##__VA_ARGS__)
#	define DECL_DETOUR_T(type, name, ...)                            \
		using _##name = type(__rescall *)(void *thisptr, ##__VA_ARGS__); \
		static _##name name;                                             \
		static type __rescall name##_Hook(void *thisptr, ##__VA_ARGS__)
#	define DECL_DETOUR_B(name, ...)                                 \
		using _##name = int(__rescall *)(void *thisptr, ##__VA_ARGS__); \
		static _##name name;                                            \
		static _##name name##Base;                                      \
		static int __rescall name##_Hook(void *thisptr, ##__VA_ARGS__)

#	define DETOUR(name, ...) \
		int __rescall name##_Hook(void *thisptr, ##__VA_ARGS__)
#	define DETOUR_T(type, name, ...) \
		type __rescall name##_Hook(void *thisptr, ##__VA_ARGS__)
#	define DETOUR_B(name, ...) \
		int __rescall name##_Hook(void *thisptr, ##__VA_ARGS__)
#endif
