
You're asking for **five distinct workflows** to compile `.cpp` source into `.exe` or `.dll` — each using **different toolchains**, run **fully via terminal/command-line**. No fluff. No GUI.

Here's your **arsenal-grade list** 👇

---

## 🧰 **1. Microsoft Build Tools (MSVC/CL.exe) – Native Windows**  
> 📍 Tool: `cl.exe` (MSVC command-line compiler)

**🔹 DLL:**
```cmd
cl /LD payload.cpp /link /out:payload.dll
```

**🔹 EXE:**
```cmd
cl payload.cpp /link /out:payload.exe
```

> ⚠️ Needs `Developer Command Prompt for Visual Studio` or path to `vcvarsall.bat`

---

## 🧰 **2. GNU Compiler (MinGW / g++) – Cross-Platform/Windows**  
> 📍 Tool: `g++` (from MinGW)

**🔹 DLL:**
```cmd
g++ -shared -o payload.dll payload.cpp
```

**🔹 EXE:**
```cmd
g++ -o payload.exe payload.cpp
```

> ✅ Good for lightweight builds. Supports Windows API. Use `x86_64-w64-mingw32-g++` for targeting 64-bit Windows from Linux.

---

## 🧰 **3. CMake + Ninja (Portable, Configurable)**  
> 📍 Tools: `cmake`, `ninja` (optional)

**🔹 DLL (from CMakeLists.txt):**
```cmake
add_library(payload SHARED payload.cpp)
```

**🔹 Terminal:**
```bash
cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release .
ninja
```

> ✅ CMake generates cross-platform build scripts. Add `-DCMAKE_SYSTEM_NAME=Windows` for cross-compilation.

---

## 🧰 **4. Clang/LLVM Toolchain (Cross-Compile + Obfuscation Ready)**  
> 📍 Tool: `clang++`

**🔹 DLL:**
```bash
clang++ -shared -o payload.dll payload.cpp
```

**🔹 EXE:**
```bash
clang++ -o payload.exe payload.cpp
```

> ✅ Bonus: Integrates well with obfuscation frameworks like **LLVM Obfuscator (ollvm)**

---

## 🧰 **5. Visual Studio MSBuild (Project-Level Builds via Terminal)**  
> 📍 Tool: `msbuild.exe`

**🔹 Setup:**
1. Create `.vcxproj` file or use Visual Studio
2. Then compile:

```cmd
msbuild payload.vcxproj /p:Configuration=Release /p:Platform=x64
```

> ✅ Used in advanced setups where DLL needs **manifest**, **resources**, or **dependencies linked** properly.

---
