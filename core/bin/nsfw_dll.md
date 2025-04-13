Here’s a **simplified and clean version** of your `.md` file — streamlined for clarity and speed, with all essential commands preserved:

---

```markdown
# 🧱 Compile `.cpp` to `.exe` / `.dll` – 5 Command-Line Methods

**No GUI. No fluff. Just terminal commands.**

---

## 1. 🔧 MSVC (cl.exe)

**DLL:**
```cmd
cl /LD payload.cpp /link /out:payload.dll
```

**EXE:**
```cmd
cl payload.cpp /link /out:payload.exe
```

> ⚠️ Requires Dev Command Prompt or `vcvarsall.bat`

---

## 2. 🐧 MinGW (g++)

**DLL:**
```cmd
g++ -shared -o payload.dll payload.cpp
```

**EXE:**
```cmd
g++ -o payload.exe payload.cpp
```

> ✅ Lightweight. Supports cross-compilation.

---

## 3. ⚙️ CMake + Ninja

**CMakeLists.txt:**
```cmake
add_library(payload SHARED payload.cpp)
```

**Build:**
```bash
cmake -G "Ninja" -DCMAKE_BUILD_TYPE=Release .
ninja
```

> ✅ Cross-platform & configurable.

---

## 4. 🧠 Clang (LLVM)

**DLL:**
```bash
clang++ -shared -o payload.dll payload.cpp
```

**EXE:**
```bash
clang++ -o payload.exe payload.cpp
```

> ✅ Works with obfuscation (e.g., OLLVM)

---

## 5. 🏗️ MSBuild

**Steps:**
1. Use `.vcxproj` or create one.
2. Then run:

```cmd
msbuild payload.vcxproj /p:Configuration=Release /p:Platform=x64
```

> ✅ Ideal for full project builds (with resources/manifests).

---
```

Let me know if you want a version tailored for Linux-to-Windows cross-compilation or obfuscation pipelines next.
