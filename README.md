# 🍷 Wine-NTsync (Userspace macOS Backend)

**Wine-NTsync** is an experimental backend for Wine that implements NT-style synchronization primitives (Event, Mutex, Semaphore) entirely in userspace, with no kernel drivers or Wine server dependency.

👉 This project is **inspired by the Linux `ntsync` implementation**, but **rewritten and tailored for macOS**.

> ⚠️ **Disclaimer**: This project is experimental and not yet fully tested. It is a **prototype** and may not work correctly in all cases. Use at your own risk.

---

## ✨ Current status

- 🧪 Early prototype backend (`WINENTSYNC=1`)
- 🧩 Basic support for `Event`, `Mutex`, and `Semaphore` (userspace)
- 🧵 Uses `pthread`/`cond` primitives instead of Wine server
- 🔬 Still under testing — not production-ready
- 💡 Focused primarily on CrossOver-based builds

---

## ⚙️ How to Use

This backend is **not plug-and-play** — manual patching of Wine source is required.

To use `Wine-NTsync`, you’ll need to:

1. Place `ntsync.c` into `dlls/ntdll/`
2. Edit `dlls/ntdll/sync.c` to dispatch sync functions via `do_ntsync()`  
   (just like `do_esync()` or `do_msync()`)
3. (Optional) Update `dlls/ntdll/ntdll.spec` if you want to override native exports directly
4. Rebuild Wine
5. Run Wine with the environment variable:

```bash
WINENTSYNC=1 wine your_app.exe
```

---

🎯 Project Goal
The goal is to provide a userspace alternative to Wine’s sync server that reduces latency and overhead in synchronization-heavy applications, especially on macOS. This backend avoids context switches, keeps things lightweight, and allows for future expansion.

🤝 Contributing
This is an open experimental project.
If you're into Wine internals, macOS internals, or just want to help make gaming/emulation smoother on Apple Silicon — feel free to contribute!

Suggestions, forks, pull requests — all welcome.
Let's improve this together.
