# 🎣 Windows Hooks Explained - Complete Guide

## What is a "Hook"?

A **hook** is a Windows mechanism that lets a program intercept and monitor system events **before** they reach other applications. Think of it like a **spy** sitting between your keyboard and your applications, watching everything you type.

---

## 🔍 The Hooks We Detect

### 1. **Low-Level Keyboard Hook (WH_KEYBOARD_LL)**

**Feature:** `has_ll_keyboard_hook`  
**Score Impact:** +0.40 (CRITICAL)

#### What It Is:
The most powerful keyboard monitoring method in Windows. It intercepts **every single keystroke** system-wide **before** any application sees it.

#### How It Works:
```
User presses key → Windows → Hook intercepts → Your app sees it → Target app sees it
                            ↑
                    Keylogger captures here!
```

#### Why Keyloggers Use It:
- ✅ Captures keystrokes from **ALL applications** (browsers, password managers, chat apps)
- ✅ Works even if the keylogger window is **hidden**
- ✅ Can **record** or even **block** keystrokes
- ✅ Operates at a low level, hard to detect

#### Legitimate Uses:
- Hotkey utilities (Discord, OBS)
- Clipboard managers
- Macro tools (AutoHotkey)
- Accessibility software (screen readers)

#### Example Code (What Keyloggers Do):
```c
// Install the hook
HHOOK hKeyboardHook = SetWindowsHookEx(
    WH_KEYBOARD_LL,           // Low-level keyboard hook
    KeyboardProc,             // Your callback function
    hInstance,                // DLL instance
    0                         // Monitor ALL threads (system-wide)
);

// Callback - gets EVERY keystroke
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        
        if (wParam == WM_KEYDOWN) {
            // Keystroke captured!
            char key = MapVirtualKey(p->vkCode, MAPVK_VK_TO_CHAR);
            LogKeyToFile(key);  // Save to file
            SendToServer(key);  // Or send over network
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}
```

**🚨 Red Flag:** If a process has this hook + no visible window + network activity → **100% keylogger behavior**

---

### 2. **Hook Without Window (Composite Detection)**

**Feature:** `hook_no_window`  
**Score Impact:** +0.25 (HIGH RISK)

#### What It Is:
Process has keyboard hooks installed **BUT** has **no visible window**.

#### Why It's Suspicious:
```
Normal App:  [Window] ← User sees it, knows it's running
Keylogger:   [Hidden] ← No window, user has no idea!
```

Legitimate apps with hooks (Discord, OBS) **always** show a window. If there's no window, the hook is **hidden from the user** → stealth behavior.

#### Detection Logic:
```python
hook_no_window = (hook_api_present == 1) AND (has_visible_window == 0)
```

**🚨 When This Triggers:**
- Background process installs keyboard hook
- No UI, no tray icon, nothing visible
- User doesn't know it exists

**Legitimate Exception:** System services (rare)

---

### 3. **Hook With Network Activity (Composite Detection)**

**Feature:** `hook_with_network`  
**Score Impact:** +0.20 (HIGH RISK)

#### What It Is:
Process has keyboard hooks **AND** active network connections.

#### Why It's Dangerous:
Classic keylogger behavior pattern:
```
1. Hook installed      → Captures keystrokes
2. Network active      → Sends data to attacker
3. Data exfiltration   → Your passwords are gone!
```

#### Attack Scenario:
```
User types password → Hook captures → Encrypt → Send to attacker.com:8080
```

#### Detection Logic:
```python
hook_with_network = (hook_api_present == 1) AND (net_connections_mean > 0)
```

**🚨 When This Triggers:**
- Process has hooks installed
- Making network connections (outbound)
- Could be sending keystrokes remotely

**Legitimate Uses:**
- Remote desktop tools (TeamViewer, AnyDesk)
- VPN clients with hotkeys
- Cloud sync tools with keyboard shortcuts

**Difference from Malicious:**
- Legitimate: User installed it knowingly, has visible window
- Malicious: Hidden, unknown origin, suspicious network destination

---

### 4. **Kernel-Mode Hooks (Driver Level)**

**Feature:** `has_kernel_hooks`  
**Score Impact:** +0.35 (CRITICAL)

#### What It Is:
A device driver running in **kernel mode** (Ring 0) that can intercept keyboard at the **lowest possible level**.

#### Privilege Levels:
```
Ring 0 (Kernel):  Full hardware access, unrestricted
Ring 3 (User):    Normal applications, restricted
```

#### How It Works:
Instead of using Windows API hooks, the malware installs a **kernel driver** that intercepts keyboard interrupts directly from the hardware.

```
Keyboard hardware → Interrupt → Kernel driver intercepts → Windows → Apps
                               ↑
                    Rootkit keylogger captures here!
```

#### Why It's More Dangerous:
- ✅ **Invisible** to normal anti-virus (operates below Windows)
- ✅ Can **hide itself** from Task Manager
- ✅ Extremely hard to detect and remove
- ✅ Persists across reboots
- ✅ Can survive system restore

#### Detection Method:
We detect suspicious kernel drivers by checking:
- Driver files in `C:\Windows\System32\drivers\`
- Loaded drivers without valid signatures
- Drivers with suspicious names (random characters)
- Drivers loading keyboard filter drivers

#### Example Attack:
Famous rootkit keyloggers:
- **Zeus Banking Trojan** - Used kernel driver to steal banking credentials
- **Carberp** - Kernel-mode keylogger + network backdoor
- **TDL4** - Bootkit that loads before Windows

**🚨 Red Flag:** Kernel drivers are **extremely rare** in normal software. If detected → almost certainly malware.

**Legitimate Uses:**
- Antivirus software (Kaspersky, BitDefender)
- Hardware drivers (Logitech, Razer gaming peripherals)
- System utilities (Process Monitor, Wireshark)

---

### 5. **Raw Input API**

**Feature:** `uses_raw_input_api`  
**Score Impact:** +0.20 (HIGH RISK)

#### What It Is:
Windows Raw Input API (`RegisterRawInputDevices`) gives **direct access** to keyboard/mouse input without using standard Windows messages.

#### How It's Different:
```
Normal Input:     Keyboard → Windows → WM_KEYDOWN message → Your app
Raw Input:        Keyboard → Windows → RegisterRawInputDevices → WM_INPUT → Your app
                                       ↑
                            Direct hardware-level access!
```

#### Why Keyloggers Use It:
- ✅ Bypasses some security software (doesn't use hooks)
- ✅ Works even when window is **hidden** or **minimized**
- ✅ Captures input from **all keyboards** (including USB, Bluetooth)
- ✅ Lower-level than standard keyboard messages

#### Example Code:
```c
// Register for raw keyboard input
RAWINPUTDEVICE rid[1];
rid[0].usUsagePage = 0x01;      // Generic Desktop
rid[0].usUsage = 0x06;          // Keyboard
rid[0].dwFlags = RIDEV_INPUTSINK; // Receive input even when hidden!
rid[0].hwndTarget = hWnd;       // Hidden window handle

RegisterRawInputDevices(rid, 1, sizeof(rid[0]));

// Now receives WM_INPUT messages with raw keystroke data
```

#### Detection Logic:
```python
uses_raw_input_api = (raw_input_registered == 1) AND (has_visible_window == 0)
```

**🚨 When This Triggers:**
- Process registered for raw input
- Window is hidden or has no UI
- Stealth keylogging behavior

**Legitimate Uses:**
- Games (reading joystick/gamepad input)
- CAD software (3D mouse input)
- Virtual machines (capturing host keyboard)

**Key Difference:**
- Legitimate: Visible window, user knows about it
- Malicious: Hidden window, raw keyboard access without user consent

---

### 6. **Hook API Present**

**Feature:** `hook_api_present`  
**Score Impact:** +0.10 (MEDIUM RISK)

#### What It Is:
Process has `user32.dll` loaded, which contains the Windows hooking APIs.

#### Why We Check This:
`user32.dll` contains:
- `SetWindowsHookEx()` - Install hooks
- `UnhookWindowsHookEx()` - Remove hooks
- `CallNextHookEx()` - Chain hook calls

If this DLL is loaded, the process **has the capability** to install hooks (but might not have actually done it yet).

#### Not Always Bad:
**Almost every** Windows GUI application loads `user32.dll` because it provides:
- Window creation
- Mouse/keyboard input
- Buttons, menus, dialogs

#### When It's Suspicious:
```python
# Alone: Not very suspicious
if hook_api_present:
    score += 0.10

# Combined with other factors: Very suspicious!
if hook_api_present AND no_visible_window:
    score += 0.25  # Hook without window

if hook_api_present AND net_connections_mean > 0:
    score += 0.20  # Hook with network
```

---

### 7. **Hook-Related DLL Count**

**Feature:** `hook_related_dll_count`  
**Score Impact:** +0.10 if ≥ 3 DLLs (MEDIUM RISK)

#### What It Is:
Count of how many hooking-related DLLs are loaded:

```python
HOOK_RELATED_DLLS = {
    "user32.dll",      # Standard Windows hooks
    "win32u.dll",      # Low-level Windows API
    "rawinput.dll",    # Raw input API
    "dinput.dll",      # DirectInput (legacy gaming)
    "dinput8.dll",     # DirectInput 8
    "hid.dll",         # Human Interface Devices
    "hidparse.sys",    # HID parser driver
}
```

#### Why Multiple DLLs Is Suspicious:
Normal apps use **one method** to read input:
- GUI app → `user32.dll` only
- Game → `dinput8.dll` only
- Device driver → `hid.dll` only

Keyloggers often load **multiple methods** as a fallback strategy:
```
Try method 1 (hooks)      → If blocked, try method 2 (raw input)
                          → If blocked, try method 3 (DirectInput)
                          → If blocked, try method 4 (HID driver)
```

**🚨 Red Flag:** If ≥ 3 DLLs loaded → Process is trying multiple input methods (suspicious)

---

## 🎯 Detection Strategy

### How We Combine Signals:

#### **Scenario 1: Hidden Keylogger**
```
✅ has_ll_keyboard_hook:        +0.40
✅ hook_no_window:               +0.25
✅ hook_with_network:            +0.20
✅ running_from_temp:            +0.15
_________________________________________
Total:                           1.00 → 🚨 MALICIOUS
```

#### **Scenario 2: Legitimate App (Discord)**
```
✅ hook_api_present:             +0.10 (for global hotkeys)
✅ has_visible_window:           -0.10 (user can see it)
✅ is_signed:                    -0.10 (verified publisher)
_________________________________________
Total:                           0.00 → ✅ SAFE
```

#### **Scenario 3: Suspicious But Not Confirmed**
```
✅ hook_api_present:             +0.10
✅ hook_related_dll_count >= 3:  +0.10
✅ net_bytes_sent_sum > 500KB:   +0.08
✅ has_startup_entry:            +0.15
_________________________________________
Total:                           0.43 → ⚠️ SUSPICIOUS
```

---

## 📚 Hook Types Reference

| Hook Type | Level | Stealth | Detection Difficulty | Used By Keyloggers |
|-----------|-------|---------|---------------------|-------------------|
| **WH_KEYBOARD_LL** | User-mode | Medium | Easy | ✅ 95% |
| **Kernel Driver** | Kernel | High | Very Hard | ✅ 80% |
| **Raw Input API** | User-mode | Medium | Medium | ✅ 60% |
| **DirectInput** | User-mode | Low | Easy | ❌ 5% (legacy) |
| **WH_KEYBOARD** | User-mode | Low | Easy | ❌ Deprecated |

---

## 🛡️ How to Protect Yourself

### As a User:
1. ✅ Only install software from trusted sources
2. ✅ Check for visible windows - hidden processes are suspicious
3. ✅ Monitor startup programs (run `msconfig`)
4. ✅ Use this detector regularly!

### As a Developer:
1. ✅ Always show a visible window if using hooks
2. ✅ Document why your app needs hooks
3. ✅ Sign your application with a certificate
4. ✅ Use hooks only when absolutely necessary

---

## 🎓 Summary Table

| Feature | What It Detects | Score | Why Dangerous |
|---------|----------------|-------|---------------|
| `has_ll_keyboard_hook` | Low-level keyboard hook | +0.40 | Captures all keystrokes system-wide |
| `hook_no_window` | Hook without visible UI | +0.25 | Stealth behavior, hidden from user |
| `hook_with_network` | Hook + network activity | +0.20 | Possible data exfiltration |
| `has_kernel_hooks` | Kernel-mode driver | +0.35 | Rootkit-level access, very dangerous |
| `uses_raw_input_api` | Raw input on hidden window | +0.20 | Advanced stealth keylogging |
| `hook_api_present` | Hooking capability | +0.10 | Has the tools to hook |
| `hook_related_dll_count` | Multiple input methods | +0.10 | Trying multiple capture techniques |

---

## 🔗 Related Documentation

- `HEURISTIC_SCORING_EXPLAINED.md` - How all features combine into a score
- `ENSEMBLE_SCORING.md` - How ML + heuristic work together
- `BEHAVIORAL_BIOMETRICS_EXPLAINER.md` - How typing patterns help detection

---

## 📖 Technical References

- [Windows Hooks Overview - Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/winmsg/about-hooks)
- [SetWindowsHookEx API](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw)
- [Raw Input API](https://docs.microsoft.com/en-us/windows/win32/inputdev/raw-input)
- [Kernel-Mode Driver Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)
