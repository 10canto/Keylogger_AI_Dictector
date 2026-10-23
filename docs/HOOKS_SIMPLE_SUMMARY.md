# 🎣 Hooks Explained - Simple Version

## What is a Hook?

A **hook** is like a **spy** that sits between your keyboard and your apps, watching (or recording) everything you type.

---

## The 7 Types We Check

### 1️⃣ **Low-Level Keyboard Hook** (+40 points)
**Feature:** `has_ll_keyboard_hook`

**What it does:**
- Captures EVERY keystroke on your entire computer
- Works even if the program is hidden
- Can record passwords, messages, everything you type

**Example:**
```
You type: "password123"
Normal app: Sees "password123"
Keylogger with hook: RECORDS "password123" first!
```

**Why it's dangerous:** 95% of keyloggers use this method

**Legitimate uses:** Discord (push-to-talk), OBS (hotkeys), AutoHotkey

---

### 2️⃣ **Hook Without Window** (+25 points)
**Feature:** `hook_no_window`

**What it means:**
- Program has keyboard hook installed
- BUT has no visible window
- Running completely hidden

**Why it's suspicious:**
- Discord shows a window → You know it's running ✅
- Hidden keylogger → You have NO IDEA it exists 🚨

---

### 3️⃣ **Hook With Network** (+20 points)
**Feature:** `hook_with_network`

**What it means:**
- Program has keyboard hook
- AND is sending data over the internet

**Attack scenario:**
```
1. You type password
2. Hook captures it
3. Sends to attacker's server
4. Your account is hacked!
```

---

### 4️⃣ **Kernel-Mode Hook** (+35 points)
**Feature:** `has_kernel_hooks`

**What it is:**
- A driver that runs BELOW Windows
- Has complete control over your computer
- Almost impossible to detect or remove

**Why it's CRITICAL:**
- Can hide itself from Task Manager
- Can't be killed by normal methods
- Survives system restore
- Used by advanced malware/rootkits

**Legitimate uses:** Antivirus software, some hardware drivers

---

### 5️⃣ **Raw Input API** (+20 points)
**Feature:** `uses_raw_input_api`

**What it is:**
- Direct hardware-level keyboard access
- Bypasses normal Windows security
- Works even when window is hidden

**Why keyloggers like it:**
- Some antivirus software doesn't detect it
- More "invisible" than regular hooks

---

### 6️⃣ **Hook API Present** (+10 points)
**Feature:** `hook_api_present`

**What it means:**
- Program loaded `user32.dll`
- Has the CAPABILITY to install hooks
- Might not have actually done it yet

**Note:** Almost every Windows program loads this DLL, so alone it's not very suspicious.

---

### 7️⃣ **Multiple Hook DLLs** (+10 points)
**Feature:** `hook_related_dll_count >= 3`

**What it means:**
- Program loaded 3+ different input-related DLLs
- Trying multiple methods to capture keystrokes

**Why it's suspicious:**
- Normal apps use ONE method
- Keyloggers try MULTIPLE methods as backup

**Think of it like:**
- Normal person: Uses front door
- Burglar: Tries front door, back door, window, chimney...

---

## 🎯 Quick Examples

### Example 1: **Brave Browser** ✅
```
✅ Visible window         (You can see it)
✅ Digitally signed       (Verified publisher)
✅ No hooks installed     (Just normal input)
─────────────────────────
Score: 0%  → ✅ SAFE
```

### Example 2: **Discord** ✅
```
⚠️ Keyboard hook          +10 points (for hotkeys)
✅ Visible window         -10 points
✅ Digitally signed       -10 points
─────────────────────────
Score: 0%  → ✅ SAFE
```

### Example 3: **Hidden Keylogger** 🚨
```
🔴 Keyboard hook          +40 points
🔴 No visible window      +25 points
🔴 Network activity       +20 points
🔴 Running from TEMP      +15 points
─────────────────────────
Score: 100%  → 🚨 MALICIOUS
```

---

## 🛡️ How to Stay Safe

### As a User:
1. ✅ Check if unknown programs are running hooks
2. ✅ Be suspicious of programs with no visible window
3. ✅ Only install software from trusted sources
4. ✅ Run this detector regularly!

### Red Flags to Watch For:
- 🚩 Program you don't recognize
- 🚩 No visible window or tray icon
- 🚩 High network usage for no reason
- 🚩 Found in TEMP folder
- 🚩 Not digitally signed

---

## 📊 Threat Levels

| Hook Type | Danger Level | Common? |
|-----------|--------------|---------|
| Low-Level Keyboard Hook | 🔴 HIGH | Very common |
| Kernel Driver | 🔴 CRITICAL | Rare but deadly |
| Raw Input API | 🟡 MEDIUM | Uncommon |
| Multiple Methods | 🟠 HIGH | Very suspicious |

---

## 🎓 Remember:

1. **Hooks aren't always bad** - Many legitimate programs use them
2. **Context matters** - Hidden + network = very bad
3. **Trust your detector** - It checks all these signals automatically
4. **When in doubt** - If score is high (>50%), investigate!

---

## 📚 Want More Details?

- **Full technical explanation:** `HOOKS_EXPLAINED.md`
- **How scoring works:** `HEURISTIC_SCORING_EXPLAINED.md`
- **ML + Heuristic combo:** `ENSEMBLE_SCORING.md`

---

## One-Sentence Summary

**A hook is a program's ability to spy on your keystrokes before they reach other apps - we detect 7 different types and assign threat scores based on how suspicious the behavior is.**
