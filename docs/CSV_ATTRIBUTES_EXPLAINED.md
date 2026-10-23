# 📊 Behavior Recording CSV - All 32 Columns Explained

## Quick Reference

Your behavior CSV file has **32 columns total**:
- **5 metadata columns** (identification, not used for ML)
- **26 feature columns** (used for ML training and detection)
- **1 label column** (training target: safe/suspicious/malicious)

---

## Column-by-Column Breakdown

### 🏷️ **Column 1: timestamp**
- **What:** When the process was observed
- **Example:** `2026-10-23 16:35:06`
- **Used for:** Timeline analysis
- **ML Training:** ❌ No

### 📝 **Column 2: process_name**
- **What:** Executable filename
- **Example:** `msedgewebview2.exe`, `epicwebhelper.exe`
- **Used for:** Human identification
- **ML Training:** ❌ No

### 🔢 **Column 3: pid**
- **What:** Process ID (unique identifier while running)
- **Example:** `17092`, `6892`
- **Used for:** Tracking processes
- **ML Training:** ❌ No

### 📂 **Column 4: exe_path**
- **What:** Full path to executable
- **Example:** `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\...\msedgewebview2.exe`
- **Used for:** Verification, location analysis
- **ML Training:** ❌ No (but location affects other features)

### 👨‍👦 **Column 5: parent_name**
- **What:** Process that launched this one
- **Example:** `epicgameslauncher.exe`
- **Used for:** Understanding process hierarchy
- **ML Training:** ❌ No

---

## 🎯 **ML FEATURES START HERE** (26 Features)

### 🎣 **Group A: Hook & API Signals**

#### **Column 6: hook_api_present** ✅ Feature #1
- **Type:** Binary (0.0 or 1.0)
- **What:** Has `user32.dll` loaded (hooking capability)
- **Heuristic:** +0.10 points
- **Your data:** `0.0` = No hooks, `1.0` = Has hook APIs

#### **Column 7: has_ll_keyboard_hook** ✅ Feature #2
- **Type:** Binary (0.0 or 1.0)
- **What:** Low-level keyboard hook installed (WH_KEYBOARD_LL)
- **Heuristic:** +0.40 points (CRITICAL)
- **Your data:** `0.0` = Good! No keyboard hooks detected

#### **Column 8: hook_related_dll_count** ✅ Feature #3
- **Type:** Integer (0-7)
- **What:** Number of hook-related DLLs loaded
- **Heuristic:** +0.10 if ≥3
- **Your data:** `0.0` or `3.0` (Epic loads 3 for UI)

---

### 👁️ **Group B: Visibility & UI**

#### **Column 9: has_visible_window** ✅ Feature #4
- **Type:** Binary (0.0 or 1.0)
- **What:** Has at least one visible window
- **Heuristic:** -0.10 points (REDUCES threat if visible)
- **Your data:** `0.0` = Background helpers (normal)

#### **Column 10: window_count** ✅ Feature #5
- **Type:** Integer (0+)
- **What:** Number of visible windows owned
- **Your data:** `0.0` = Helper processes don't need windows

---

### 💻 **Group C: Resource Behavior** (8 Features)

#### **Column 11: cpu_mean** ✅ Feature #6
- **Type:** Float (0-100%)
- **What:** Average CPU usage
- **Your data:** `0.0` = Idle

#### **Column 12: cpu_max** ✅ Feature #7
- **Type:** Float (0-100%)
- **What:** Peak CPU usage
- **Your data:** `0.0` = No CPU spikes

#### **Column 13: mem_rss_mb_mean** ✅ Feature #8
- **Type:** Float (MB)
- **What:** Average memory usage
- **Your data:** `40.33` to `151.48` MB (normal for helpers)

#### **Column 14: file_write_bytes_sum** ✅ Feature #9
- **Type:** Float (bytes)
- **What:** Total bytes written to disk
- **Heuristic:** Watch for excessive logging
- **Your data:** `0.0` = No writes during observation

#### **Column 15: file_write_rate** ✅ Feature #10
- **Type:** Float (bytes/second)
- **What:** Write speed to disk
- **Heuristic:** +0.05 if >50,000 bytes/sec
- **Your data:** `0.0` = No active writing

#### **Column 16: open_file_count_mean** ✅ Feature #11
- **Type:** Float (count)
- **What:** Average open file handles
- **Your data:** `8.0` = Normal

#### **Column 17: net_connections_mean** ✅ Feature #12
- **Type:** Float (count)
- **What:** Average network connections
- **Your data:** `0.0` = No network during observation

#### **Column 18: net_bytes_sent_sum** ✅ Feature #13
- **Type:** Float (bytes)
- **What:** Total network bytes sent
- **Heuristic:** +0.08 if >500,000 bytes
- **Your data:** `0.0` = No network traffic

---

### 🔒 **Group D: Binary Trust**

#### **Column 19: is_signed** ✅ Feature #14
- **Type:** Binary (0.0 or 1.0)
- **What:** Has digital signature (Authenticode)
- **Heuristic:** -0.10 points (REDUCES threat)
- **Your data:** `0.0` = Not signed (but from trusted locations)

#### **Column 20: is_system_process** ✅ Feature #15
- **Type:** Binary (0.0 or 1.0)
- **What:** Windows system component
- **Heuristic:** -0.30 points (major trust boost)
- **Your data:** `0.0` = Third-party apps

---

### 🔁 **Group E: Persistence**

#### **Column 21: has_startup_entry** ✅ Feature #16
- **Type:** Binary (0.0 or 1.0)
- **What:** Has registry startup entry
- **Heuristic:** +0.15 points
- **Your data:** `0.0` = Not in startup

---

### 📂 **Group F: Process Metadata** (6 Features)

#### **Column 22: no_exe_path** ✅ Feature #17
- **Type:** Binary (0.0 or 1.0)
- **What:** Executable path is missing
- **Heuristic:** +0.10 points
- **Your data:** `0.0` = Paths present

#### **Column 23: cmdline_empty** ✅ Feature #18
- **Type:** Binary (0.0 or 1.0)
- **What:** No command-line arguments
- **Heuristic:** +0.07 if also has hooks
- **Your data:** `1.0` = No arguments (common for helpers)

#### **Column 24: name_length** ✅ Feature #19
- **Type:** Integer (characters)
- **What:** Length of process name
- **Your data:** `17` to `18` characters

#### **Column 25: running_from_temp** ✅ Feature #20
- **Type:** Binary (0.0 or 1.0)
- **What:** Running from %TEMP% folder
- **Heuristic:** +0.15 points (SUSPICIOUS)
- **Your data:** `0.0` = In Program Files ✅

#### **Column 26: running_from_appdata** ✅ Feature #21
- **Type:** Binary (0.0 or 1.0)
- **What:** Running from AppData folder
- **Your data:** `0.0` = Not in AppData

#### **Column 27: age_seconds** ✅ Feature #22
- **Type:** Float (seconds)
- **What:** How long process has been running
- **Your data:** `1.124` to `2.163` seconds (newly started)

---

### 🎯 **Group G: Composite Signals** (Derived Features)

#### **Column 28: hook_no_window** ✅ Feature #23
- **Type:** Binary (0.0 or 1.0)
- **Formula:** `hook_api_present AND NOT has_visible_window`
- **What:** Hook installed but hidden from user
- **Heuristic:** +0.25 points (HIGH RISK)
- **Your data:** `1.0` for Epic helpers (background service, legitimate)

#### **Column 29: hook_with_network** ✅ Feature #24
- **Type:** Binary (0.0 or 1.0)
- **Formula:** `hook_api_present AND net_connections_mean > 0`
- **What:** Hook + network activity (data exfiltration?)
- **Heuristic:** +0.20 points (HIGH RISK)
- **Your data:** `0.0` = No network during observation ✅

---

### 🔬 **Group H: Extended Detection**

#### **Column 30: has_kernel_hooks** ✅ Feature #25
- **Type:** Binary (0.0 or 1.0)
- **What:** Kernel-mode driver detected (rootkit)
- **Heuristic:** +0.35 points (CRITICAL)
- **Your data:** `0.0` = No kernel drivers ✅

#### **Column 31: uses_raw_input_api** ✅ Feature #26
- **Type:** Binary (0.0 or 1.0)
- **What:** Raw keyboard input registered
- **Heuristic:** +0.20 points (HIGH RISK)
- **Your data:** `0.0` = Not using raw input ✅

---

### 🏷️ **Training Target**

#### **Column 32: label**
- **Type:** Category (string)
- **Values:** `"safe"`, `"suspicious"`, `"malicious"`
- **What:** Ground truth for training
- **Your data:** All marked as `"safe"` (your normal behavior)

---

## 📊 Quick Feature Checklist

**✅ Safe Indicators in Your Data:**
- No keyboard hooks (has_ll_keyboard_hook = 0.0)
- No kernel drivers (has_kernel_hooks = 0.0)
- No raw input (uses_raw_input_api = 0.0)
- Not from TEMP folder (running_from_temp = 0.0)
- No data exfiltration (net_bytes_sent_sum = 0.0)

**⚠️ Moderate Signals in Your Data:**
- Some hook APIs loaded (normal for GUI apps)
- No visible windows (background helpers, expected)
- Not digitally signed (but in trusted locations)

**🎯 This is GOOD training data because:**
1. Real applications you actually use
2. Mix of different behaviors
3. All confirmed safe
4. Teaches ML what YOUR normal workflow looks like

---

## 🧮 How Scores Are Calculated

### Heuristic Model:
```python
score = 0.0

# Add red flags
if has_ll_keyboard_hook:       score += 0.40
if hook_no_window:              score += 0.25
if hook_with_network:           score += 0.20
if has_kernel_hooks:            score += 0.35
if uses_raw_input_api:          score += 0.20
if running_from_temp:           score += 0.15
if has_startup_entry:           score += 0.15
# ... (more rules)

# Subtract green flags
if is_system_process:           score -= 0.30
if has_visible_window:          score -= 0.10
if is_signed:                   score -= 0.10

return clamp(score, 0.0, 1.0)
```

### ML Model:
- Uses ALL 26 features simultaneously
- Learns complex patterns from training data
- 99% accuracy after training

### Ensemble (Your Current System):
```python
ml_score = random_forest.predict(all_26_features)
heuristic_score = rule_based_scoring(all_26_features)

if heuristic_score >= 0.60:
    final_score = max(ml_score, heuristic_score)  # Trust strong signals
else:
    final_score = 0.80 * ml_score + 0.20 * heuristic_score  # Trust ML more
```

---

## 📈 Example from Your Data

**Epic Web Helper (epicwebhelper.exe):**

```
Features:
  hook_api_present:       1.0   (+0.10)
  hook_related_dll_count: 3.0   (+0.10)
  hook_no_window:         1.0   (+0.25)
  has_visible_window:     0.0   (no reduction)
  is_signed:              0.0   (no reduction)
  running_from_temp:      0.0   (no addition)
  has_ll_keyboard_hook:   0.0   (no addition)
  hook_with_network:      0.0   (no addition)
  
Heuristic Score: 0.10 + 0.10 + 0.25 = 0.45
Risk Level: ✅ SAFE (< 0.50 threshold)

ML Score: (trained on 1000+ samples)
Final Ensemble: ~0.10-0.30 → ✅ SAFE

Why it's safe:
✓ From Epic Games (legitimate publisher)
✓ No network activity
✓ No keyboard hooks
✓ Known background service
```

---

## 🎓 Summary

- **32 total columns** in your CSV
- **26 are ML features** that detect threats
- **6 are metadata** for identification
- **1 is the label** (safe/suspicious/malicious)

All features work together to create a complete behavioral profile of each process!

---

## 📚 Related Docs

- **Feature scoring:** `HEURISTIC_SCORING_EXPLAINED.md`
- **Hook types:** `HOOKS_EXPLAINED.md`  
- **ML + Heuristic:** `ENSEMBLE_SCORING.md`
