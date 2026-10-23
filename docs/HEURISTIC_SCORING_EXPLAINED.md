# 🔍 Heuristic Scoring System - How It Works

## Overview

The **heuristic model** is a rule-based scoring system that analyzes **28 behavioral features** of each process and assigns a threat score from **0.0 (safe) to 1.0 (malicious)**.

---

## 📊 How Scoring Works

The heuristic starts at `score = 0.0` and:
- **Adds points** for suspicious behaviors (red flags)
- **Subtracts points** for benign traits (green flags)
- **Final score** is clamped between 0.0 and 1.0

```
Final Score = (Red Flags) - (Green Flags)
Clamped to range [0.0, 1.0]
```

---

## 🚨 Red Flags (Suspicious Behaviors)

### 🔴 **CRITICAL THREATS** (0.35-0.40 points each)

| Feature | Score | What It Means | Why It's Dangerous |
|---------|-------|---------------|-------------------|
| **has_kernel_hooks** | +0.35 | Kernel-mode driver loaded | Very rare, rootkit-level access |
| **has_ll_keyboard_hook** | +0.40 | Low-level keyboard hook installed | Classic keylogger signature |

**Example:** If a process has both → `0.35 + 0.40 = 0.75` → 🚨 **MALICIOUS**

---

### 🟠 **HIGH RISK** (0.20-0.25 points each)

| Feature | Score | What It Means | Why Suspicious |
|---------|-------|---------------|----------------|
| **hook_no_window** | +0.25 | Keyboard hook but NO visible window | Stealth behavior - hiding from user |
| **hook_with_network** | +0.20 | Keyboard hook + network activity | Sending keystrokes over network |
| **uses_raw_input_api** | +0.20 | Raw input API + hidden window | Advanced stealth keylogging |

**Example:** Hidden hook + network → `0.25 + 0.20 = 0.45` → ⚠️ **SUSPICIOUS**

---

### 🟡 **MEDIUM RISK** (0.10-0.15 points each)

| Feature | Score | What It Means | Why Concerning |
|---------|-------|---------------|----------------|
| **has_startup_entry** | +0.15 | Added to registry Run keys | Persistence mechanism |
| **running_from_temp** | +0.15 | Running from %TEMP% folder | Malware often runs from temp |
| **no_exe_path** | +0.10 | Missing executable path | Suspicious/hidden process |
| **hook_api_present** | +0.10 | user32.dll loaded | Possible hooking capability |
| **hook_related_dll_count ≥ 3** | +0.10 | 3+ hook-related DLLs | Multiple hooking methods |

---

### 🟢 **LOW RISK** (0.05-0.08 points each)

| Feature | Score | Threshold | What It Detects |
|---------|-------|-----------|-----------------|
| **net_bytes_sent_sum** | +0.08 | > 500 KB | Heavy data exfiltration |
| **file_write_rate** | +0.05 | > 50 KB/sec | Excessive file writes (logging?) |
| **cmdline_empty + hook_api_present** | +0.07 | Both true | Hidden hook with no args |

---

## ✅ Green Flags (Benign Traits)

These **reduce** the threat score:

| Feature | Score | What It Means | Why It's Good |
|---------|-------|---------------|---------------|
| **is_system_process** | **-0.30** | Windows system process | Trusted by OS |
| **has_visible_window** | **-0.10** | Has a visible UI window | Transparent to user |
| **is_signed** | **-0.10** | Digitally signed binary | Verified publisher |

**Example:** Legitimate app with window + signed → `0.50 - 0.10 - 0.10 = 0.30` → ✅ **SAFE**

---

## 📈 Real-World Examples

### Example 1: **Brave Browser** (Legitimate)
```
Features detected:
✅ is_signed: -0.10
✅ has_visible_window: -0.10
⚠️ hook_api_present: +0.10 (for UI input)

Score = 0.10 - 0.10 - 0.10 = 0.00 (clamped)
Result: ✅ SAFE (0%)
```

---

### Example 2: **Suspicious Unknown App**
```
Features detected:
🔴 has_ll_keyboard_hook: +0.40
🟠 hook_no_window: +0.25
🟡 running_from_temp: +0.15
🟡 no_exe_path: +0.10

Score = 0.40 + 0.25 + 0.15 + 0.10 = 0.90
Result: 🚨 MALICIOUS (90%)
```

---

### Example 3: **Discord (Signed App with Hooks)**
```
Features detected:
⚠️ hook_api_present: +0.10 (for global hotkeys)
🟢 has_kernel_hooks: +0.00 (none)
✅ is_signed: -0.10
✅ has_visible_window: -0.10

Score = 0.10 - 0.10 - 0.10 = 0.00 (clamped)
Result: ✅ SAFE (0%)
```

---

### Example 4: **Advanced Keylogger**
```
Features detected:
🔴 has_kernel_hooks: +0.35 (rootkit driver)
🔴 has_ll_keyboard_hook: +0.40
🟠 hook_with_network: +0.20
🟡 cmdline_empty + hook_api: +0.07
🟡 running_from_temp: +0.15

Score = 0.35 + 0.40 + 0.20 + 0.07 + 0.15 = 1.17 → clamped to 1.00
Result: 🚨 MALICIOUS (100%)
```

---

## 🎯 Score Thresholds

After calculating the score:

| Score Range | Risk Level | Display |
|-------------|------------|---------|
| **0.00 - 0.49** | ✅ SAFE | Green, normal operation |
| **0.50 - 0.89** | ⚠️ SUSPICIOUS | Yellow, monitor closely |
| **0.90 - 1.00** | 🚨 MALICIOUS | Red, alert user |

---

## 🔧 The 28 Features Analyzed

### **Group A: Hook & API Signals**
1. `hook_api_present` - user32.dll loaded
2. `has_ll_keyboard_hook` - Low-level keyboard hook
3. `hook_related_dll_count` - Count of hook DLLs

### **Group B: Visibility / UI**
4. `has_visible_window` - Process has visible window
5. `window_count` - Number of windows

### **Group C: Resource Behavior**
6. `cpu_mean` - Average CPU usage
7. `cpu_max` - Peak CPU usage
8. `mem_rss_mb_mean` - Average memory MB
9. `file_write_bytes_sum` - Total file writes
10. `file_write_rate` - Writes per second
11. `open_file_count_mean` - Average open files
12. `net_connections_mean` - Average network connections
13. `net_bytes_sent_sum` - Total network bytes sent

### **Group D: Binary Trust**
14. `is_signed` - Digital signature present
15. `is_system_process` - Windows system process

### **Group E: Persistence**
16. `has_startup_entry` - Registry Run key entry

### **Group F: Process Metadata**
17. `no_exe_path` - Missing executable path
18. `cmdline_empty` - Empty command line
19. `name_length` - Process name length
20. `running_from_temp` - Running from temp folder
21. `running_from_appdata` - Running from AppData
22. `age_seconds` - Process age

### **Group G: Composite Signals**
23. `hook_no_window` - Hook without window (stealth)
24. `hook_with_network` - Hook with network activity

### **Group H: Advanced Detection**
25. `has_kernel_hooks` - Kernel-mode driver detected
26. `uses_raw_input_api` - Raw input API usage

---

## 🤖 ML + Heuristic Ensemble

When **both ML and heuristic** are active (your current setup):

```python
# Get both scores
ml_score = model.predict(...)       # Machine Learning
heuristic_score = _heuristic_score(features)

# Combine intelligently
if heuristic_score >= 0.60:
    # Strong threat detected by rules → trust it
    final = max(ml_score, heuristic_score)
else:
    # Normal case → trust ML more
    final = 0.80 × ml_score + 0.20 × heuristic_score
```

### Why This Works:
- **ML** learns subtle patterns from training data
- **Heuristic** catches classic threats with strong signals
- **Ensemble** takes best of both worlds

---

## 📖 Code Location

**File:** `src/classifier.py`  
**Function:** `_heuristic_score()` (line ~129)  
**Features:** `src/feature_extractor.py` (line ~73-100)

---

## 🎓 Summary

The heuristic model works by:

1. ✅ **Extracting 28 features** from each running process
2. ✅ **Applying security rules** - adding/subtracting points
3. ✅ **Computing final score** - 0.0 (safe) to 1.0 (malicious)
4. ✅ **Comparing to thresholds** - SAFE / SUSPICIOUS / MALICIOUS

**Key Insight:** Multiple weak signals (0.10-0.15 each) can add up to trigger alerts, even if no single feature is highly suspicious. This mimics how security experts think!
