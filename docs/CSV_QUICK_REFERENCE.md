# 📊 CSV Attributes Quick Reference

## 32 Columns Total

### 🏷️ Metadata (5 columns) - Not used for ML
1. `timestamp` - When observed
2. `process_name` - Executable name
3. `pid` - Process ID
4. `exe_path` - Full file path
5. `parent_name` - Parent process

---

### 🤖 ML Features (26 columns) - Used for detection

| # | Feature | Type | What It Detects | Score |
|---|---------|------|-----------------|-------|
| **GROUP A: HOOKS** |
| 6 | `hook_api_present` | Binary | Has hooking capability | +0.10 |
| 7 | `has_ll_keyboard_hook` | Binary | 🚨 Keyboard hook active | **+0.40** |
| 8 | `hook_related_dll_count` | Integer | Multiple hook methods | +0.10 if ≥3 |
| **GROUP B: VISIBILITY** |
| 9 | `has_visible_window` | Binary | User can see it | **-0.10** ✅ |
| 10 | `window_count` | Integer | Number of windows | - |
| **GROUP C: RESOURCES** |
| 11 | `cpu_mean` | Float | Average CPU % | - |
| 12 | `cpu_max` | Float | Peak CPU % | - |
| 13 | `mem_rss_mb_mean` | Float | Average memory MB | - |
| 14 | `file_write_bytes_sum` | Float | Total disk writes | - |
| 15 | `file_write_rate` | Float | Write speed | +0.05 if >50K/s |
| 16 | `open_file_count_mean` | Float | Open files | - |
| 17 | `net_connections_mean` | Float | Network connections | - |
| 18 | `net_bytes_sent_sum` | Float | Network bytes sent | +0.08 if >500K |
| **GROUP D: TRUST** |
| 19 | `is_signed` | Binary | Digital signature | **-0.10** ✅ |
| 20 | `is_system_process` | Binary | Windows system | **-0.30** ✅ |
| **GROUP E: PERSISTENCE** |
| 21 | `has_startup_entry` | Binary | Auto-starts | +0.15 |
| **GROUP F: METADATA** |
| 22 | `no_exe_path` | Binary | Missing path | +0.10 |
| 23 | `cmdline_empty` | Binary | No arguments | +0.07 with hooks |
| 24 | `name_length` | Integer | Name length | - |
| 25 | `running_from_temp` | Binary | 🚨 In TEMP folder | **+0.15** |
| 26 | `running_from_appdata` | Binary | In AppData | - |
| 27 | `age_seconds` | Float | Process age | - |
| **GROUP G: COMPOSITE** |
| 28 | `hook_no_window` | Binary | 🚨 Hidden hook | **+0.25** |
| 29 | `hook_with_network` | Binary | 🚨 Hook + network | **+0.20** |
| **GROUP H: ADVANCED** |
| 30 | `has_kernel_hooks` | Binary | 🚨 Kernel driver | **+0.35** |
| 31 | `uses_raw_input_api` | Binary | 🚨 Raw input | **+0.20** |

---

### 🎯 Label (1 column) - Training target
32. `label` - `"safe"` / `"suspicious"` / `"malicious"`

---

## 🚨 Critical Red Flags

| Feature | Value | Meaning | Action |
|---------|-------|---------|--------|
| `has_ll_keyboard_hook` | 1.0 | Keyboard hook | Investigate |
| `has_kernel_hooks` | 1.0 | Rootkit driver | **Alert!** |
| `hook_no_window` | 1.0 | Hidden hook | Investigate |
| `hook_with_network` | 1.0 | Data exfiltration? | **Alert!** |
| `running_from_temp` | 1.0 | Suspicious location | Investigate |

---

## ✅ Green Flags (Good Signs)

| Feature | Value | Meaning | Effect |
|---------|-------|---------|--------|
| `is_signed` | 1.0 | Verified publisher | -0.10 |
| `has_visible_window` | 1.0 | User can see it | -0.10 |
| `is_system_process` | 1.0 | Windows trusted | **-0.30** |

---

## 📈 Score Thresholds

| Score Range | Risk Level | Action |
|-------------|------------|--------|
| 0.00 - 0.49 | ✅ SAFE | Normal |
| 0.50 - 0.89 | ⚠️ SUSPICIOUS | Monitor |
| 0.90 - 1.00 | 🚨 MALICIOUS | Alert |

---

## 🎯 Your Data Example

**Epic Web Helper (from your CSV):**
```
hook_api_present:       1.0  (has capability)
hook_related_dll_count: 3.0  (3 DLLs)
hook_no_window:         1.0  (background service)
has_ll_keyboard_hook:   0.0  (no actual hook) ✅
running_from_temp:      0.0  (in Program Files) ✅
hook_with_network:      0.0  (no network) ✅

Heuristic: 0.45 → ✅ SAFE
ML Model: ~0.20 → ✅ SAFE
```

---

## 💡 Quick Tips

### Good Training Data Has:
✅ Mix of applications (browsers, games, tools)  
✅ Different behaviors (some hooks, some none)  
✅ All confirmed safe (your real usage)  
✅ At least 100+ processes recorded

### Red Flags in Data:
🚩 Unknown processes from TEMP  
🚩 Keyboard hooks you didn't know about  
🚩 High network + hooks combination  
🚩 Kernel drivers you didn't install

---

## 🔍 How to Read Your CSV

1. **Open in Excel/LibreOffice**
2. **Sort by features:**
   - `has_ll_keyboard_hook` = 1.0 → Check if expected
   - `running_from_temp` = 1.0 → Investigate
   - `hook_with_network` = 1.0 → Verify legitimate
3. **Check all processes are recognized**
4. **Verify all labels are "safe"**

---

## 📚 Full Documentation

- **Detailed explanation:** `CSV_ATTRIBUTES_EXPLAINED.md`
- **How scoring works:** `HEURISTIC_SCORING_EXPLAINED.md`
- **Hook types:** `HOOKS_EXPLAINED.md`
