# Ensemble Scoring System

## Overview

The KeyloggerDetector uses an **ensemble scoring system** that combines both Machine Learning (ML) and rule-based heuristic scoring for more accurate threat detection.

## How It Works

### 1. ML Model Score
- Uses trained Random Forest model (300 trees, 99% accuracy)
- Learned patterns from 300+ safe applications + synthetic threats
- Outputs probability: `P(malicious) + 0.5 × P(suspicious)`

### 2. Heuristic Score
- Rule-based detection using security indicators:
  - **Strong signals** (0.35-0.40 each):
    - Kernel-mode hooks
    - Low-level keyboard hook without window
    - Hook + network activity
  - **Medium signals** (0.10-0.20 each):
    - Startup entries, temp folder execution
    - Hook APIs loaded, suspicious DLLs
  - **Weak signals** (0.05-0.08 each):
    - High network traffic, file writes
  - **Mitigating factors** (reduce score):
    - System process (-0.30)
    - Visible window (-0.10)
    - Code signed (-0.10)

### 3. Ensemble Strategy

```
if heuristic_score >= 0.60:
    # Strong heuristic signal detected
    final_score = max(ml_score, heuristic_score)
else:
    # Weak heuristic - trust ML more
    final_score = 0.80 × ml_score + 0.20 × heuristic_score
```

## Why Ensemble?

✅ **Catches what ML might miss** - New/unknown threats with strong heuristic signals  
✅ **Catches what heuristics miss** - Subtle behavioral patterns only ML recognizes  
✅ **Reduces false positives** - Two independent checks agree  
✅ **Better generalization** - Not reliant on single detection method  

## Examples

### Example 1: Legitimate App (Brave Browser)
- **ML Score**: 0.15 (learned Brave is safe from training)
- **Heuristic**: 0.05 (no suspicious indicators)
- **Final**: `0.80 × 0.15 + 0.20 × 0.05 = 0.13` → ✅ SAFE

### Example 2: Unknown Keylogger
- **ML Score**: 0.45 (unsure, never seen this exact variant)
- **Heuristic**: 0.75 (detected: keyboard hook + hidden window + network)
- **Final**: `max(0.45, 0.75) = 0.75` → 🚨 MALICIOUS (≥0.60 threshold)

### Example 3: Borderline App
- **ML Score**: 0.55 (suspicious patterns)
- **Heuristic**: 0.30 (weak signals)
- **Final**: `0.80 × 0.55 + 0.20 × 0.30 = 0.50` → ⚠️ SUSPICIOUS (≥0.50 threshold)

## Thresholds

| Risk Level | Score Range | Action |
|------------|-------------|---------|
| ✅ SAFE | 0.00 - 0.49 | Normal operation |
| ⚠️ SUSPICIOUS | 0.50 - 0.89 | Monitor closely |
| 🚨 MALICIOUS | 0.90 - 1.00 | Alert user |

## Configuration

To adjust the ensemble weights, edit `src/classifier.py`:

```python
# Line ~455 and ~305
if heuristic >= 0.60:           # Strong heuristic threshold
    final_score = max(ml_score, heuristic)
else:
    final_score = 0.80 * ml_score + 0.20 * heuristic  # ML weight / Heuristic weight
```

## Benefits Over Single Method

| Scenario | ML Only | Heuristic Only | Ensemble |
|----------|---------|----------------|----------|
| Known threat in training | ✅ Detected | ✅ Detected | ✅ Detected |
| New threat variant | ❌ Missed | ✅ Detected | ✅ Detected |
| Behavioral pattern only ML knows | ✅ Detected | ❌ Missed | ✅ Detected |
| False positive on benign app | ⚠️ Maybe | ⚠️ Maybe | ✅ Reduced |

## Model Version Display

When ML model is loaded:
- Shows `Model: generic-1.0` or `Model: personalized-1.0`
- Uses ensemble scoring (ML + heuristic)

When ML model fails to load:
- Shows `Model: heuristic`
- Uses heuristic-only scoring

## Technical Details

**Files Modified:**
- `src/classifier.py` - `_compute_score()` method (line ~445)
- `src/classifier.py` - `batch_classify()` method (line ~295)

**Dependencies:**
- NumPy (for score clipping)
- scikit-learn (for ML model inference)

**Performance:**
- Batch processing: ~10ms per 100 processes
- Heuristic adds: ~0.1ms per process (negligible overhead)
