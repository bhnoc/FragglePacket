# FragglePacket - TUI User Flow Diagram

## Visual Navigation Map

```
                            ┌─────────────────────────────────┐
                            │     FragglePacket v0.2.0        │
                            │         (No Args)               │
                            └────────────────┬────────────────┘
                                             │
                                             ▼
                    ╔════════════════════════════════════════════╗
                    ║          DASHBOARD (Mode: DASHBOARD)        ║
                    ║                                            ║
                    ║  ┌──────────────┬──────────────────────┐  ║
                    ║  │ RESULTS      │  VERDICT/PROGRESS    │  ║
                    ║  │ Table:       │  ┌────────────────┐  │  ║
                    ║  │ • Google DNS │  │ STATUS: PASS   │  ║
                    ║  │ • GitHub     │  │ Median: 1500   │  ║
                    ║  │ • M365       │  └────────────────┘  │  ║
                    ║  │ ▶ Selected   │  ┌────────────────┐  │  ║
                    ║  └──────────────┤  │ Progress: 35%  │  ║
                    ║                 │  └────────────────┘  │  ║
                    ║                 └──────────────────────┘  ║
                    ║                                            ║
                    ║  [MODE: DASHBOARD]                         ║
                    ║  [?]Help [1]Dash [T]Tests [F]Fuzz [H]HTTPS║
                    ╚════════════════════════════════════════════╝
                              │  │  │   │    │    │    │
              ┌───────────────┘  │  │   │    │    │    └─────────┐
              │                  │  │   │    │    │              │
              ▼                  │  │   │    │    │              ▼
    ┌─────────────────┐          │  │   │    │    │      ┌─────────────┐
    │ [ESC] Returns   │          │  │   │    │    │      │   [q] Quit  │
    │  to Dashboard   │          │  │   │    │    │      └─────────────┘
    └─────────────────┘          │  │   │    │    │
                                 │  │   │    │    │
         [1] ─────────────────── ┘  │   │    │    │
         (Already here)             │   │    │    │
                                    │   │    │    │
         [Enter] ────────────────── ┘   │    │    │
              │                         │    │    │
              ▼                         │    │    │
    ╔═══════════════════════════════╗   │    │    │
    ║   TARGET DETAIL               ║   │    │    │
    ║   (Mode: DETAIL)              ║   │    │    │
    ║                               ║   │    │    │
    ║  Target: github.com           ║   │    │    │
    ║  ┌─────────────────────────┐  ║   │    │    │
    ║  │ MTU Results:            │  ║   │    │    │
    ║  │ ICMP: 1500 bytes        │  ║   │    │    │
    ║  │  ↳ 20 IP + 8 ICMP +    │  ║   │    │    │
    ║  │    1472 payload         │  ║   │    │    │
    ║  │ TCP:  1500 bytes        │  ║   │    │    │
    ║  │  ↳ 20 IP + 20 TCP +    │  ║   │    │    │
    ║  │    1460 payload         │  ║   │    │    │
    ║  └─────────────────────────┘  ║   │    │    │
    ║                               ║   │    │    │
    ║  [t] Run tracepath (popup)    ║   │    │    │
    ║  [r] Retest this target       ║   │    │    │
    ║  [ESC] Back                   ║   │    │    │
    ╚═══════════════════════════════╝   │    │    │
                                        │    │    │
         [3] ────────────────────────── ┘    │    │
              │                              │    │
              ▼                              │    │
    ╔═══════════════════════════════╗        │    │
    ║   MTU SIMULATOR               ║        │    │
    ║   (Mode: SIMULATOR)           ║        │    │
    ║                               ║        │    │
    ║  Simulated MTU: 1400          ║        │    │
    ║  [◀────────▒▒▒▒─────▶]        ║        │    │
    ║  Use ←/→ to adjust            ║        │    │
    ║                               ║        │    │
    ║  Impact Analysis:             ║        │    │
    ║  • GitHub: WOULD WORK ✓       ║        │    │
    ║  • Teams:  WOULD FAIL ✗       ║        │    │
    ║                               ║        │    │
    ║  [ESC] Back                   ║        │    │
    ╚═══════════════════════════════╝        │    │
                                             │    │
         [T] ─────────────────────────────── ┘    │
              │                                   │
              ▼                                   │
    ╔═══════════════════════════════════════╗    │
    ║   TEST PANEL                          ║    │
    ║   (Mode: TESTS [Single/All])          ║    │
    ║                                       ║    │
    ║  Test Categories:                     ║    │
    ║  [1] DNS  [2] MTU   [3] HTTPS        ║    │
    ║  [4] TCP  [5] RTT   [6] Loss         ║    │
    ║  [7] Path [8] IPv6  [9] App          ║    │
    ║              [0] Fuzzing              ║    │
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║    │
    ║  Results for: DNS (github.com)        ║    │
    ║  ✓ DNS Resolution: 15.3ms             ║    │
    ║  ✓ EDNS0 Support: Yes                 ║    │
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║    │
    ║                                       ║    │
    ║  [1-0] Select category                ║    │
    ║  [Enter] Run test (single/all)        ║    │
    ║  [A] Run ALL tests on current target  ║    │
    ║  [Tab] Toggle Single ⟷ All Targets   ║    │
    ║  [ESC] Back                           ║    │
    ║                                       ║    │
    ║  [MODE: TESTS (Single)]               ║    │
    ╚═══════════════════════════════════════╝    │
              │                                   │
              │ [Tab] Toggle                      │
              ▼                                   │
    ╔═══════════════════════════════════════╗    │
    ║   TEST PANEL                          ║    │
    ║   (Mode: TESTS [All Targets])         ║    │
    ║                                       ║    │
    ║  [Enter] runs on ALL 159 targets      ║    │
    ║  (Will take several minutes)          ║    │
    ║                                       ║    │
    ║  [MODE: TESTS (All)]                  ║    │
    ╚═══════════════════════════════════════╝    │
                                                  │
         [F] ──────────────────────────────────── ┘
              │                                   │
              ▼                                   │
    ╔═══════════════════════════════════════╗    │
    ║   FUZZING PANEL                       ║    │
    ║   (Mode: FUZZING)                     ║    │
    ║                                       ║    │
    ║  Fuzzing Modes:                       ║    │
    ║  ▶ Segment Size Fuzzing               ║    │
    ║    Length Mismatch                    ║    │
    ║    TCP Options Corruption             ║    │
    ║    IP Fragmentation                   ║    │
    ║    Checksum Validation                ║    │
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║    │
    ║  Results:                             ║    │
    ║  Mode            Pkts  Size   Status  ║    │
    ║  segment-size    100   45KB   ✓       ║    │
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║    │
    ║                                       ║    │
    ║  [↑/↓] Select                         ║    │
    ║  [Enter] Run fuzzer                   ║    │
    ║  [A] Run ALL fuzzers                  ║    │
    ║  [ESC] Back                           ║    │
    ║                                       ║    │
    ║  [MODE: FUZZING]                      ║    │
    ╚═══════════════════════════════════════╝    │
                                                  │
         [H] ──────────────────────────────────── ┘
              │
              ▼
    ╔═══════════════════════════════════════╗
    ║   HTTPS PANEL                         ║
    ║   (Mode: HTTPS)                       ║
    ║                                       ║
    ║  Select Target:                       ║
    ║  ○ github.com                         ║
    ║  ▶ outlook.office365.com              ║
    ║  ○ mail.google.com                    ║
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
    ║  HTTPS Test Results:                  ║
    ║  Target      DNS  TCP  TLS   Diag    ║
    ║  github.com  ✓    ✓    ✓     OK      ║
    ║  outlook...  ✓    ✓    ⚠     BLACKH. ║
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
    ║  Diagnosis:                           ║
    ║  1. MTU BLACKHOLE: TCP connects but   ║
    ║     TLS times out → Set MTU to 1400   ║
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
    ║                                       ║
    ║  [↑/↓] Select target                  ║
    ║  [Enter] Test selected                ║
    ║  [A] Test ALL targets                 ║
    ║  [ESC] Back                           ║
    ║                                       ║
    ║  [MODE: HTTPS]                        ║
    ╚═══════════════════════════════════════╝


    ╔═══════════════════════════════════════╗
    ║   POPUP: TRACEPATH OUTPUT             ║
    ║   (Overlay on any screen)             ║
    ║                                       ║
    ║  Running tracepath to github.com...   ║
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
    ║  1:  192.168.1.1     0.5ms pmtu 1500  ║
    ║  2:  10.0.0.1        2.3ms pmtu 1500  ║
    ║  3:  72.14.215.85    5.1ms            ║
    ║  4:  142.250.169...  8.2ms            ║
    ║  ...                                  ║
    ║  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   ║
    ║  [↑/↓] or [PgUp/PgDn] to scroll       ║
    ║  [ESC] to close                       ║
    ╚═══════════════════════════════════════╝


    ╔═══════════════════════════════════════╗
    ║   HELP SCREEN                         ║
    ║   (Mode: HELP)                        ║
    ║                                       ║
    ║  NAVIGATION                           ║
    ║    ↑/↓      Move selection            ║
    ║    Enter    View details              ║
    ║    ESC      Back to dashboard         ║
    ║                                       ║
    ║  VIEWS                                ║
    ║    1        Dashboard                 ║
    ║    T        Test Panel                ║
    ║    F        Fuzzing Panel             ║
    ║    H        HTTPS Testing             ║
    ║    3        MTU Simulator             ║
    ║    ?/h      This help                 ║
    ║                                       ║
    ║  TEST PANEL (when in Test Panel)      ║
    ║    1-0      Select test category      ║
    ║    Enter    Run selected test         ║
    ║    A        Run ALL tests             ║
    ║    Tab      Toggle single/all targets ║
    ║                                       ║
    ║  ACTIONS                              ║
    ║    r        Retest selected target    ║
    ║    R        Retest ALL targets        ║
    ║    t        Run tracepath (popup)     ║
    ║    s        Save JSON report          ║
    ║    q        Quit                      ║
    ║                                       ║
    ║  [ESC] Back                           ║
    ╚═══════════════════════════════════════╝
```

## Key Binding Summary

| Key | Global Action | Context-Aware Overrides |
|-----|---------------|-------------------------|
| `q` | Quit | (always) |
| `?`, `h` | Help | (always) |
| `ESC` | Back to Dashboard | Closes popups first |
| `↑/↓` | Navigate | Scroll popup if open |
| `PgUp/PgDn` | (none) | Scroll popup |
| `←/→` | Adjust MTU | (in Simulator) |
| `1` | Go to Dashboard | **In Test Panel**: Select DNS |
| `2` | (none) | **In Test Panel**: Select MTU |
| `3` | Go to Simulator | **In Test Panel**: Select HTTPS |
| `4-9,0` | (none) | **In Test Panel**: Select categories 4-10 |
| `T` | Test Panel | (always) |
| `F` | Fuzzing Panel | (always) |
| `H` | HTTPS Panel | (always) |
| `Tab` | (none) | **In Test Panel**: Toggle Single/All |
| `Enter` | View Detail | **Mode-specific**: Run test/fuzzer |
| `A` | (none) | **Test Panel**: Run all tests<br>**Fuzzing**: Run all fuzzers<br>**HTTPS**: Test all targets |
| `r` | Retest single | (from Dashboard) |
| `R` | Retest all | (from Dashboard) |
| `t` | Tracepath | (opens popup) |
| `s` | Save report | (from Dashboard) |

## Flow Decision Points

### From Dashboard → Enter
- Goes to **Target Detail** for selected target
- Shows packet breakdowns, tunnel overhead calculations
- Option to run tracepath with `t` key

### From Test Panel → Enter
- **If Single Mode**: Runs test on currently selected target
- **If All Mode**: Runs test on all 159 targets (prompts for confirmation)
- Mode indicator in footer shows current mode: `[MODE: TESTS (Single)]` or `[MODE: TESTS (All)]`

### From Test Panel → Tab
- Toggles between **Single** and **All Targets** modes
- Footer updates to reflect current mode
- Enter behavior changes accordingly

### From Any Panel → ESC
- If popup is open: Closes popup
- Else: Returns to Dashboard
- Exception: From Dashboard, ESC does nothing

## Popup Behavior

### Tracepath Popup (triggered by `t` key)
- Overlays current screen (doesn't change mode)
- Streams output line-by-line in real-time
- Auto-scrolls to bottom
- User can scroll up with `↑/↓` or `PgUp/PgDn`
- Close with `ESC` to return to previous screen

### Other Popups
- Used for confirmations, errors, progress messages
- Single-screen (no scrolling)
- Close with `ESC` or any key (context-dependent)

## Design Principles

1. **Context-Aware Keys**: Number keys (1-10) work differently in Test Panel vs other screens
2. **Clear Mode Indicators**: Footer always shows current mode
3. **Consistent Navigation**: ESC always goes back/closes
4. **Visual Feedback**: Selected items highlighted, status icons (✓/✗/⚠)
5. **Graceful Degradation**: If features unavailable (e.g., tracepath), tool continues with warnings

## Future Enhancements

- Add breadcrumb trail: `Dashboard > Target Detail > Tracepath`
- Implement modal dialog stack for nested popups
- Add visual indicator for scrollable areas ("↓ more")
- Keyboard shortcuts quick reference (Ctrl+?)
- Save/restore session state

