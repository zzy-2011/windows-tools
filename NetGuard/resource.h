#pragma once

// ============================================================
//  Main Window Controls
// ============================================================
#define IDC_LISTVIEW        1001
#define IDC_BTN_SCAN        1002
#define IDC_BTN_STOP        1003
#define IDC_BTN_EXPORT      1004
#define IDC_BTN_BLACKLIST   1005
#define IDC_BTN_SETTINGS    1006
#define IDC_COMBO_FILTER    1007
#define IDC_STATUSBAR       1008
#define IDC_PROGRESSBAR     1009

// ============================================================
//  Settings Dialog Controls
// ============================================================
#define IDD_SETTINGS        2000
#define IDC_EDIT_APIKEY     2001
#define IDC_CHK_ABUSEIPDB   2002
#define IDC_CHK_ET          2003
#define IDC_CHK_BLOCKLIST   2004
#define IDC_CHK_FEODO       2005
#define IDC_COMBO_CACHE     2006
#define IDC_BTN_CLEARCACHE  2007

// ============================================================
//  Custom Window Messages
// ============================================================
#define WM_SCAN_COMPLETE    (WM_APP + 1)
#define WM_SCAN_PROGRESS    (WM_APP + 2)
#define WM_BL_COMPLETE      (WM_APP + 3)
#define WM_BL_ERROR         (WM_APP + 4)
#define WM_ABUSE_RESULT     (WM_APP + 5)
