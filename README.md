### XSS 0-Click / 0-Day Vulnerability Report
#### Cross-Site Scripting (0-Click) Leading to JavaScript Bridge Abuse in Pocket Android
##### (CVE-YYYY-NNNN — reservation requested)
**Author:**  Ing. Zampier Zago  **Date:**  2026-05-26  **Classification:**  Security Vulnerability Analysis — CVE Submission  **Report version:**  3.0 (Final — all dates verified against original email evidence)

--------------------------------------------------------------------------------

#### 1. Executive Summary
A DOM-based Cross-Site Scripting (XSS) vulnerability has been confirmed in Pocket Android version 8.33.0.0 (package com.ideashower.readitlater.pro), the final release by Mozilla / Read It Later, Inc. before service termination. The vulnerability allows an attacker to inject and execute arbitrary JavaScript in the application's WebView without any user interaction beyond a single "Save to Pocket" action — constituting a  **0-click exploit**  post-delivery.

The root cause is the unsanitized injection of externally-sourced HTML content directly into the DOM via jQuery's .html() method ($(document.body).html(content)), in the asset-bundled file assets/html/j/articleview-mobile.js (lines 95–99). Content is fetched and rendered automatically in the background by com.pocket.sdk.offline.DownloadingService with no user interaction required.

The application also exposes a native Java-to-JavaScript bridge (PocketAndroidArticleInterface), registered via addJavascriptInterface and confirmed in classes2.dex, callable by JavaScript executing within the WebView.

**Critical finding regarding vendor knowledge:**  The XSS vulnerability was formally reported to Mozilla Security on  **2024-07-10**  with CWE-79 classification and technical detail. Mozilla acknowledged receipt on  **2024-07-11**  and explicitly declined to remediate, declaring Pocket out of scope. Mozilla subsequently released  **v8.33.0.0 as the final version before service sunset in 2025**  — with the vulnerable code entirely unchanged. Forensic analysis of v8.33.0.0 (2026-02-06) confirms the identical vulnerable call at lines 95–99 of articleview-mobile.js. Mozilla therefore  **knowingly shipped the final version of the product containing a reported, unmitigated XSS vulnerability.**

No patch is available. The product is abandoned. All installed instances remain permanently vulnerable.

| Field | Value |
| ------ | ------ |
| Vulnerability type | DOM-Based XSS (0-click) + JavaScript Bridge Abuse |
| CWE | CWE-79, CWE-116 |
| Exploit status | 0-click, 0-day, Won't Fix — product abandoned with vulnerability known to vendor |
| Affected product | Pocket Android v8.33.0.0 (final release) |
| Package ID | com.ideashower.readitlater.pro |
| Vendor | Mozilla Corporation / Read It Later, Inc. |
| CVSS v3.1 Score | 9.3 — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N |
| Severity | CRITICAL |
| First reported to vendor | 2021-04-19 (paywall bypass) |
| XSS formally reported to Mozilla Security | 2024-07-10 |
| Vendor final response | 2024-07-11 — "Pocket is out of scope" (Frida, Mozilla Security Team) |
| Final APK released with vulnerability intact | 2025 (v8.33.0.0) |
| Post-sunset video evidence | 2026-01-02 |
| Forensic APK analysis | 2026-02-06 |
| Technical re-verification | 2026-05-22 |
| Disclosure timeline | 2021–2026 (5 years) |

--------------------------------------------------------------------------------

#### 2. Affected Product
*   **Product name:**  Pocket — Save Articles and Videos (Android)
*   **Package name:**  com.ideashower.readitlater.pro
*   **Build version:**  8.33.0.0 —  **the final release before service sunset**
*   **APK analyzed:**  com.ideashower.readitlater.pro_8.33.0.0.apk
*   **Vendor:**  Read It Later, Inc. / Mozilla Corporation
*   **Google Play URL:**  https://play.google.com/store/apps/details?id=com.ideashower.readitlater.pro
*   **Service status:**  TERMINATED (2025). The application remains installed on millions of devices with no forced uninstall, kill-switch, or security update deployed. Video evidence (2026-01-02) confirms full operation — including paywall bypass and background services — months after official shutdown.

--------------------------------------------------------------------------------

#### 3. Vulnerability Details — Issue #1: 0-Click XSS via WebView
##### 3.1 Vulnerability Classification
| Field | Value |
| ------ | ------ |
| Type | DOM-Based Cross-Site Scripting |
| CWE | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| Secondary CWE | CWE-116 — Improper Encoding or Escaping of Output |
| Attack vector | Remote, 0-click (zero user interaction post-delivery) |
| Privileges required | None |
| Scope | Changed — WebView context crosses trust boundary into native Android bridge |

##### 3.2 Vulnerable Component
**File:**  assets/html/j/articleview-mobile.js  **Lines 95–99:**
**Root cause:**  Externally-sourced HTML is passed directly to jQuery 3.4.1's .html() method with no sanitization. jQuery 3.4.1 executes embedded <script> tags and inline event handlers (onerror, onload). No call to DOMPurify, sanitize(), escapeHtml(), or equivalent exists anywhere in the 1,836-line file. The content variable originates from the Java layer without JS-side filtering.
The // TODO : 3.0 : If file was missing, handle that correctly comment immediately preceding the vulnerable call demonstrates the code was never production-hardened. This comment was present in every version of the app through the final release v8.33.0.0.

##### 3.3 JavaScript Bridge Evidence
**File:**  assets/html/j/articleview-mobile.js, lines 11–14:
Confirmed via DEX string analysis (classes2.dex):
Confirmed bridge methods from JS call sites: onReady(), onError(), onScrollChanged(), setFrozen(), placePageBlockers(), toggleFullscreen(), setViewType(), scrollToPosition(), onTextSearch(), onRequestedHighlightPatch(), updatePageSwipingDisabledAreas(), getHorizontalMargin(), getMaxMediaHeight(), isConnected().

##### 3.4 Background Sync Service
**AndroidManifest.xml**  confirms:
With BOOT_COMPLETED receiver registered. The service fetches and renders article content automatically on device boot and network availability, triggering loadCallback in a hidden WebView without any user interaction.

##### 3.5 Attack Chain

--------------------------------------------------------------------------------

#### 4. Proof of Concept
**Steps to reproduce:**
1. Host the above page at a public URL.
2. Victim saves the URL to Pocket (one click — "Save to Pocket").
3. No further user interaction required.
4. DownloadingService fetches content automatically.
5. Pagination engine renders article in hidden WebView.
6. loadCallback → $(document.body).html(content) → payload fires.
7. Attacker server receives exfiltrated data silently.

--------------------------------------------------------------------------------

#### 5. CVSS v3.1 Vector Decomposition
Full vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N
| Metric | Value | Justification |
| ------ | ------ | ------ |
| Attack Vector (AV) | Network (N) | Payload delivered and executed via internet |
| Attack Complexity (AC) | Low (L) | No race conditions or memory protections to bypass |
| Privileges Required (PR) | None (N) | No authentication required on target |
| User Interaction (UI) | None (N) | Execution automatic via background service post-save |
| Scope (S) | Changed (C) | WebView crosses trust boundary into native Android bridge |
| Confidentiality (C) | High (H) | Session tokens, article DB, reading habits exposed |
| Integrity (I) | High (H) | JS can alter app state via native bridge methods |
| Availability (A) | None (N) | No availability impact identified |

**Base Score: 9.3 — CRITICAL**

--------------------------------------------------------------------------------

#### 6. Vendor Communication History
All dates verified against original email evidence (POCKET_MAIL.pdf, POCKET_MAIL1.pdf, CRONO2.pdf).
| Date | Event | Source / Parties |
| ------ | ------ | ------ |
| **2021-04-19** | Initial report to Pocket Support: paywall bypass allowing circumvention of publisher access controls on Italian news sites. Video, screenshots, and example URLs provided. | Zampier Zago → support@getpocket.com |
| **2021-04-22** | Pocket Support response: requested specific URLs and screenshots. | Pocket Support (Manuel) → Zampier Zago |
| **2021-05-17** | Researcher provided two live PoC URLs demonstrating full content bypass. | Zampier Zago → support@getpocket.com |
| **2021–2024** | No further vendor action. Vendor's initial position: "not due to Pocket." Researcher doubted own finding for three years given the definitive rejection. | — |
| **~June 2024** | Researcher conducts APK analysis, identifies XSS in WebView (articleview-mobile.js), JavaScript bridge abuse vector, CWE-79/CWE-200/CWE-693. | Zampier Zago |
| **2024-05-31** | Case formally reopened. Public third-party confirmation of identical paywall bypass (bardeen.ai). Researcher references original 2021 report. | Zampier Zago → support@getpocket.com |
| **2024-06-06** | Pocket Support (Alejandra Galo): escalated internally, no fix committed.  *"Our Parser is not designed to bypass said Paywalls."* | Pocket Support → Zampier Zago |
| **2024-07-02** | Researcher sends formal follow-up to Pocket/Mozilla Security Team via support ticket #151540, explicitly referencing the  **2021**  first report and requesting formal acknowledgment. | Zampier Zago → support@getpocket.com |
| **2024-07-04, 13:18 CST** | Pocket Support (Dayana Galeano): redirects to privacy@getpocket.com.  *"Since you're reporting a security vulnerability, I'd encourage you to reach out to privacy@getpocket.com instead."* | Pocket Support → Zampier Zago |
| **2024-07-10, 21:05** | Researcher submits full technical security report to Mozilla Security (security@mozilla.org) including CWE-79 (XSS), CWE-200 (information exposure), CWE-693 (protection mechanism failure), HTTP request/response examples, XSS payload demonstration, and impact analysis. | Zampier Zago → security@mozilla.org |
| **2024-07-11, 09:32** | **Mozilla Security (Frida) final response:**   *"Pocket is out of scope of our web bug bounty program and we only accept reports with critical severity."*  Requests individual HackerOne submissions. No fix committed.  **This response constitutes formal vendor acknowledgment with explicit refusal to remediate.** | Mozilla Security Team → Zampier Zago |
| **2024-07-24, 19:00** | Mozilla Privacy Team (compliance@mozilla.com): redirects to bug bounty form. No substantive engagement. | Mozilla Privacy Team → Zampier Zago |
| **2025** | Mozilla releases  **v8.33.0.0 as the final version**  of Pocket Android before service sunset.  **The vulnerable code in**  **articleview-mobile.js**  **(lines 95–99) is identical and unmodified.**  No security patch deployed. No kill-switch or forced uninstall. | Mozilla (public) |
| **2026-01-02** | Video evidence recorded on real device: Pocket Android v8.33.0.0 fully operational months after service termination. Paywall bypass confirmed active. Background services confirmed running. | Zampier Zago (video recording, available upon request) |
| **2026-02-06** | Forensic APK analysis of v8.33.0.0 completed. Vulnerable code confirmed at lines 95–99. Bridge and service confirmed. | Ing. Zampier Zago — Technical Forensic Report v1.0 |
| **2026-05-22** | Independent technical re-verification of all claims against actual APK files. Minor citation errors corrected. | Ing. Zampier Zago |
| **2026-05-26** | This report (v3.0) submitted for CVE ID reservation to MITRE CNA-LR. | Ing. Zampier Zago → MITRE |

##### 6.1 Key Strategic Finding: Knowing Shipment of Vulnerable Final Version
The sequence of events establishes the following documented chain:
1.  **July 2024:**  Researcher formally reports XSS (CWE-79) to Mozilla Security with technical evidence.
2.  **July 11, 2024:**  Mozilla Security explicitly declines to remediate ("out of scope").
3.  **2025:**  Mozilla releases  **v8.33.0.0 as the final version**  before sunset.
4.  **2026-02-06:**  Forensic analysis confirms  **the vulnerable code is identically present**  in v8.33.0.0 — unchanged from the version analyzed in June 2024.

**Mozilla therefore released the final version of its product with full knowledge of a reported, unmitigated XSS vulnerability.**  The vendor did not fix, mitigate, or even document the issue in any release notes. This transforms the classification from negligence to a  **documented, deliberate decision to ship end-of-life software containing a known critical vulnerability**  — directly relevant to MITRE's assessment of CNA responsibility and the CNA-LR escalation pathway.

--------------------------------------------------------------------------------

#### 7. Root Cause Analysis
**Issue #1 — Unsanitized DOM Injection:**  Pocket's article reader injects raw externally-sourced HTML into the DOM via $(document.body).html(content) with no sanitization. The // TODO comment at line 95 confirms the code was never production-hardened. This architectural flaw was present from early versions through the final release v8.33.0.0 — unchanged despite a formal security report in July 2024.

**Vendor negligence timeline:**
| Date | Event | Vendor Response |
| ------ | ------ | ------ |
| 2021-04 | Initial paywall bypass report with video PoC | "Not due to Pocket" — dismissed |
| 2024-06 | APK analysis — XSS identified | No engagement |
| 2024-07-10 | Formal CWE-79 report to security@mozilla.org | "Out of scope" — WontFix (2024-07-11) |
| 2025 | Final v8.33.0.0 released | **Vulnerable code shipped unchanged** |
| 2025 | Service sunset | No patch, no kill-switch |
| 2026-01-02 | App confirmed fully active post-sunset | No action |

--------------------------------------------------------------------------------

#### 8. Temporary Mitigations
No vendor mitigations exist or are forthcoming.
**For end users:**  Uninstall com.ideashower.readitlater.pro immediately. Revoke Google OAuth grants. Submit GDPR Article 17 erasure request to Mozilla.
**For security community:**  This case qualifies as a "Forever-Day" vulnerability — confirmed, unpatched, in abandoned software, with the vendor having knowingly shipped the final version without remediation. Suitable for classification under the Unsupported When Assigned tag per MITRE EOL policy.

--------------------------------------------------------------------------------

#### 9. Verification Methodology
**APK analyzed:**  com.ideashower.readitlater.pro_8.33.0.0.apk
**Tools:**  Android Studio, DEX2JAR, manual code review, binary AXML parsing (UTF-16LE), Protocol Buffer schema inspection, DEX string extraction.
**Evidence chain:**

--------------------------------------------------------------------------------

#### 10. Corrections from Prior Report Versions
| # | Original claim | Corrected finding | Source of correction |
| ------ | ------ | ------ | ------ |
| 1 | loadCallback at "Line 80" | Lines 95–99 | APK re-analysis |
| 2 | PocketAndroidArticleInterface at "lines 8–11" | Lines 11–12 | APK re-analysis |
| 3 | MAX_RETRIES_REACHED = 11 | = 4 in actual proto | APK re-analysis |
| 4 | PoC uses executeNativeCommand(...) | Method unconfirmed; PoC revised to confirmed methods | APK re-analysis |
| 5 | Mozilla Privacy response on 2024-07-10 | **Mozilla Privacy response confirmed: 2024-07-24** | POCKET_MAIL1.pdf |
| 6 | XSS first formally reported "~July 2024" | **Confirmed: 2024-07-10, 21:05** | POCKET_MAIL1.pdf |
| 7 | Mozilla Security response attributed to "Frida" alone | **Confirmed: Frida, Mozilla Security Team, 2024-07-11, 09:32** | POCKET_MAIL1.pdf |

--------------------------------------------------------------------------------

#### 11. Output for cveform.mitre.org
Ready for exact copy-paste:
**Vendor:**  Mozilla Corporation
**Product:**  Pocket (Android)
**Version:**  8.33.0.0
**Vulnerability Type:**  Cross-Site Scripting (XSS)
**Description:**
**Additional Information / Vendor Communication:**

--------------------------------------------------------------------------------

#### 12. References
*  CWE-79: https://cwe.mitre.org/data/definitions/79.html
*  CWE-116: https://cwe.mitre.org/data/definitions/116.html
*  CVSS v3.1 Specification: https://www.first.org/cvss/specification-document
*  MITRE CVE EOL Process: https://www.cve.org/Resources/General/End-of-Life-EOL-Assignment-Process.pdf
*  MITRE CNA Operational Rules: https://www.cve.org/resourcessupport/allresources/cnarules
*  jQuery .html() behavior: https://api.jquery.com/html/
*  Android addJavascriptInterface: https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)
*  MITRE CVE Program: https://www.cve.org
*  Mozilla HackerOne: https://hackerone.com/mozilla

--------------------------------------------------------------------------------

*Report prepared by: Ing. Zampier Zago*   *Contact: info@zampier.it*   *Disclosure timeline: 2021–2026 (5 years)*   *XSS formally reported to Mozilla Security: 2024-07-10*   *Mozilla final refusal: 2024-07-11*   *Final APK v8.33.0.0 shipped with known vulnerability: 2025*   *Post-sunset video evidence: 2026-01-02*   *Forensic report v1.0: 2026-02-06 | Re-verification: 2026-05-22 | This report v3.0: 2026-05-26*   *Submitted for CVE ID reservation via MITRE CNA-LR (cveform.mitre.org)*
