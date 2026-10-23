/**
 * MCPShield Privacy-First Cookieless Telemetry (UK PECR & EU GDPR Compliant)
 * - Strictly honors Do Not Track (DNT) and Global Privacy Control (GPC)
 * - Zero cookies, zero localStorage IDs, zero IP logging, zero PII
 */
(function () {
  function isTrackingOptedOut() {
    if (typeof navigator === "undefined") return true;
    if (navigator.doNotTrack === "1" || navigator.doNotTrack === "yes") return true;
    if (typeof window !== "undefined" && window.doNotTrack === "1") return true;
    if (navigator.globalPrivacyControl === true) return true;
    return false;
  }

  function trackEvent(eventName, meta) {
    if (isTrackingOptedOut()) {
      return { sent: false, reason: "DNT_OR_GPC_ENABLED" };
    }
    const payload = {
      event: String(eventName || "pageview").slice(0, 64),
      path: typeof location !== "undefined" ? location.pathname : "/",
      referrerDomain:
        typeof document !== "undefined" && document.referrer
          ? (() => {
              try {
                return new URL(document.referrer).hostname;
              } catch {
                return "direct";
              }
            })()
          : "direct",
      meta: meta && typeof meta === "object" ? meta : {},
      ts: new Date().toISOString().slice(0, 13) + ":00:00Z" // Bucketed to hour for k-anonymity
    };

    try {
      if (typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
        const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
        navigator.sendBeacon("/api/event", blob);
      }
    } catch {
      // Fail silently — analytics must never degrade user experience
    }
    return { sent: true, payload };
  }

  if (typeof window !== "undefined") {
    window.MCPShieldAnalytics = { isTrackingOptedOut, trackEvent };
    window.addEventListener("DOMContentLoaded", function () {
      trackEvent("pageview", {});
    });
  }
})();
