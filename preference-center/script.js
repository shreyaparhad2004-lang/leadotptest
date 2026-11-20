const {
  preferenceFormId,
  preferenceDetailsApiUrl,
  preferenceHistoryApiUrl,
  downloadHistoryPdfApiUrl,
  submitApiUrl,
  signatureServiceUrl,
  userToken,
  showButtons,
  showLanguageDropdown,
  enableCheckboxes,
  enableRadioButtons,
  enableDropdowns,
  footerAlignment = "left",
  customAttributes,
  receivedType,
  customHeaders,
  apiDomain
} = window.consentWidgetConfig;

// Re-points a branding asset URL at the ConfigMap-provided apiDomain. Handles both
// root-relative paths ("/cpm-api/upload/v1/fileDownloads?...") and absolute URLs that
// still carry a stale host, so the logo loads from the correct backend when the
// downloaded widget is hosted elsewhere.
function resolveAssetUrl(url) {
  if (!url) return url;
  const raw = String(url).trim();
  const marker = "/cpm-api/upload/v1/fileDownloads";
  if (/^https?:\/\//i.test(raw)) {
    try {
      const parsed = new URL(raw);
      if (parsed.pathname.indexOf(marker) === 0 && apiDomain) {
        return apiDomain + parsed.pathname + parsed.search;
      }
    } catch (e) {}
    return raw;
  }
  if (raw.indexOf("/cpm-api/") === 0 && apiDomain) {
    return apiDomain + raw;
  }
  return raw;
}

let createConsentRequestList = [];
let selectedLanguage = "english";
let storedSigning = { bss: null, bssPublicKey: null, sss: null };
let pendingSignController = null;
let currentSnapshot = null;
let consentJwt = null;
let clickEvent = async () => {};
let currentActiveView = "CURRENT";

const AES_KEY_B64 = "el+1+epeGlCquCYLsk3zyQTsq3KUKQKL9QcV0B9KIS8=";
let globalSSS = null;
let isSSSValid = false;
let currentBranding = {};
let currentLang = "english";
// Marks the unfilled mandatory statements of the rendered preference; set by renderConsent
let validateMandatoryFields = () => true;

// Used by the shared OTP code to decide whether Submit can be enabled
function isSelectionSigned() {
  return isSSSValid;
}

// Signing runs after every selection change; wait briefly for the latest one
async function waitForSelectionSigned(timeoutMs = 5000) {
  const until = Date.now() + timeoutMs;
  while (!isSSSValid && Date.now() < until) {
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

// Used by the submit and by the shared Verify and Submit: checks the mandatory fields (before any OTP is used),
// waits for the selection signing and builds the submit payload. Resolves to { ok, message }.
async function prepareConsentSubmit() {
  if (!validateMandatoryFields()) {
    showToast(OTP_TEXT.mandatory, "error");
    return { ok: false, message: OTP_TEXT.mandatory };
  }
  await waitForSelectionSigned();
  if (!isSSSValid) {
    return { ok: false, message: OTP_TEXT.notSigned };
  }
  createConsentRequestList = buildFinalConsentRequest(currentLang).createConsentRequestDtoWrapper;
  return { ok: true };
}

// New form JWT and re-render
async function reloadConsentForm() {
  await fetchConsentData();
}


const urlParams = new URLSearchParams(window.location.search);

const campaignId = urlParams.get("c");
const linkToken = urlParams.get("lt");

const campaignLinkContext = {
  ...(campaignId && { campaignId }),
  ...(linkToken && { linkToken })
};

function uint8ToBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = "";

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(i, i + chunkSize)
    );
  }

  return btoa(binary);
}
async function encryptPayload(body) {
  const keyBytes = Uint8Array.from(atob(AES_KEY_B64), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(body));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, encoded);
  const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), iv.byteLength);
  return uint8ToBase64(combined);
}

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization-SDP": userToken || "",
    ...customHeaders
  };
}

// ── IndexedDB helper ──
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("consent-signing-store", 2);
    req.onupgradeneeded = function(e) {
      const db = e.target.result;
      if (!db.objectStoreNames.contains("keys")) db.createObjectStore("keys");
    };
    req.onsuccess = e => resolve({
      put: (store, val, key) => new Promise((res, rej) => {
        const tx = e.target.result.transaction(store, "readwrite");
        const r = tx.objectStore(store).put(val, key);
        r.onsuccess = () => res(); r.onerror = () => rej(r.error);
      }),
      get: (store, key) => new Promise((res, rej) => {
        const tx = e.target.result.transaction(store, "readonly");
        const r = tx.objectStore(store).get(key);
        r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
      }),
    });
    req.onerror = () => reject(req.error);
  });
}

// Generates ECDSA P-256 key pair on first load; private key is non-extractable
// and stored in IndexedDB. Public key is exported as SPKI base64.
async function initSigningKey() {
  try {
    const db = await openDB();
    const existing = await db.get("keys", "signingKeyEC");
    if (existing) return;

    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );

    await db.put("keys", keyPair.privateKey, "signingKeyEC");

    const pubKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const pubKeyB64 = btoa(String.fromCharCode(...new Uint8Array(pubKeyBuffer)));
    await db.put("keys", pubKeyB64, "signingPublicKeyB64");
  } catch (e) {
    console.error("Signing key initialization failed:", e);
  }
}

async function getPublicKeyB64() {
  try {
    const db = await openDB();
    return await db.get("keys", "signingPublicKeyB64");
  } catch (e) {
    return null;
  }
}

// Produces canonical JSON (sorted keys, no whitespace) matching Go's canonicalize.
function canonicalizePayload(obj) {
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalizePayload).join(",") + "]";
  }
  if (obj !== null && typeof obj === "object") {
    var keys = Object.keys(obj).sort();
    return "{" + keys.map(function(k) {
      return JSON.stringify(k) + ":" + canonicalizePayload(obj[k]);
    }).join(",") + "}";
  }
  return JSON.stringify(obj);
}

// Signs using ECDSA-P256; returns base64url IEEE P1363 signature.
async function signPayload(payload) {
  try {
    const db = await openDB();
    const privateKey = await db.get("keys", "signingKeyEC");
    if (!privateKey) return null;

    const encoded = new TextEncoder().encode(canonicalizePayload(payload));
    const sigBuffer = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      encoded
    );
    return btoa(String.fromCharCode(...new Uint8Array(sigBuffer)))
      .replace(/[+]/g, "-").replace(/[/]/g, "_").replace(/=/g, "");
  } catch (e) {
    console.error("Payload signing failed:", e);
    return null;
  }
}

// Converts ASN.1 DER ECDSA signature (Go output) to IEEE P1363 (WebCrypto input).
function derToP1363(der) {
  var off = 2;
  if (der[1] === 0x81) off = 3;
  off++;
  var rLen = der[off++];
  var rPad = (rLen === 33 && der[off] === 0x00) ? 1 : 0;
  var rBytes = der.slice(off + rPad, off + rLen);
  off += rLen;
  off++;
  var sLen = der[off++];
  var sPad = (sLen === 33 && der[off] === 0x00) ? 1 : 0;
  var sBytes = der.slice(off + sPad, off + sLen);
  var result = new Uint8Array(64);
  result.set(rBytes.slice(-32), 32 - Math.min(rBytes.length, 32));
  result.set(sBytes.slice(-32), 64 - Math.min(sBytes.length, 32));
  return result;
}

// Verifies the server-side ECDSA-SHA256 signature against the payload.
async function verifySSS(payload, sssBase64Url, pemPublicKey) {
  try {
    let b64 = pemPublicKey
      .replace(/-----BEGIN PUBLIC KEY-----/g, '')
      .replace(/-----END PUBLIC KEY-----/g, '')
      .replace(/\s+/g, '')
      .replace(/[^A-Za-z0-9+/=]/g, '');
    while (b64.length % 4 !== 0) { 
        b64 += '=';
    }
    var der = Uint8Array.from(atob(b64), function(c) { return c.charCodeAt(0); });
    var pubKey = await crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    var data = new TextEncoder().encode(canonicalizePayload(payload));
    var sigB64 = sssBase64Url.replace(/-/g, "+").replace(/_/g, "/");
    while (sigB64.length % 4) sigB64 += "=";
    var derBytes = Uint8Array.from(atob(sigB64), function(c) { return c.charCodeAt(0); });
    var p1363 = derToP1363(derBytes);
    var result = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pubKey, p1363, data);
    return result;
  } catch (e) {
    return false;
  }
}
function buildFinalConsentRequest(selectedLang) {
  const requestList = [];
  const consentDiv = document.getElementById("consent-root");

  const allElements = consentDiv.querySelectorAll("[name]");

  const pushConsent = (permissionId, optionId = null, hasValue = false) => {
    let existing = requestList.find(r => r.permissionId === permissionId);

    if (existing) {
      if (hasValue) {
        existing.optedForIndexes.push(parseInt(optionId));
      }
    } else {
      requestList.push({
        consentLanguage: selectedLang,
        consentReceivedType: receivedType,
        customAttributes,
        permissionId,
        optedForIndexes: hasValue ? [parseInt(optionId)] : []
      });
    }
  };

  allElements.forEach(el => {
    const permissionId = el.name;

    if (el.type === "checkbox" && enableCheckboxes) {
      if (el.checked) {
        pushConsent(permissionId, el.getAttribute("data-option-id") || "0", true);
      } else {
        pushConsent(permissionId, null, false);
      }
    }

    else if (el.type === "radio" && enableRadioButtons) {
      if (el.checked) {
        pushConsent(permissionId, el.getAttribute("data-option-id") || "0", true);
      } else {
        // ensure permission exists even if nothing selected
        pushConsent(permissionId, null, false);
      }
    }

  else if (el.tagName === "SELECT" && enableDropdowns) {
    const opt = el.options[el.selectedIndex];

    if (opt && opt.value !== "") {
      pushConsent(
        permissionId,
        opt.getAttribute("data-option-id") || "0",
        true
      );
    } else {
      pushConsent(permissionId, null, false);
    }
  }
  });
  
  const msDropdowns = consentDiv.querySelectorAll(".ms-dropdown");
  msDropdowns.forEach(ms => {
    if (!enableDropdowns) return;
    // Single-select dropdowns use a hidden <select>; handled by the [name] SELECT loop above.
    if (ms.querySelector("select")) return;
    const permId = ms.getAttribute("data-perm-id");
    const checkedBoxes = ms.querySelectorAll('input[type="checkbox"]:checked');
    if (checkedBoxes.length > 0) {
      checkedBoxes.forEach(cb => {
        pushConsent(permId, cb.getAttribute("data-option-id") || "0", true);
      });
    } else {
      pushConsent(permId, null, false);
    }
  });

requestList.sort((a, b) =>
  String(a.permissionId).localeCompare(String(b.permissionId))
);

const normalizedList = requestList.map(item => {
  const sortedItem = {};
  Object.keys(item)
    .sort()
    .forEach(key => {
      sortedItem[key] = item[key];
    });
  return sortedItem;
});

return {
  createConsentRequestDtoWrapper: normalizedList
};
}

// Called on every radio/checkbox/dropdown change.
async function onSelectionChange(selectedLang) {
  // Not ready until the new selection is signed again
  isSSSValid = false;
  updateSubmitReady();

  const request = buildFinalConsentRequest(selectedLang);

  // Always track the latest snapshot so stale in-flight responses fail verification.
  currentSnapshot = request;
  var bssPublicKey = await getPublicKeyB64();
  var bss = await signPayload(currentSnapshot.createConsentRequestDtoWrapper);
  if (!bss || !bssPublicKey) {
   return; }

  try {
    var headers = { "Content-Type": "application/json" };
    var res = await fetch(signatureServiceUrl + "/v1/sign", {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ payload: currentSnapshot.createConsentRequestDtoWrapper, bss: bss, bss_pkey: bssPublicKey })
    });
    if (!res.ok) {
      var signErr = null;
      try { signErr = await res.json(); } catch (e) {}
      if (res.status === 401) showToast(" 401 Unauthorized", "error");
      else if (res.status === 404) showToast(" 404 Not Found", "error");
      else if (res.status === 500) showToast(" 500 Service Down", "error");
      else if (signErr?.error?.code === "BSS_VERIFICATION_FAILED") showToast(" BSS authentication failed", "error");
      else if (signErr?.error?.code === "SSS_VERIFICATION_FAILED") showToast(" SSS authentication failed", "error");
      else showToast(" Signature service failed", "error");
      return;
    }
    var signData = await res.json();
    var sss = signData.sss;
    globalSSS = sss;
	
    // Verify against currentSnapshot (latest) — if user changed selection while
    // this request was in-flight, currentSnapshot !== snapshot and verification fails.
    var valid = await verifySSS(currentSnapshot.createConsentRequestDtoWrapper, sss, signData.sss_pkey);

    //storedSigning = { bss: bss, bssPublicKey: bssPublicKey, sss: sss };
    isSSSValid = !!valid;
    updateSubmitReady();
  } catch (e) {
    console.error("[SDP-SIGN] Signature service call failed:", e);
    showToast("v1/sign service unavailable", "error");
  }
}

async function handleApiResponse(res) {
  let payload = {};

  try {
    payload = await res.json();
  } catch (e) {
    payload = {};
  }

  const apiMessage =
    payload?.statusMessage ||
    payload?.message ||
    payload?.error;

  // 401
  if (res.status === 401 || payload?.statusCode === 401) {
    showErrorOnly(apiMessage || "401 UNAUTHORIZED");
    throw new Error(apiMessage || "UNAUTHORIZED");
  }

  // Any API error
  if (!res.ok) {
    const msg = apiMessage || `Request failed (${res.status})`;

    showErrorOnly(msg);
    throw new Error(msg);
  }

  return payload;
}

function showErrorOnly(message) {
  const widgetContainer = document.querySelector(".widget-container");

  if (!widgetContainer) return;

  // Remove the existing UI
  widgetContainer.innerHTML = "";

  // Show only the API message
  const error = document.createElement("div");
  error.className = "error-only-message";
  error.textContent = message;

  widgetContainer.appendChild(error);
}



function setFormDisabled(disabled = true) {
  const root = document.getElementById("consent-root");
  const inputs = root.querySelectorAll("input, select, textarea, button");
  inputs.forEach(input => input.disabled = disabled);

  const submitBtn = document.getElementById("submitBtn");
  const cancelBtn = document.getElementById("cancelBtn");
  submitBtn.disabled = disabled;
  cancelBtn.disabled = disabled;
  
  if (disabled) {
    submitBtn.classList.add("loading");
  } else {
    submitBtn.classList.remove("loading");
  }
}

const historyPagination = {
  page: 0,
  size: 10,
  hasMore: true,
  loading: false
};

const SCROLL_THRESHOLD = 180; 
function attachHistoryScroll() {
  const scrollContainer = document.querySelector(".preview-statements");

  if (!scrollContainer || scrollContainer.dataset.scrollBound) return;

  scrollContainer.addEventListener("scroll", () => {
    if (
      scrollContainer.scrollTop + scrollContainer.clientHeight >=
      scrollContainer.scrollHeight - SCROLL_THRESHOLD
    ) {
      loadMoreHistory();
    }
  });

  scrollContainer.dataset.scrollBound = "true";
}


async function loadMoreHistory() {
  if (!historyPagination.hasMore || historyPagination.loading) return;

  historyPagination.loading = true;
  historyPagination.failed = false;;

  try {
    const scrollPayload = {
      preferenceFormId,
      page: historyPagination.page + 1,
      pageSize: historyPagination.size,
      sortBy: "formName",
      sortDirection: "ASC"
    };
    const browserSignature = await signPayload(scrollPayload);
    if (browserSignature) scrollPayload.bss = browserSignature;

 const res = await fetch(preferenceHistoryApiUrl, {
  method: "POST",
  headers: authHeaders(),
  credentials: "include",
  body: JSON.stringify({ ...scrollPayload, ...campaignLinkContext })
});


   const result = await handleApiResponse(res);
   const response = result.response;

  if (!response || !response.preferenceHistoryByTimeStamp) {
    historyPagination.hasMore = false;
    return;
  }
    Object.entries(response.preferenceHistoryByTimeStamp || {}).forEach(
      ([timestamp, list]) => {
        if (!window.preferenceHistory[timestamp]) {
          window.preferenceHistory[timestamp] = [];
        }
        window.preferenceHistory[timestamp].push(...list);
      }
    );

    historyPagination.page = response.page;
    historyPagination.hasMore = response.hasMore;

    renderHistory(window.preferenceHistory);
  } catch (e) {
    console.error("History scroll failed", e);

    // STOP infinite retry loop
    historyPagination.hasMore = false;
    historyPagination.failed = true;

  } finally {
    historyPagination.loading = false;
  }
}


document.addEventListener("DOMContentLoaded", () => {
  const container = document.querySelector(".widget-container");
  Array.from(container.children).forEach((child) => {
    if (!child.classList.contains("preview-statements")) {
      child.style.display = "none"; 
    }
  });

  const consentRoot = document.getElementById("consent-root");
  consentRoot.innerText = "Loading...";
});


function getSelectedByPosition(perm, selectedLang) {
  if (!perm.optedFor?.length || !perm.permissionTranslation) return [];

  const baseTr = perm.permissionTranslation[0];
  const targetTr = perm.permissionTranslation.find(
    pt => pt.language?.toLowerCase() === selectedLang
  );

  if (!baseTr?.options || !targetTr?.options) return [];

  return perm.optedFor
    .map(value => {
      const idx = baseTr.options.indexOf(value);
      return idx >= 0 ? targetTr.options[idx] : null;
    })
    .filter(Boolean);
}


function renderLanguageDropdown(data) {
  const langWrapper = document.getElementById("language-wrapper");
  const langSelect = document.getElementById("langSelect");

  const languages = (data.languages || []).map(l => l.toLowerCase());

  if (!showLanguageDropdown || languages.length === 0) {
    langWrapper.style.display = "none";
    return;
  }

  langWrapper.style.display = "block";
  langSelect.innerHTML = "";
  selectedLanguage = selectedLanguage || languages[0];

  languages.forEach(lang => {
    const opt = document.createElement("option");
    opt.value = lang;
    opt.text = lang.toUpperCase();
    if (lang === selectedLanguage) opt.selected = true;
    langSelect.appendChild(opt);
  });

	langSelect.onchange = async () => {
	  selectedLanguage = langSelect.value;

	  const request = buildFinalConsentRequest(selectedLanguage);

	  if (window.preferenceData?.currentPreference) {
		renderConsent(window.preferenceData, selectedLanguage);
	  }

	  if (!document.getElementById("historyTab").classList.contains("hidden")) {
		renderHistory(window.preferenceHistory, selectedLanguage);
	  }

	  await onSelectionChange(selectedLanguage, request);
	};
}


async function fetchConsentData() {
  try {
    const publicKey = await getPublicKeyB64();
    const browserSignature = await signPayload({ preferenceFormId });
    const baseBody = {
      preferenceFormId,
      page: 0,
      pageSize: 10,
      sortBy: "formName",
      sortDirection: "ASC"
    };
    if (publicKey) baseBody.bssk = publicKey;
    const res = await fetch(preferenceDetailsApiUrl, {
      method: "POST",
      headers: authHeaders(),
      credentials: "include",
      body: JSON.stringify({ ...baseBody, ...campaignLinkContext })
    });

const result = await handleApiResponse(res);
consentJwt = result.response.payload;
// decode JWT response
const decoded = decodeJwt(result.response.payload);

const payloadEncryptionEnabled = decoded.data.response.payloadEncryptionEnabled;
window.payloadEncryptionEnabled = payloadEncryptionEnabled;

const data = decoded?.data?.response?.data;

// NEW LINES YOU NEED TO ADD:
const sssk = decoded.sssk;
const bssk = decoded.bssk;
const nonce = decoded.nonce;

window.preferenceHistory = data.preferenceHistoryAgainstTimeStamp?.preferenceHistoryByTimeStamp || {};
if (data.currentPreference) {
  data.currentPreference.permissions =
    (data.currentPreference.permissions || [])
      .map(p => ({ ...p }))
      .sort((a, b) => String(a.id).localeCompare(String(b.id)));
}

window.preferenceData = data;

// OTP is required when any consent form in this preference center has it enabled (set by the backend in the JWT)
const otpSource = decoded?.data?.response || {};
otp.enabled = otpSource.otpEnabled === true;
otp.resendSeconds = Number(otpSource.resendTimerSeconds) > 0
  ? Number(otpSource.resendTimerSeconds)
  : DEFAULT_RESEND_SECONDS;

 if (data.golabalFontFamily) {
  const fontFamily = data.golabalFontFamily;
  if (!document.getElementById("consent-global-font")) {
    const style = document.createElement("style");
    style.id = "consent-global-font";
    style.innerHTML = `
      .widget-container input,
      .widget-container select,
      .widget-container textarea,
      .widget-container button,
  `;
    document.head.appendChild(style);
  }
}

// keep previously selected language after submit
selectedLanguage = selectedLanguage || data.languages?.[0]?.toLowerCase() || "englis";
renderLanguageDropdown(data);
handlePreferenceView(data.preferenceView);
if (data.currentPreference) {
  renderConsent(data, selectedLanguage);
    setTimeout(() => {
  onSelectionChange(selectedLanguage);
}, 0);
}

renderConsent(data, selectedLanguage);
    const container = document.querySelector(".widget-container");
    Array.from(container.children).forEach((child) => {
      child.style.display = "";
    });
    showOtpSection(currentActiveView !== "HISTORY");

} catch (e) {
  console.error("[CONSENT-WIDGET] fetchConsentData failed:", e);

  const consentRoot = document.getElementById("consent-root");

  consentRoot.innerText =
    e?.message || "Failed to load preference data.";

  const container = document.querySelector(".widget-container");

  if (container) {
    Array.from(container.children).forEach((child) => {
      child.style.display = "";
    });
  }
}

}

function showToast(message, type) {
  const toast = document.getElementById("toast");

  toast.textContent = message;
  toast.style.backgroundColor =
    type === "success" ? "#4CAF50" : "#f44336";

  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 2000);
}


function getFormValues(selectedLang) {
  createConsentRequestList = [];

  const consentDiv = document.getElementById("consent-root");
  const checkboxes = consentDiv.querySelectorAll('input[type="checkbox"]:checked');
  const radioButtons = consentDiv.querySelectorAll('input[type="radio"]:checked');
  const dropdowns = consentDiv.querySelectorAll("select");

  const pushConsent = (permissionId, optionId) => {
    let existing = createConsentRequestList.find(req => req.permissionId === permissionId);
    if (existing) {
      existing.optedForIndexes.push(parseInt(optionId));
    } else {
      createConsentRequestList.push({
        permissionId,
        customAttributes,
        consentReceivedType: receivedType,
        optedForIndexes: [parseInt(optionId)],
        consentLanguage: selectedLang
      });
    }
  };

  checkboxes.forEach(checkbox => {
    if (!enableCheckboxes) return;
    const optionId = checkbox.getAttribute("data-option-id") || "0";
    pushConsent(checkbox.name, optionId);
  });

  radioButtons.forEach(radio => {
    if (!enableRadioButtons) return;
    const optionId = radio.getAttribute("data-option-id") || "0";
    pushConsent(radio.name, optionId);
  });


 dropdowns.forEach(drop => {
    if (!enableDropdowns) return;

    const selected = drop.options[drop.selectedIndex];

    // Skip unselected dropdown
    if (!selected || !selected.value) return;

    const optionId = selected.getAttribute("data-option-id") || "0";
    pushConsent(drop.name, optionId);
  });

  document.querySelectorAll("#consent-root .ms-dropdown").forEach(ms => {
    if (!enableDropdowns) return;
    const permId = ms.getAttribute("data-perm-id");
    const checkedBoxes = ms.querySelectorAll('input[type="checkbox"]:checked');
    checkedBoxes.forEach(cb => {
      const optionId = cb.getAttribute("data-option-id") || "0";
      pushConsent(permId, optionId);
    });
  });

  document.querySelectorAll("#consent-root [name]").forEach(el => {
    if (el.tagName === "SELECT") {
      return;
    }
    if (!createConsentRequestList.some(req => req.permissionId === el.name)) {
      createConsentRequestList.push({
        customAttributes,
        permissionId: el.name,
        consentReceivedType: receivedType,
        optedForIndexes: [],
        consentLanguage: selectedLang
      });
    }
  });

  sendConsent();
}
  
// Always resolves to an object with success (consentWidget.submit() does not throw).
// OTP form: always resolves to an object with success (consentWidget.submit() does not throw).
// Without OTP it behaves as before: the response on success, nothing otherwise.
async function sendConsent() {
  // Read before the form may reload (a reload sets otp.enabled again)
  const otpSubmit = otp.enabled;
  setFormDisabled(true);
  submitting = true;
  updateSubmitReady();
  // Declared outside try so the Android bridge in finally can read it
  let data = {};
  try {
    createConsentRequestList.sort((a, b) =>
  String(a.permissionId).localeCompare(String(b.permissionId))
);
    const body = { createConsentRequestDtoWrapper: createConsentRequestList };
    if (storedSigning.bss) {
      body.bss = await signPayload(createConsentRequestList);
      body.sss = globalSSS;
      body.jwt=consentJwt;
    } else {
      const browserSignature = await signPayload(createConsentRequestList);
      if (browserSignature) body.bss = browserSignature;
      body.sss = globalSSS;
      body.jwt=consentJwt;
    }

    let requestBody;

    if (window.payloadEncryptionEnabled) {

        const encryptedPayload = await encryptPayload(body);

        requestBody = {
            payload: encryptedPayload
        };

    } else {

        requestBody = body;
    }

    const res = await fetch(submitApiUrl, {
        method: "POST",
        credentials: "include",
        headers: authHeaders(),
        body: JSON.stringify(requestBody)
    });

    data = await res.json();
    try {
      sessionStorage.setItem("consentResponse", JSON.stringify(data));
    } catch (e) {
      console.error("Storage failed:", e);
    }
    if (data.response && data.statusCode === 200) {
     showToast("Consent saved successfully!", "success");
     notifyConsentSubmitted(data);
     await new Promise(resolve => setTimeout(resolve, 3000));
     resetOtp();
     await fetchConsentData();
     setFormDisabled(false);
     return otpSubmit ? { ...data, success: true } : data;
    } else {
      const message = submitErrorMessage(data);
      showToast(message, "error");
      await new Promise(resolve => setTimeout(resolve, 3000));
      // Start again with a new form JWT; for an OTP form the submit used up the form session, so a new OTP is needed
      const otpWasVerified = otp.enabled && otp.stage === "verified";
      resetOtp();
      await reloadConsentForm();
      if (otpWasVerified) setOtpMessage(otpSubmitFailedMessage(data), "error");
      setFormDisabled(false);
      if (otpSubmit) return { ...data, success: false, message };
      }
  } catch (err) {
    console.error(err);
    const message = "Failed to submit. Please check your network connection.";
    showToast(message, "error");
    setFormDisabled(false);
    if (otpSubmit) return { success: false, message };
  } finally {
    submitting = false;
    updateSubmitReady();
    // Send response to Android WebView if available
    if (typeof window.AndroidBridge !== 'undefined' && 
        typeof window.AndroidBridge.onApiResponse === 'function') {
      try {
        window.AndroidBridge.onApiResponse(JSON.stringify(data));
      } catch (error) {
        console.error('Failed to send response to Android:', error);
      }
    }
  }
}



function isOptionSelected(perm, optionId, baseValue) {

  if (Array.isArray(perm.optedFor)) {
    return perm.optedFor.includes(baseValue);
  }

  if (perm.optedFor && typeof perm.optedFor === "object") {
    return !!perm.optedFor[optionId];
  }

  return false;
}

function isMandatoryField(perm) {
  const mandatoryValue = perm?.mandatory;

  if (typeof mandatoryValue === "boolean") return mandatoryValue;
  if (typeof mandatoryValue === "number") return mandatoryValue === 1;
  if (typeof mandatoryValue === "string") {
    const normalized = mandatoryValue.trim().toLowerCase();
    return normalized === "true" || normalized === "1" || normalized === "yes";
  }

  return false;
}


function renderConsent(data, selectedLang) {
  const root = document.getElementById("consent-root");
  root.innerHTML = "";

  const errorDiv = document.getElementById("error-message");
  errorDiv.innerHTML = "";

  const branding = data.currentPreference?.branding || {};
  const permissions = data.currentPreference?.permissions || [];
  currentBranding = branding;
  applyOtpLabels((selectedLang || "").toLowerCase());

  const logoArea = document.getElementById("logo-area");
  logoArea.innerHTML = "";
  logoArea.classList.remove("left", "center", "right");

  const align = (branding.logoAlignment || "left").toLowerCase();
  logoArea.classList.add(["left", "center", "right"].includes(align) ? align : "left");

  const wrapper = document.createElement("div");
  wrapper.style.display = "flex";

  if (align === "center") {
    wrapper.style.flexDirection = "column";
  } else if (align === "right") {
    wrapper.style.flexDirection = "row-reverse";
  } else {
    wrapper.style.flexDirection = "row";
  }

  wrapper.style.alignItems = "center";
  wrapper.style.gap = "5px";


  if (branding.logo) {
    const img = document.createElement("img");
    img.src = resolveAssetUrl(branding.logo);
    img.alt = branding.companyName || "Logo";
    img.className = "branding-logo";
    img.onerror = () => img.classList.add("hidden");
    wrapper.appendChild(img);
  }

  if (branding.companyName) {
    const nameDiv = document.createElement("div");
    nameDiv.innerText = branding.companyName;
    nameDiv.classList.add("company-name");

    if (branding.headerFontColor)
      nameDiv.style.color = branding.headerFontColor;
    if (branding.headerFontFamily)
      nameDiv.style.fontFamily = branding.headerFontFamily;
    if (branding.headerFontSize) {
      const sizeMap = {
        small: "14px",
        medium: "16px",
        large: "20px",
      };
      const sz = branding.headerFontSize.toLowerCase();
      nameDiv.style.fontSize =
        sizeMap[sz] || branding.headerFontSize;
    }
    if (branding.headerFontStyle) {
      const styleLower =
        branding.headerFontStyle.toLowerCase();
      if (styleLower.includes("italic"))
        nameDiv.style.fontStyle = "italic";
      if (styleLower.includes("bold"))
        nameDiv.style.fontWeight = "bold";
    }

    wrapper.appendChild(nameDiv);
  }

  logoArea.appendChild(wrapper);

 
  if (!permissions.length) {
    root.innerHTML = "<p>No consent items found.</p>";
    return;
  }

  permissions.forEach((perm) => {
  const block = document.createElement("div");
  block.className = "permission-block";
  block.setAttribute("data-permission-id", String(perm.id));

  const tr = perm.permissionTranslation?.find(
    (pt) => pt.language.toLowerCase() === selectedLang
  );

  const htmlString = tr?.text || perm.text || "";
  const tempDiv = document.createElement("div");
  tempDiv.innerHTML = htmlString;

  const children = Array.from(tempDiv.children);

  if (children.length > 0) {
    children.forEach((child) => {
      const el = document.createElement(child.tagName.toLowerCase());
      el.innerHTML = child.innerHTML;

      if (child.getAttribute("style")) {
        el.setAttribute("style", child.getAttribute("style"));
      }

      el.style.display = "block";
      el.style.lineHeight = "1";

      // Preserve paragraph spacing and explicit blank lines from editor content.
      if (child.tagName.toLowerCase() === "p") {
        const normalized = (child.innerHTML || "").replace(/&nbsp;/g, "").trim().toLowerCase();
        const childText = (child.textContent || "").trim();
        const isBlankParagraph =
          !childText &&
          (normalized === "" || normalized === "<br>" || normalized === "<br/>" || normalized === "<br />");

        el.style.margin = "0 0 5px 0";
        el.style.minHeight = "1em";
        if (isBlankParagraph) {
          el.innerHTML = "&nbsp;";
        }
      } else {
        el.style.margin = "2px 0";
      }

      block.appendChild(el);
    });

    if (isMandatoryField(perm)) {
      const lastChild = block.lastChild;
      if (lastChild && lastChild instanceof HTMLElement) {
        lastChild.innerHTML += ' <span class="mandatory">*</span>';
      }
    }
  } else {
    const p = document.createElement("p");
    p.textContent = htmlString.replace(/<[^>]*>/g, "");
    p.style.whiteSpace = "pre-wrap";
    p.style.margin = "0 0 5px 0";
    p.style.lineHeight = "1";

    if (isMandatoryField(perm)) {
      p.innerHTML += ' <span class="mandatory">*</span>';
    }

    block.appendChild(p);
  }
  const options = tr?.options || perm.options || [];
  const optionMap = perm.optionsMap || {};

  if (perm.elementType === "CHECKBOX" && enableCheckboxes) {
    if (Object.keys(optionMap).length > 0) {
      const mapEntries = Object.entries(optionMap);
      const translatedOptions = tr?.options || perm.options || [];
      mapEntries.forEach(([id, baseValue], index) => {
        const displayLabel = translatedOptions[index] || baseValue;
        const labelEl = document.createElement("label");
        const input = document.createElement("input");
        input.type = "checkbox";
        input.name = perm.id;
        input.value = baseValue;
        input.setAttribute("data-option-id", id);
        if (isOptionSelected(perm, id, baseValue)) input.checked = true;
        labelEl.appendChild(input);
        labelEl.append(" " + displayLabel);
        block.appendChild(labelEl);
      });
    } else {
      const selectedOptions = getSelectedByPosition(perm, selectedLang);
      options.forEach((opt) => {
        const label = document.createElement("label");
        const input = document.createElement("input");
        input.type = "checkbox";
        input.name = perm.id;
        input.value = opt;
        if (selectedOptions.includes(opt)) input.checked = true;
        label.appendChild(input);
        label.append(" " + opt);
        block.appendChild(label);
      });
    }
  }

  if (perm.elementType === "RADIOBUTTON" && enableRadioButtons) {
    if (Object.keys(optionMap).length > 0) {
      const mapEntries = Object.entries(optionMap);
      const translatedOptions = tr?.options || perm.options || [];
      mapEntries.forEach(([id, baseValue], index) => {
        const displayLabel = translatedOptions[index] || baseValue;
        const labelEl = document.createElement("label");
        const input = document.createElement("input");
        input.type = "radio";
        input.name = perm.id;
        input.value = baseValue;
        input.setAttribute("data-option-id", id);
        if (isOptionSelected(perm, id, baseValue)) input.checked = true;
        labelEl.appendChild(input);
        labelEl.append(" " + displayLabel);
        block.appendChild(labelEl);
      });
    } else {
      const selectedOptions = getSelectedByPosition(perm, selectedLang);
      options.forEach((opt) => {
        const label = document.createElement("label");
        const input = document.createElement("input");
        input.type = "radio";
        input.name = perm.id;
        input.value = opt;
        if (selectedOptions.includes(opt)) input.checked = true;
        label.appendChild(input);
        label.append(" " + opt);
        block.appendChild(label);
      });
    }
  }

  if (perm.elementType === "DROPDOWN" && enableDropdowns) {
    const optionEntries = Object.keys(optionMap).length > 0
      ? Object.entries(optionMap).map(([id, baseValue], index) => ({
          id,
          baseValue,
          label: (tr?.options || perm.options || [])[index] || baseValue
        }))
      : options.map((opt, idx) => ({ id: idx.toString(), baseValue: opt, label: opt }));

    if (perm.allowMultipleSelection) {
      const msDropdown = document.createElement("div");
      msDropdown.className = "ms-dropdown";
      msDropdown.setAttribute("data-perm-id", perm.id);

      const control = document.createElement("div");
      control.className = "ms-control";
      control.tabIndex = 0;

      const chips = document.createElement("div");
      chips.className = "ms-chips";

      const placeholder = document.createElement("span");
      placeholder.className = "ms-placeholder";
      placeholder.textContent = "Select Options";

      const arrow = document.createElement("span");
      arrow.className = "ms-arrow";
      arrow.textContent = "▾";

      const clearAll = document.createElement("span");
      clearAll.className = "ms-clear-all";
      clearAll.textContent = "✕";
      clearAll.setAttribute("aria-label", "Clear all selected options");
      clearAll.addEventListener("click", (e) => {
        e.stopPropagation();
        panel.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
          cb.checked = false;
        });
        refreshChips();
        onSelectionChange(selectedLang);
      });

      control.appendChild(chips);
      control.appendChild(placeholder);
      control.appendChild(clearAll);
      control.appendChild(arrow);

      const panel = document.createElement("div");
      panel.className = "ms-panel";
      panel.style.display = "none";

      const refreshChips = () => {
        chips.innerHTML = "";
        const checkedBoxes = panel.querySelectorAll('input[type="checkbox"]:checked');
        checkedBoxes.forEach(cb => {
          const chip = document.createElement("span");
          chip.className = "ms-chip";

          const label = document.createElement("span");
          label.textContent = cb.getAttribute("data-label") || cb.value;
          chip.appendChild(label);

          const remove = document.createElement("span");
          remove.className = "ms-chip-remove";
          remove.textContent = "✕";
          remove.addEventListener("click", (e) => {
            e.stopPropagation();
            cb.checked = false;
            refreshChips();
            onSelectionChange(selectedLang);
          });
          chip.appendChild(remove);

          chips.appendChild(chip);
        });
        placeholder.style.display = checkedBoxes.length ? "none" : "inline";
        control.classList.toggle("has-selection", checkedBoxes.length > 0);
      };

      optionEntries.forEach(entry => {
        const optionLabel = document.createElement("label");
        optionLabel.className = "ms-option";

        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.value = entry.baseValue;
        checkbox.setAttribute("data-option-id", entry.id);
        checkbox.setAttribute("data-label", entry.label);

        // Pre-check based on existing preference data (edit/reload case)
        if (isOptionSelected(perm, entry.id, entry.baseValue)) {
          checkbox.checked = true;
        }

        checkbox.addEventListener("change", () => {
          optionLabel.classList.toggle("ms-option-selected", checkbox.checked);
          refreshChips();
          panel.style.display = "none";
          control.classList.remove("open");
          onSelectionChange(selectedLang);
        });

        optionLabel.appendChild(checkbox);
        optionLabel.append(" " + entry.label);
        panel.appendChild(optionLabel);
      });

      control.addEventListener("click", (e) => {
        e.stopPropagation();
        const isOpen = panel.style.display === "block";
        document.querySelectorAll(".ms-panel").forEach(p => p.style.display = "none");
        document.querySelectorAll(".ms-control").forEach(c => c.classList.remove("open"));
        panel.style.display = isOpen ? "none" : "block";
        control.classList.toggle("open", !isOpen);
      });

      msDropdown.appendChild(control);
      msDropdown.appendChild(panel);
      refreshChips(); // reflect pre-checked boxes as chips immediately
      block.appendChild(msDropdown);
    } else {
        // Single-select custom dropdown (shares multiselect panel styling)
        const ssDropdown = document.createElement("div");
        ssDropdown.className = "ms-dropdown";
        ssDropdown.setAttribute("data-perm-id", perm.id);

        // Hidden native select keeps existing data-collection + validation working
        const select = document.createElement("select");
        select.name = perm.id;
        select.style.display = "none";

        const defaultOption = document.createElement("option");
        defaultOption.value = "";
        defaultOption.text = "Select options";
        defaultOption.selected = true;
        defaultOption.disabled = true;
        select.appendChild(defaultOption);

        optionEntries.forEach(entry => {
          const option = document.createElement("option");
          option.value = entry.baseValue;
          option.text = entry.label;
          option.setAttribute("data-option-id", entry.id);
          select.appendChild(option);
        });

        const control = document.createElement("div");
        control.className = "ms-control";
        control.tabIndex = 0;

        const valueText = document.createElement("span");
        valueText.className = "ms-chips ss-value";

        const placeholder = document.createElement("span");
        placeholder.className = "ms-placeholder";
        placeholder.textContent = "Select Options";

        const arrow = document.createElement("span");
        arrow.className = "ms-arrow";
        arrow.textContent = "▾";

        control.appendChild(valueText);
        control.appendChild(placeholder);
        control.appendChild(arrow);

        const panel = document.createElement("div");
        panel.className = "ms-panel";
        panel.style.display = "none";

        optionEntries.forEach(entry => {
          const optionLabel = document.createElement("label");
          optionLabel.className = "ms-option";
          optionLabel.textContent = entry.label;

          // Pre-select based on existing preference data (edit/reload case)
          if (isOptionSelected(perm, entry.id, entry.baseValue)) {
            select.value = entry.baseValue;
            valueText.textContent = entry.label;
            placeholder.style.display = "none";
            optionLabel.classList.add("ms-option-selected");
          }

          optionLabel.addEventListener("click", (e) => {
            e.stopPropagation();
            select.value = entry.baseValue;

            valueText.textContent = entry.label;
            placeholder.style.display = "none";

            panel.querySelectorAll(".ms-option").forEach(o => o.classList.remove("ms-option-selected"));
            optionLabel.classList.add("ms-option-selected");

            panel.style.display = "none";
            control.classList.remove("open");

            onSelectionChange(selectedLang);
          });

          panel.appendChild(optionLabel);
        });

        control.addEventListener("click", (e) => {
          e.stopPropagation();
          const isOpen = panel.style.display === "block";
          document.querySelectorAll(".ms-panel").forEach(p => p.style.display = "none");
          document.querySelectorAll(".ms-control").forEach(c => c.classList.remove("open"));
          panel.style.display = isOpen ? "none" : "block";
          control.classList.toggle("open", !isOpen);
        });

        ssDropdown.appendChild(select);
        ssDropdown.appendChild(control);
        ssDropdown.appendChild(panel);
        block.appendChild(ssDropdown);
      }
  }

  block.querySelectorAll("input, select").forEach(function(el) {
    if (el.closest(".ms-dropdown")) return; // ms-dropdown fires onSelectionChange directly
    el.addEventListener("change", function() { onSelectionChange(selectedLang); });
  });

  const statementError = document.createElement("div");
  statementError.className = "error-message statement-error";
  statementError.style.display = "none";
  block.appendChild(statementError);

  root.appendChild(block);
});

 

  const cancelBtn = document.getElementById("cancelBtn");
  const submitBtn = document.getElementById("submitBtn");

  const selectedLanguage = selectedLang?.toLowerCase();
  const translatedBranding =
    branding.brandingTranslation?.find(
      (b) => b.language?.toLowerCase() === selectedLanguage
    );

  const submitLabel =
    translatedBranding?.primaryButtonLabel ||
    branding.primaryButtonLabel ||
    "Submit";
  const cancelLabel =
    translatedBranding?.secondaryButtonLabel ||
    branding.secondaryButtonLabel ||
    "Cancel";

  currentLang = selectedLanguage;

  // OTP form: the primary button is Verify & Submit (one tap verifies the OTP and saves); Cancel stays as is
  if (showButtons) {
    cancelBtn.style.display = "block";
    cancelBtn.innerText = cancelLabel;

    submitBtn.style.display = "block";
    submitBtn.innerText = otp.enabled ? otpLabels.verifySubmit : submitLabel;
    submitBtn.disabled = true; // enabled by updateSubmitReady once signed

      submitBtn.style.backgroundColor =
        branding.primaryButtonbgColor;
    if (branding.primaryFontColor)
      submitBtn.style.color = branding.primaryFontColor;
    if (branding.primaryButtonborderColor)
      submitBtn.style.borderColor =
        branding.primaryButtonborderColor;
    if (branding.primaryFontSize)
      submitBtn.style.fontSize = branding.primaryFontSize;
    if (branding.primaryFontStyle) {
      submitBtn.style.fontStyle =
        branding.primaryFontStyle;
      submitBtn.style.fontWeight =
        branding.primaryFontStyle;
    }

    if (branding.secondaryButtonBgColor)
      cancelBtn.style.backgroundColor =
        branding.secondaryButtonBgColor;
    if (branding.secondaryFontColor)
      cancelBtn.style.color =
        branding.secondaryFontColor;
    if (branding.secondaryButtonBorderColor)
      cancelBtn.style.borderColor =
        branding.secondaryButtonBorderColor;
    if (branding.secondaryFontSize)
      cancelBtn.style.fontSize =
        branding.secondaryFontSize;
    if (branding.secondaryFontStyle) {
      cancelBtn.style.fontStyle =
        branding.secondaryFontStyle;
      cancelBtn.style.fontWeight =
        branding.secondaryFontStyle;
    }

    const buttonGroup =
      document.getElementById("button-group");
    const buttonFooterAlignment =
      data.currentPreference.branding?.footerAlignment ||
      footerAlignment;

    buttonGroup.classList.remove("left", "center", "right");

    if (buttonFooterAlignment === "center") {
      buttonGroup.classList.add("center");
    } else if (buttonFooterAlignment === "right") {
      buttonGroup.classList.add("right");
    } else {
      buttonGroup.classList.add("left");
    }
  } else {
    cancelBtn.style.display = "none";
    submitBtn.style.display = "none";
  }

  ensureOtpSection();
  updateSubmitReady();

clickEvent = async (e) => {
    if (e) {
        e.preventDefault();
    }

    // OTP form: consentWidget.submit() runs the same verify-then-save as Verify and Submit
    if (otp.enabled) {
        // The hidden Submit button's disabled state does not stop a programmatic consentWidget.submit()
        if (submitting) {
            return { success: false, message: OTP_TEXT.submitInProgress };
        }
        return await verifyAndSubmit();
    }

    // A preference center without OTP is submitted as before
    if (!validateMandatoryFields()) {
      showToast("Please fill all mandatory fields", "error");
      return;
    }

    const payload = buildFinalConsentRequest(selectedLanguage);
    createConsentRequestList = payload.createConsentRequestDtoWrapper;

    return await sendConsent();
};

validateMandatoryFields = () => {
    errorDiv.innerHTML = "";
    root.querySelectorAll(".statement-error").forEach((el) => {
      el.textContent = "";
      el.style.display = "none";
    });
    root.querySelectorAll(".error-border").forEach((el) => {
      el.classList.remove("error-border");
    });

    let isValid = true;

    permissions.forEach((perm) => {
        if (isMandatoryField(perm)) {
            const name = perm.id;
            let hasValue = false;

            if (
                perm.elementType === "CHECKBOX" ||
                perm.elementType === "RADIOBUTTON"
            ) {
                const inputs = root.querySelectorAll(
                    `input[name="${name}"]:checked`
                );
                if (inputs.length > 0) hasValue = true;
            } else if (perm.elementType === "DROPDOWN") {
                if (perm.allowMultipleSelection) {
                    const msEl = root.querySelector(`[data-perm-id="${name}"]`);
                    if (msEl && msEl.querySelectorAll('input[type="checkbox"]:checked').length > 0) hasValue = true;
                } else {
                    const select = root.querySelector(`select[name="${name}"]`);
                    if (select && select.value) hasValue = true;
                }
            }

            if (!hasValue) {
                isValid = false;

              const statementError = root.querySelector(
                `.permission-block[data-permission-id="${name}"] .statement-error`
              );
              if (statementError) {
                statementError.textContent = "This field is required.";
                statementError.style.display = "block";
              }

                root.querySelectorAll(`[name="${name}"]`)
                    .forEach(el => el.classList.add("error-border"));
              root.querySelectorAll(`.ms-dropdown[data-perm-id="${name}"] .ms-control`)
                .forEach(el => el.classList.add("error-border"));
            }
        }
    });

    return isValid;
};

submitBtn.onclick = clickEvent;

cancelBtn.onclick = async () => {
  if (window.preferenceData?.currentPreference) {
    // Reset form to original state
    renderConsent(window.preferenceData, selectedLanguage);

    // Clear previous signature state
    globalSSS = null;
    isSSSValid = false;
    resetOtp();

    const submitBtn = document.getElementById("submitBtn");
    if (submitBtn) {
      submitBtn.disabled = true;
    }

    // Generate fresh BSS + SSS for restored selections
    await onSelectionChange(selectedLanguage);
  }
};
}

function switchToCurrent() {
  document
    .getElementById("consent-root")
    .classList.remove("hidden");
  document
    .getElementById("historyTab")
    .classList.add("hidden");

  document
    .getElementById("tab-current")
    .classList.add("active");
  document
    .getElementById("tab-history")
    .classList.remove("active");

  document.getElementById("logo-area").style.display =
    "block";
  toggleFooterButtons(true);
  
    if (window.preferenceData?.currentPreference) {
    renderConsent(window.preferenceData, selectedLanguage);
  }

  currentActiveView = "CURRENT";
  const downloadBtn = document.getElementById("downloadHistoryBtn");
  downloadBtn.classList.remove("hidden");
  downloadBtn.innerHTML = '<i class="ri-download-2-line"></i> Download Current Preference';
}

function switchToHistory() {
  document
    .getElementById("consent-root")
    .classList.add("hidden");
  document
    .getElementById("historyTab")
    .classList.remove("hidden");

  document
    .getElementById("tab-current")
    .classList.remove("active");
  document
    .getElementById("tab-history")
    .classList.add("active");

  document.getElementById("logo-area").style.display =
    "none";
  toggleFooterButtons(false);

if (window.preferenceHistory) {
  renderHistory(window.preferenceHistory, selectedLanguage);
}
  currentActiveView = "HISTORY";
  const downloadBtn = document.getElementById("downloadHistoryBtn");
  downloadBtn.classList.remove("hidden");
  downloadBtn.innerHTML = '<i class="ri-download-2-line"></i> Download Preference History';
  attachHistoryScroll();

}

function handlePreferenceView(view) {
  const tabs = document.getElementById("pc-tabs");
  const tabCurrent = document.getElementById("tab-current");
  const tabHistory = document.getElementById("tab-history");

  tabs.classList.add("d-none");

  if (view === "CURRENT_PREFERENCE") {
    tabs.classList.remove("d-none");
    tabHistory.style.display = "none";
    tabCurrent.style.display = "block";
    tabCurrent.classList.remove("pc-tab");
    tabCurrent.style.fontWeight = "bold"; 
    switchToCurrent();
  }

  if (view === "PREFERENCE_HISTORY") {
    tabs.classList.remove("d-none");
    tabCurrent.style.display = "none";
    tabHistory.style.display = "block";
    tabHistory.classList.remove("pc-tab");
    tabHistory.style.fontWeight = "bold"; 
    switchToHistory();
  }

  if (view === "BOTH") {
    tabs.classList.remove("d-none");
    tabCurrent.style.display = "block";
    tabHistory.style.display = "block";
    switchToCurrent();
  }
}

// The OTP section belongs to the current preference; the history view hides it with the footer
function showOtpSection(show) {
  const section = document.getElementById("otp-section");
  if (section) section.style.display = show ? "" : "none";
}

function toggleFooterButtons(show) {
  const cancelBtn = document.getElementById("cancelBtn");
  const submitBtn = document.getElementById("submitBtn");
  const footer = document.getElementById("button-group");
  const footerBorder = document.getElementById("full-width-footer-border");
  showOtpSection(show);

  if (!show) {
    cancelBtn.style.display = "none";
    submitBtn.style.display = "none";
    footer.style.display = "none";
    footerBorder.classList.add("hidden"); 
  } else {
    footer.style.display = "flex";
    cancelBtn.style.display = "block";
    submitBtn.style.display = "block";
    footerBorder.classList.remove("hidden");
  }
  
}

function renderHistory(historyDto, selectedLang = "en") {
  const historyRoot = document.getElementById("historyTab");
  historyRoot.innerHTML = "";
  historyRoot.classList.add("history-scroll");

  if (!historyDto || Object.keys(historyDto).length === 0) {
    historyRoot.innerHTML = "<p>No preference history available.</p>";
    return;
  }

  Object.keys(historyDto)
    .sort((a, b) => new Date(b) - new Date(a))
    .forEach((timestamp) => {
      const record = document.createElement("div");
      record.className = "history-record";

      
      const dateHeader = document.createElement("div");
      dateHeader.className = "history-date";
      const date = new Date(timestamp);
      const datePart = date.toLocaleDateString("en-US", {
        month: "short",
        day: "2-digit",
        year: "numeric",
      });

const timePart = date.toLocaleTimeString("en-GB", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const icon = document.createElement("i");
icon.className = "ri-calendar-2-line me-2 fs-5 big-icon";


dateHeader.innerHTML = "";
dateHeader.appendChild(icon);
dateHeader.append(" ", datePart, " | ", timePart);

      record.appendChild(dateHeader);

const row = document.createElement("div");
  historyDto[timestamp].forEach(item => {
    const line = document.createElement("div");
    line.className = "history-row";
const permissionContent = document.createElement("div");
permissionContent.className = "history-permission-content";
permissionContent.innerHTML = item.permission || "";
line.appendChild(permissionContent);

const optedText = item.optedFor?.length
  ? item.optedFor
      .map(opt => opt.charAt(0).toUpperCase() + opt.slice(1))
      .join(", ")
  : "No selection";
const value = document.createElement("span");
value.className = "value";
value.textContent = optedText;
line.append(" ");
line.appendChild(value);
    row.appendChild(line);
  });

  record.appendChild(row);
  historyRoot.appendChild(record);
    });
}

document.getElementById("tab-current").addEventListener("click", switchToCurrent);
document.getElementById("tab-history").addEventListener("click", switchToHistory);
document.getElementById("downloadHistoryBtn").addEventListener("click", downloadPreferenceHistory);

async function downloadPreferenceHistory() {
  const downloadBtn = document.getElementById("downloadHistoryBtn");
  if (downloadBtn) downloadBtn.classList.add("loading");

  try {
    const body = {
      preferenceFormId,
      page: 0,
      pageSize: 1000,
      sortBy: "formName",
      sortDirection: "ASC",
      type: currentActiveView 
    };

    if (currentActiveView === "CURRENT") body.language = selectedLanguage;

    const browserSignature = await signPayload(body);
    if (browserSignature) body.bss = browserSignature;

    const res = await fetch(downloadHistoryPdfApiUrl, {
      method: "POST",
      headers: authHeaders(),
      credentials: "include",
      body: JSON.stringify({ ...body, ...campaignLinkContext })
    });

    if (!res.ok) {
      let msg = "Failed to download preference history.";
      try {
        const err = await res.json();
        msg = err?.statusMessage || msg;
      } catch (e) {}
      showToast(msg, "error");
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    const formName = String(window.preferenceData?.name || window.consentWidgetConfig.preferenceFormName || "preference").trim();
    const filenamePrefix = currentActiveView === "CURRENT" ? "current-preference" : "preference-history";
    const timestamp = new Date().toISOString().slice(0, 19).replace("T", "_").replace(/:/g, "-");
    link.download = filenamePrefix + "_" + formName.replace(/[\\/:*?"<>|\x00-\x1f]/g, "_") + "_" + timestamp + ".pdf";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

  } catch (e) {
    console.error("Download preference history failed:", e);
    showToast("Failed to download. Please check your network connection.", "error");
  } finally {
    if (downloadBtn) downloadBtn.classList.remove("loading");
  }
}

let submitting = false;
let lastSubmitReady = null;

// ── OTP verification state (forms with otpEnabled) ──
const OTP_LENGTH = 6;
const DEFAULT_RESEND_SECONDS = 30;
const otp = {
  enabled: false,
  resendSeconds: DEFAULT_RESEND_SECONDS,
  stage: "idle",        // idle: Generate OTP | sent: enter OTP | verified: OTP verified, consent not saved yet
  mobile: "",           // contact the OTP was sent to; verify must use the same values
  email: "",
  blockedUntil: 0,      // Generate / Resend disabled until then (resend cooldown or lockout)
  clearMessageOnUnblock: false,
  busy: false,
  message: "",
  messageType: ""
};
let otpTicker = null;

// ── OTP verification ──
// Generate OTP -> Verify and Submit (one tap verifies the OTP and saves the consent).
const OTP_DEFAULT_LABELS = {"title":"OTP Based Consent Verification","generate":"Generate OTP","info":"We'll send an OTP to your mobile number for verification.","enterOtp":"Enter 6 Digit OTP","verifySubmit":"Verify & Submit","resend":"Resend OTP","sentTo":"Enter 6 digit OTP sent to your mobile number ending with","verifiedTitle":"Verification Completed","verified":"Your identity has been verified successfully."};
let otpLabels = Object.assign({}, OTP_DEFAULT_LABELS);

// Widget messages; responseMessage from the OTP service is shown as received
const OTP_TEXT = {
  invalidMobile: "Please provide a valid 10-digit mobile number.",
  invalidEmail: "Please provide a valid email address.",
  sendFailed: "Could not send the OTP. Please try again.",
  verifyFailed: "Unable to verify OTP. Please try again.",
  otpExpired: "Your OTP has expired. Please generate a new OTP.",
  generic: "Something went wrong. Please try again.",
  serviceUnavailable: "The OTP service is unavailable. Please try again later.",
  sessionExpired: "Your session has expired, please try submitting the consent again.",
  contactChanged: "The mobile number or email has changed. Please generate a new OTP.",
  generateFirst: "Please generate an OTP first.",
  enterOtp: "Please enter the 6-digit OTP.",
  mandatory: "Please fill all mandatory fields",
  notSigned: "Your consent selection could not be verified. Please try again.",
  verificationExpired: "Your OTP verification has expired. Please generate a new OTP.",
  saveFailedRetry: "Your consent could not be sent. Please check your connection and submit again.",
  saveFailedNewOtp: "Your consent was not saved. Please generate a new OTP and submit again.",
  submitInProgress: "The consent is being submitted. Please wait."
};

// Answers meaning the form session (form JWT and its nonce) has ended: expired, already used, or replaced by the
// form JWT of a later Generate / Resend OTP
const FORM_SESSION_ERRORS = ["INVALID_JWT_TOKEN", "JWT_TOKEN_EXPIRED", "NONCE_MISSING", "INVALID_NONCE", "NONCE_ALREADY_USED"];

const OTP_INFO_ICON = '<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 11v6M12 7v1" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
const OTP_SUCCESS_ICON = '<svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 12.5l2.5 2.5 5.5-5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

// OTP texts are English in every language for now; per-language OTP texts will come later
function applyOtpLabels() {
  otpLabels = Object.assign({}, OTP_DEFAULT_LABELS);
}

// OTP forms: Verify & Submit can run once the 6 digits are entered, or right away when the OTP is already
// verified (the save request did not get through and is sent again).
function isOtpSubmitReady() {
  if (!otp.enabled) return true;
  if (otp.busy) return false;
  if (otp.stage === "verified") return true;
  return otp.stage === "sent" && readOtpInput().length === OTP_LENGTH;
}

// Ready to submit: the selection is signed and verified, the OTP part is ready (OTP forms) and no submit is running.
// Enables the widget's Submit / Verify and Submit and tells the parent page through onSubmitReady, only when the
// state changes.
function updateSubmitReady() {
  const ready = isSelectionSigned() && !submitting && isOtpSubmitReady();
  const submitBtn = document.getElementById("submitBtn");
  if (submitBtn && !submitBtn.classList.contains("loading")) submitBtn.disabled = !ready;
  refreshVerifySubmitButton();

  if (ready === lastSubmitReady) return;
  lastSubmitReady = ready;
  const callback = (window.consentWidgetConfig || {}).onSubmitReady;
  if (typeof callback !== "function") return;
  try {
    callback(ready);
  } catch (e) {
    console.error("[SDP] onSubmitReady callback failed:", e);
  }
}

// .../open-api/v1/consent/v1/sendOtp and verifyOtp, for a consent form and a preference center alike
// (the form JWT tells the backend which one); defaults to the folder of the submit API.
function otpApiUrl(name) {
  const cfg = window.consentWidgetConfig || {};
  const configured = name === "sendOtp" ? cfg.sendOtpApiUrl : cfg.verifyOtpApiUrl;
  return configured || String(submitApiUrl).replace(/\/(consent|preference)\/v1\/createOrUpdateConsent$/, "/consent/v1/" + name);
}

// 10-digit Indian mobile starting with 6-9; spaces, hyphens, +91 and a leading 0 are stripped. "" when invalid.
function normalizeMobile(value) {
  let mobile = String(value == null ? "" : value).replace(/[ -]/g, "");
  if (mobile.indexOf("+91") === 0) mobile = mobile.slice(3);
  else if (mobile.length === 12 && mobile.indexOf("91") === 0) mobile = mobile.slice(2);
  if (mobile.length === 11 && mobile.charAt(0) === "0") mobile = mobile.slice(1);
  return /^[6-9][0-9]{9}$/.test(mobile) ? mobile : "";
}

// Mobile and email are set by the parent page (touchpoint 1) and read when they are used, not on load.
function readOtpContact() {
  const cfg = window.consentWidgetConfig || {};
  return { mobile: normalizeMobile(cfg.mobile), email: String(cfg.email || "").trim() };
}

async function postOtp(name, body) {
  const res = await fetch(otpApiUrl(name), {
    method: "POST",
    headers: authHeaders(),
    credentials: "include",
    body: JSON.stringify(Object.assign({ jwt: consentJwt }, body))
  });
  const payload = await res.json().catch(() => ({}));
  return { ok: res.ok, payload: payload || {} };
}

function otpErrorMessage(payload) {
  if (payload.statusMessage === "INVALID_MOBILE") return OTP_TEXT.invalidMobile;
  if (payload.statusMessage === "INVALID_EMAIL") return OTP_TEXT.invalidEmail;
  if (payload.statusMessage === "OTP_SERVICE_UNAVAILABLE" || payload.statusCode === 503) return OTP_TEXT.serviceUnavailable;
  return OTP_TEXT.generic;
}

// The form session of the OTP request has ended (expired, used, or replaced by a later Generate / Resend OTP)
function isOtpSessionExpired(payload) {
  return !!payload && FORM_SESSION_ERRORS.indexOf(payload.statusMessage) >= 0;
}

// Message for a failed submit; the backend's OTP_VERIFICATION_REQUIRED, and for an OTP form an ended form session
// (e.g. JWT_TOKEN_EXPIRED), are shown as the widget's own text. A form without OTP shows the status as before.
function submitErrorMessage(data) {
  const status = data && data.statusMessage;
  if (status === "OTP_VERIFICATION_REQUIRED") return OTP_TEXT.verificationExpired;
  if (otp.enabled && FORM_SESSION_ERRORS.indexOf(status) >= 0) return OTP_TEXT.sessionExpired;
  return status || "Something went wrong.";
}

// OTP section message after a failed submit of an OTP form: the submit used up the form session, so the form is
// reloaded and a new OTP is needed
function otpSubmitFailedMessage(data) {
  const status = data && data.statusMessage;
  if (status === "OTP_VERIFICATION_REQUIRED") return OTP_TEXT.verificationExpired;
  if (FORM_SESSION_ERRORS.indexOf(status) >= 0) return OTP_TEXT.sessionExpired;
  return OTP_TEXT.saveFailedNewOtp;
}

// New form JWT and back to Generate OTP, with the message on the OTP section
async function restartOtpSession(message) {
  resetOtp();
  try {
    await reloadConsentForm();
  } catch (e) {
    console.error("[SDP-OTP] reloading the form failed:", e);
  }
  setOtpMessage(message, "error");
}

// SUD callback (touchpoint 2), read when used. An error in SUD's code must not break the widget.
function notifyConsentSubmitted(response) {
  const callback = (window.consentWidgetConfig || {}).onConsentSubmitted;
  if (typeof callback !== "function") return;
  try {
    callback(response);
  } catch (e) {
    console.error("[SDP] onConsentSubmitted callback failed:", e);
  }
}

function otpElement(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text) el.textContent = text;
  return el;
}

function otpHint(text) {
  const hint = otpElement("span", "otp-hint");
  hint.innerHTML = OTP_INFO_ICON;
  hint.appendChild(otpElement("span", "", text));
  return hint;
}

function otpPrimaryButton(id, label, onClick) {
  const btn = otpElement("button", "otp-primary", label);
  btn.type = "button";
  btn.id = id;
  if (currentBranding.primaryButtonbgColor) btn.style.backgroundColor = currentBranding.primaryButtonbgColor;
  if (currentBranding.primaryFontColor) btn.style.color = currentBranding.primaryFontColor;
  if (currentBranding.primaryButtonborderColor) btn.style.borderColor = currentBranding.primaryButtonborderColor;
  btn.addEventListener("click", onClick);
  return btn;
}

// The OTP section sits between the statements and the footer, so it stays visible while the statements scroll.
// It stays visible when showButtons is false; only Submit / Cancel are hidden then.
function ensureOtpSection() {
  let section = document.getElementById("otp-section");
  if (!otp.enabled) {
    if (section) section.remove();
    stopOtpTicker();
    return;
  }
  if (section) {
    // Language changed: re-render the texts, keep the digits typed so far
    const typed = readOtpInput();
    renderOtpSection();
    otpDigitInputs().forEach((input, i) => { input.value = typed.charAt(i); });
    updateOtpControls();
    return;
  }

  section = otpElement("div", "otp-section");
  section.id = "otp-section";
  const statements = document.querySelector(".preview-statements");
  if (!statements || !statements.parentNode) return;
  statements.parentNode.insertBefore(section, statements.nextSibling);
  renderOtpSection();
}

function renderOtpSection() {
  const section = document.getElementById("otp-section");
  if (!section) return;
  section.replaceChildren();

  if (otp.stage === "verified") {
    // OTP verified, consent not saved yet (the save is running, or did not get through and is sent again with the
    // footer's Verify & Submit)
    section.appendChild(otpElement("div", "otp-title", otpLabels.verifiedTitle));
    const success = otpElement("div", "otp-success");
    success.innerHTML = OTP_SUCCESS_ICON;
    success.appendChild(otpElement("span", "", otpLabels.verified));
    section.appendChild(success);
    const message = otpElement("div", "otp-message");
    message.id = "otpMessage";
    message.setAttribute("role", "status");
    section.appendChild(message);
  } else {
    section.appendChild(otpElement("div", "otp-title", otpLabels.title));
    const box = otpElement("div", "otp-box");

    if (otp.stage === "sent") {
      const label = otpElement("label", "otp-label", otpLabels.enterOtp + " ");
      label.appendChild(otpElement("span", "mandatory", "*"));
      box.appendChild(label);

      const row = otpElement("div", "otp-row");
      row.appendChild(buildOtpInputs());
      // Verify & Submit is the footer's primary button (with showButtons: false the parent page's button, which
      // calls consentWidget.submit())
      const resend = otpElement("button", "otp-link", otpLabels.resend);
      resend.type = "button";
      resend.id = "otpResendBtn";
      if (currentBranding.primaryButtonbgColor) resend.style.color = currentBranding.primaryButtonbgColor;
      resend.addEventListener("click", onGenerateOtp);
      row.appendChild(resend);
      box.appendChild(row);

      const sentHint = otpHint(otpLabels.sentTo + " ****" + otp.mobile.slice(-2));
      sentHint.classList.add("otp-sent-hint");
      box.appendChild(sentHint);
    } else {
      const row = otpElement("div", "otp-row");
      row.appendChild(otpPrimaryButton("otpGenerateBtn", otpLabels.generate, onGenerateOtp));
      row.appendChild(otpHint(otpLabels.info));
      box.appendChild(row);
    }

    const message = otpElement("div", "otp-message");
    message.id = "otpMessage";
    message.setAttribute("role", "status");
    box.appendChild(message);
    section.appendChild(box);
  }
  updateOtpControls();
}

function buildOtpInputs() {
  const wrap = otpElement("div", "otp-inputs");
  for (let i = 0; i < OTP_LENGTH; i++) {
    const input = otpElement("input", "otp-digit");
    input.type = "text";
    input.setAttribute("inputmode", "numeric");
    input.setAttribute("pattern", "[0-9]*");
    input.setAttribute("autocomplete", i === 0 ? "one-time-code" : "off");
    input.setAttribute("aria-label", "OTP digit " + (i + 1));

    input.addEventListener("input", () => {
      const digits = input.value.replace(/[^0-9]/g, "");
      if (digits.length > 1) {
        // SMS autofill puts the whole code in one box
        fillOtpDigits(i, digits);
      } else {
        input.value = digits;
        if (digits && i < OTP_LENGTH - 1) wrap.children[i + 1].focus();
      }
      updateOtpControls();
    });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !input.value && i > 0) wrap.children[i - 1].focus();
      if (e.key === "Enter" && showButtons && readOtpInput().length === OTP_LENGTH) onVerifyAndSubmitClick();
    });
    input.addEventListener("paste", (e) => {
      e.preventDefault();
      const text = (e.clipboardData || window.clipboardData).getData("text") || "";
      fillOtpDigits(i, text.replace(/[^0-9]/g, ""));
      updateOtpControls();
    });
    wrap.appendChild(input);
  }
  return wrap;
}

function otpDigitInputs() {
  return Array.from(document.querySelectorAll("#otp-section .otp-digit"));
}

function fillOtpDigits(start, digits) {
  const inputs = otpDigitInputs();
  if (!digits) return;
  let last = start;
  for (let j = 0; j < digits.length && start + j < inputs.length; j++) {
    inputs[start + j].value = digits.charAt(j);
    last = start + j;
  }
  inputs[Math.min(last + 1, inputs.length - 1)].focus();
}

function readOtpInput() {
  return otpDigitInputs().map(input => input.value).join("");
}

function clearOtpInputs() {
  const inputs = otpDigitInputs();
  inputs.forEach(input => { input.value = ""; });
  if (inputs[0]) inputs[0].focus();
}

function formatOtpWait(seconds) {
  if (seconds < 60) return seconds + "s";
  const rest = seconds % 60;
  return Math.floor(seconds / 60) + ":" + (rest < 10 ? "0" : "") + rest;
}

function setOtpMessage(message, type) {
  otp.message = message || "";
  otp.messageType = type || "";
  updateOtpControls();
}

function blockOtpFor(seconds, clearMessageOnUnblock) {
  otp.blockedUntil = seconds > 0 ? Date.now() + seconds * 1000 : 0;
  otp.clearMessageOnUnblock = !!clearMessageOnUnblock;
}

// Updates enabled states, countdown labels and the message without rebuilding the section (keeps typed digits).
function updateOtpControls() {
  const waitSeconds = Math.max(0, Math.ceil((otp.blockedUntil - Date.now()) / 1000));
  if (!waitSeconds && otp.clearMessageOnUnblock) {
    otp.clearMessageOnUnblock = false;
    otp.message = "";
    otp.messageType = "";
  }
  const countdown = waitSeconds > 0 ? " (" + formatOtpWait(waitSeconds) + ")" : "";

  const generateBtn = document.getElementById("otpGenerateBtn");
  if (generateBtn) {
    generateBtn.disabled = otp.busy || waitSeconds > 0;
    generateBtn.classList.toggle("loading", otp.busy);
    generateBtn.textContent = otpLabels.generate + countdown;
  }

  const resendBtn = document.getElementById("otpResendBtn");
  if (resendBtn) {
    resendBtn.disabled = otp.busy || waitSeconds > 0;
    resendBtn.textContent = otpLabels.resend + countdown;
  }

  otpDigitInputs().forEach(input => { input.disabled = otp.busy || submitting; });

  const messageEl = document.getElementById("otpMessage");
  if (messageEl) {
    messageEl.textContent = otp.message;
    messageEl.className = "otp-message" + (otp.messageType ? " " + otp.messageType : "");
  }

  if (waitSeconds > 0) startOtpTicker();
  else stopOtpTicker();

  // Also refreshes Verify and Submit (digits typed, busy) and tells the parent page through onSubmitReady
  updateSubmitReady();
}

// Verify and Submit is enabled once the 6 digits are entered, or right away to retry a failed save
// OTP form: the footer's primary button is Verify & Submit. It is enabled once the 6 digits are entered (or, after a
// network error, to send the save again) and shows the loading state while the OTP is verified and the consent saved.
// Forms without OTP keep their Submit as before.
function refreshVerifySubmitButton() {
  if (!otp.enabled) return;
  const submitBtn = document.getElementById("submitBtn");
  if (!submitBtn) return;
  const working = otp.busy || submitting;
  submitBtn.classList.toggle("loading", working);
  submitBtn.disabled = working || !(isSelectionSigned() && isOtpSubmitReady());
}

function startOtpTicker() {
  if (!otpTicker) otpTicker = setInterval(updateOtpControls, 1000);
}

function stopOtpTicker() {
  if (otpTicker) {
    clearInterval(otpTicker);
    otpTicker = null;
  }
}

// Back to Generate OTP. The resend cooldown / lockout is kept, sdp-otp-service enforces it anyway.
function resetOtp() {
  otp.stage = "idle";
  otp.mobile = "";
  otp.email = "";
  otp.busy = false;
  otp.message = "";
  otp.messageType = "";
  renderOtpSection();
  updateSubmitReady();
}

// Ends the current OTP after a failed verify: Generate OTP again, after the lockout when there is one.
function endOtpAttempt(retryAfterSeconds) {
  otp.stage = "idle";
  blockOtpFor(retryAfterSeconds, true);
  renderOtpSection();
}

// Generate OTP and Resend OTP
async function onGenerateOtp() {
  if (otp.busy) return;
  setOtpMessage("", "");

  const contact = readOtpContact();
  if (!contact.mobile) {
    setOtpMessage(OTP_TEXT.invalidMobile, "error");
    return;
  }

  otp.busy = true;
  updateOtpControls();
  try {
    // language picks the OTP message template; the backend falls back to English when it has none for it
    const language = typeof currentLang === "string" && currentLang ? currentLang : "en";
    const { ok, payload } = await postOtp("sendOtp", { mobile: contact.mobile, email: contact.email, language });
    if (!ok && isOtpSessionExpired(payload)) {
      await restartOtpSession(OTP_TEXT.sessionExpired);
    } else if (!ok) {
      setOtpMessage(otpErrorMessage(payload), "error");
    } else if (payload.responseCode === 200) {
      // The form session restarted with the OTP: use the new form JWT from now on (the previous one can no longer
      // be used). An older backend sends none; the current form JWT is kept then.
      if (typeof payload.jwt === "string" && payload.jwt) consentJwt = payload.jwt;
      otp.mobile = contact.mobile;
      otp.email = contact.email;
      otp.stage = "sent";
      otp.message = "";
      otp.messageType = "";
      blockOtpFor(otp.resendSeconds, false);
      otp.busy = false;
      renderOtpSection();
      clearOtpInputs();
    } else if (payload.responseCode === 205) {
      // Resend cooldown, too many OTP requests, or locked out after wrong OTPs
      blockOtpFor(Number(payload.retryAfterSeconds) || 0, true);
      setOtpMessage(payload.responseMessage || OTP_TEXT.sendFailed, "error");
    } else {
      setOtpMessage(payload.responseMessage || OTP_TEXT.sendFailed, "error");
    }
  } catch (e) {
    console.error("[SDP-OTP] sendOtp failed:", e);
    setOtpMessage(OTP_TEXT.generic, "error");
  } finally {
    otp.busy = false;
    updateOtpControls();
  }
}

function onVerifyAndSubmitClick() {
  verifyAndSubmit();
}

function otpFailure(message) {
  setOtpMessage(message, "error");
  return { success: false, message };
}

// Verify and Submit (the widget's button, or consentWidget.submit() for an OTP form). One tap:
//   1. checks the mandatory fields and the selection signing; when one fails, the OTP is not used
//   2. verifies the OTP, unless it is already verified in this form session (the save request did not get
//      through and is sent again)
//   3. saves the consent straight away; a failed save ends the form session and a new OTP is needed
// Always resolves to an object with success; never throws.
async function verifyAndSubmit() {
  if (otp.busy || submitting) return { success: false, message: OTP_TEXT.submitInProgress };
  if (otp.stage === "idle") return otpFailure(OTP_TEXT.generateFirst);

  // The OTP is checked only against the contact it was sent to; the backend records that contact on verify
  const contact = readOtpContact();
  if (contact.mobile !== otp.mobile || contact.email !== otp.email) {
    resetOtp();
    return otpFailure(OTP_TEXT.contactChanged);
  }
  if (otp.stage === "sent" && readOtpInput().length !== OTP_LENGTH) return otpFailure(OTP_TEXT.enterOtp);

  setOtpMessage("", "");
  otp.busy = true; // also blocks a second tap while the fields are checked
  updateOtpControls();
  let prepared;
  try {
    prepared = await prepareConsentSubmit();
  } catch (e) {
    console.error("[SDP-OTP] preparing the submit failed:", e);
    prepared = { ok: false, message: OTP_TEXT.generic };
  } finally {
    otp.busy = false;
    updateOtpControls();
  }
  if (!prepared || !prepared.ok) return otpFailure((prepared && prepared.message) || OTP_TEXT.generic);

  if (otp.stage !== "verified") {
    const verified = await verifyOtpCode();
    if (!verified.ok) return { success: false, message: verified.message };
  }

  const result = await sendConsent();
  if (!result.success && otp.enabled && otp.stage === "verified") {
    // The save request did not get through (network error) and the form session is kept: the next tap sends it
    // again with the verified OTP. If it did reach the server, that tap gets "session expired" and a new OTP is needed.
    setOtpMessage(OTP_TEXT.saveFailedRetry, "error");
  }
  updateOtpControls();
  return result;
}

// Verifies the entered OTP; resolves to { ok, message }
async function verifyOtpCode() {
  otp.busy = true;
  updateOtpControls();
  try {
    const { ok, payload } = await postOtp("verifyOtp", { mobile: otp.mobile, email: otp.email, otp: readOtpInput() });
    return await handleVerifyOtpResult(ok, payload);
  } catch (e) {
    console.error("[SDP-OTP] verifyOtp failed:", e);
    setOtpMessage(OTP_TEXT.generic, "error");
    return { ok: false, message: OTP_TEXT.generic };
  } finally {
    otp.busy = false;
    updateOtpControls();
  }
}

// Handles the verify response as per the OTP error table; resolves to { ok, message }
async function handleVerifyOtpResult(ok, payload) {
  if (!ok) {
    if (isOtpSessionExpired(payload)) {
      await restartOtpSession(OTP_TEXT.sessionExpired);
      return { ok: false, message: OTP_TEXT.sessionExpired };
    }
    const errorMessage = otpErrorMessage(payload);
    setOtpMessage(errorMessage, "error");
    return { ok: false, message: errorMessage };
  }
  // The OTP service's message as received; 203 (OTP expired, already used or never sent) has its own fallback.
  // An expired OTP is not an expired form session: the form session restarts with every Generate / Resend OTP.
  const message = payload.responseMessage
    || (payload.responseCode === 203 ? OTP_TEXT.otpExpired : OTP_TEXT.verifyFailed);
  const retryAfterSeconds = Number(payload.retryAfterSeconds) || 0;

  switch (payload.responseCode) {
    case 200:
      otp.stage = "verified";
      otp.message = "";
      otp.messageType = "";
      // Verified: the resend wait of this OTP no longer applies, so no countdown is left on Generate OTP once the
      // form is back to it (after the save). A Generate OTP inside sdp-otp-service's own wait gets its wait message.
      otp.blockedUntil = 0;
      otp.clearMessageOnUnblock = false;
      stopOtpTicker();
      renderOtpSection();
      return { ok: true, message: "" };
    case 202: // wrong OTP; with no attempts left the OTP is used up (lockout when retryAfterSeconds)
      if (payload.attemptsLeft === 0) endOtpAttempt(retryAfterSeconds);
      else clearOtpInputs();
      break;
    case 203: // expired, already used or never sent
    case 204: // locked out or maximum attempts reached
      endOtpAttempt(retryAfterSeconds);
      break;
  }
  setOtpMessage(message, "error");
  return { ok: false, message };
}



function decodeJwt(token) {
  const base64Url = token.split('.')[1];
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

  const jsonPayload = decodeURIComponent(
    atob(base64)
      .split('')
      .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
      .join('')
  );

  return JSON.parse(jsonPayload);
}



async function submitConsent() {
  return await sendConsent();
}

function resetConsent() {
  resetWidget();
}

function getConsentState() {
  return {
    payload: createConsentRequestList,
    jwt: consentJwt,
    sss: globalSSS
  };
}
async function resetWidget() {
  if (window.preferenceData?.currentPreference) {
    // Restore original state
    renderConsent(window.preferenceData, selectedLanguage);

    // Clear old signature
    globalSSS = null;
    isSSSValid = false;
    resetOtp();

    const submitBtn = document.getElementById("submitBtn");
    if (submitBtn) {
      submitBtn.disabled = true;
    }

    // Generate fresh BSS + SSS
    await onSelectionChange(selectedLanguage);
  }
}

window.consentWidget = {
    submit: async () => {
        return await clickEvent();
    },

    reset: async () => {
        return await resetWidget();
    }
};

initSigningKey().then(fetchConsentData);

