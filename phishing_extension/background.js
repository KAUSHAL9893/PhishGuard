const PHISHING_API_ENDPOINT = "https://api.phishguard.example/check";
const SAFE_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const SUSPECTED_CACHE_DURATION = 12 * 60 * 60 * 1000; // 12 hours

// Initialize a cache to store URL check results
let urlCache = {};

// Load cache from storage
chrome.storage.local.get(['phishGuardCache'], result => {
  if (result.phishGuardCache) {
    urlCache = result.phishGuardCache;
    // Clean expired entries
    cleanCache();
  }
});

// Regularly clean the cache of expired entries
setInterval(cleanCache, 60 * 60 * 1000); // Every hour

function cleanCache() {
  const now = Date.now();
  for (const url in urlCache) {
    if (now > urlCache[url].expiry) {
      delete urlCache[url];
    }
  }
  // Save cleaned cache to storage
  chrome.storage.local.set({ phishGuardCache: urlCache });
}

// Listen for before navigation events to check URLs
chrome.webNavigation.onBeforeNavigate.addListener(async details => {
  // Only check main frame navigations
  if (details.frameId !== 0) return;
  
  const url = new URL(details.url);
  
  // Skip internal browser pages
  if (url.protocol === 'chrome:' || url.protocol === 'chrome-extension:' || url.protocol === 'about:') {
    return;
  }
  
  const checkResult = await checkUrlForPhishing(details.url);
  
  if (checkResult.isSuspicious) {
    // Show warning to user
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(details.url) +
          "&reason=" + encodeURIComponent(checkResult.reason)
    });
    
    // Send notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'images/warning-icon.jpg',
      title: 'Phishing Warning',
      message: `PhishGuard has detected potential phishing at: ${url.hostname}`
    });
  }
});

// Main function to check URLs for phishing indicators
async function checkUrlForPhishing(url) {
  // Check cache first
  if (urlCache[url] && urlCache[url].expiry > Date.now()) {
    return urlCache[url].result;
  }
  
  const parsedUrl = new URL(url);
  const result = { isSuspicious: false, reason: '', score: 0 };
  
  // Simple heuristics that can be done locally
  // 1. Check for IP address URLs
  const ipAddressRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
  if (ipAddressRegex.test(parsedUrl.hostname)) {
    result.isSuspicious = true;
    result.reason = 'Uses IP address instead of domain name';
    result.score += 0.6;
  }
  
  // 2. Check for excessive subdomains
  const subdomainCount = parsedUrl.hostname.split('.').length;
  if (subdomainCount > 4) {
    result.isSuspicious = true;
    result.reason += (result.reason ? ' | ' : '') + 'Excessive subdomains';
    result.score += 0.3;
  }
  
  // 3. Check for URL length (phishing URLs often very long)
  if (url.length > 100) {
    result.isSuspicious = true;
    result.reason += (result.reason ? ' | ' : '') + 'Suspiciously long URL';
    result.score += 0.2;
  }
  
  // 4. Look for common sensitive keywords
  const suspiciousKeywords = ['login', 'signin', 'account', 'bank', 'password', 'secure', 'update'];
  for (const keyword of suspiciousKeywords) {
    if (url.toLowerCase().includes(keyword)) {
      result.score += 0.1;
    }
  }
  
  // 5. Check domain age and reputation with API (simulated)
  try {
    const apiResponse = await fetchPhishingAPIResults(url);
    
    if (apiResponse.knownPhishing) {
      result.isSuspicious = true;
      result.reason += (result.reason ? ' | ' : '') + 'Known phishing site';
      result.score += 0.9;
    }
    
    if (apiResponse.domainAge < 30) { // Domain less than 30 days old
      result.isSuspicious = true;
      result.reason += (result.reason ? ' | ' : '') + 'Very new domain';
      result.score += 0.5;
    }
    
    if (apiResponse.suspiciousScore > 0) {
      result.score += apiResponse.suspiciousScore;
    }
  } catch (error) {
    console.error("Error checking URL with API:", error);
  }
  
  // Set final result based on overall score
  if (result.score >= 0.7) {
    result.isSuspicious = true;
    if (!result.reason) {
      result.reason = 'Multiple suspicious patterns detected';
    }
  }
  
  // Cache the result
  const cacheDuration = result.isSuspicious ? SUSPECTED_CACHE_DURATION : SAFE_CACHE_DURATION;
  urlCache[url] = {
    result: result,
    expiry: Date.now() + cacheDuration
  };
  
  // Save to storage
  chrome.storage.local.set({ phishGuardCache: urlCache });
  
  return result;
}

// Function to fetch results from phishing detection API
// This is a simulation - in a real extension, you would call your actual API
async function fetchPhishingAPIResults(url) {
  // In a real extension, this would be an actual API call
  // For now, we'll simulate a response with a small random element
  
  // For demo purposes, consider these domains as known phishing
  const knownPhishingDomains = [
    'paypai.com', 'amaz0n.com', 'faceb00k.com', 'g00gle.com', 'appleid-verify.com'
  ];
  
  const parsedUrl = new URL(url);
  const domainName = parsedUrl.hostname;
  
  // Simulate API response
  return new Promise(resolve => {
    setTimeout(() => {
      // In a real extension, this would be the response from your phishing API
      resolve({
        knownPhishing: knownPhishingDomains.includes(domainName),
        domainAge: Math.floor(Math.random() * 500), // Random age in days
        suspiciousScore: Math.random() * 0.3, // Random score component
        isSslValid: true
      });
    }, 100); // Simulate network delay
  });
}

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "checkUrl") {
    checkUrlForPhishing(request.url).then(result => {
      sendResponse(result);
    });
    return true; // Required for async response
  } else if (request.action === "getStats") {
    // Return stats about URLs checked, warnings shown, etc.
    chrome.storage.local.get(['phishGuardStats'], result => {
      sendResponse(result.phishGuardStats || {
        urlsChecked: 0,
        phishingDetected: 0,
        lastDetection: null
      });
    });
    return true;
  }
});
