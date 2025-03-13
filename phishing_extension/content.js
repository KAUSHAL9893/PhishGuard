document.addEventListener('DOMContentLoaded', function() {
    // Detect if the page has login forms
    const passwordFields = document.querySelectorAll('input[type="password"]');
    
    if (passwordFields.length > 0) {
      // Notify background script that this page has login forms
      chrome.runtime.sendMessage({
        action: "loginPageDetected", 
        url: window.location.href
      });
      
      // Add additional protections for password fields
      passwordFields.forEach(field => {
        // Add event listener to check for pasted passwords
        field.addEventListener('paste', function(e) {
          chrome.runtime.sendMessage({
            action: "passwordPasteDetected",
            url: window.location.href
          });
        });
        
        // Enhanced form protection
        const form = field.closest('form');
        if (form) {
          form.addEventListener('submit', function(e) {
            const formAction = form.action;
            if (formAction) {
              // Double-check the form submission URL
              chrome.runtime.sendMessage(
                {action: "checkUrl", url: formAction},
                function(result) {
                  if (result.isSuspicious && result.score > 0.8) {
                    // High-risk form submission - block and warn
                    e.preventDefault();
                    
                    if (confirm("WARNING: PhishGuard detected this form may be sending your data to a suspected phishing site. Are you sure you want to continue?")) {
                      // User confirmed, continue submission
                      return true;
                    } else {
                      return false;
                    }
                  }
                }
              );
            }
          });
        }
      });
    }
    
    // Look for common phishing content in the page
    const pageText = document.body.innerText.toLowerCase();
    const phishingPhrases = [
      'verify your account immediately',
      'your account has been suspended',
      'unusual login attempt',
      'confirm your information',
      'update your payment information',
      'security alert'
    ];
    
    let phishingPhraseFound = false;
    for (const phrase of phishingPhrases) {
      if (pageText.includes(phrase)) {
        phishingPhraseFound = true;
        break;
      }
    }
    
    if (phishingPhraseFound) {
      // Notify background of suspicious content
      chrome.runtime.sendMessage({
        action: "suspiciousContentDetected",
        url: window.location.href,
        content: "Suspicious urgency phrases detected"
      });
    }
  });
  
  // Observe DOM changes to detect dynamically injected forms
  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
      if (mutation.addedNodes && mutation.addedNodes.length > 0) {
        for (let i = 0; i < mutation.addedNodes.length; i++) {
          const node = mutation.addedNodes[i];
          if (node.nodeType === 1) { // ELEMENT_NODE
            // Check newly added elements for password fields
            const passwordFields = node.querySelectorAll('input[type="password"]');
            if (passwordFields.length > 0) {
              chrome.runtime.sendMessage({
                action: "dynamicLoginFormDetected",
                url: window.location.href
              });
            }
          }
        }
      }
    });
  });
  
  // Start observing the document
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
  
  // Add event listener for any URL changes (e.g., in SPA applications)
  let lastUrl = location.href;
  new MutationObserver(() => {
    const url = location.href;
    if (url !== lastUrl) {
      lastUrl = url;
      chrome.runtime.sendMessage({
        action: "spaNavigation",
        url: url
      });
    }
  }).observe(document, {subtree: true, childList: true});