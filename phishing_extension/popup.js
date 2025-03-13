document.addEventListener('DOMContentLoaded', function() {
    const statusContainer = document.getElementById('statusContainer');
    const detailsContainer = document.getElementById('details');
    const checkNowButton = document.getElementById('checkNow');
    const urlsCheckedElem = document.getElementById('urlsChecked');
    const phishingDetectedElem = document.getElementById('phishingDetected');
    const lastDetectionElem = document.getElementById('lastDetection');
    
    // Get statistics
    chrome.runtime.sendMessage({action: "getStats"}, function(stats) {
      urlsCheckedElem.textContent = stats.urlsChecked || 0;
      phishingDetectedElem.textContent = stats.phishingDetected || 0;
      lastDetectionElem.textContent = stats.lastDetection || 'None';
    });
    
    // Check current tab URL
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      const currentUrl = tabs[0].url;
      
      // Skip internal browser pages
      if (currentUrl.startsWith('chrome:') || 
          currentUrl.startsWith('chrome-extension:') || 
          currentUrl.startsWith('about:')) {
        
        statusContainer.className = 'status safe';
        statusContainer.textContent = 'Browser internal page (safe)';
        return;
      }
      
      checkUrl(currentUrl);
    });
    
    // Handle check now button
    checkNowButton.addEventListener('click', function() {
      chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        statusContainer.className = 'status checking';
        statusContainer.textContent = 'Checking...';
        detailsContainer.textContent = '';
        
        checkUrl(tabs[0].url);
      });
    });
    
    function checkUrl(url) {
      chrome.runtime.sendMessage(
        {action: "checkUrl", url: url},
        function(result) {
          if (result.isSuspicious) {
            statusContainer.className = 'status unsafe';
            statusContainer.textContent = '⚠️ Warning: Potential Phishing Detected';
            
            detailsContainer.innerHTML = `
              <p><strong>Risk Score:</strong> ${Math.round(result.score * 100)}%</p>
              <p><strong>Issues:</strong> ${result.reason}</p>
              <p>Be careful! This site shows characteristics commonly associated with phishing attempts.</p>
            `;
          } else {
            statusContainer.className = 'status safe';
            statusContainer.textContent = '✓ No phishing detected';
            
            if (result.score > 0.3) {
              detailsContainer.innerHTML = `
                <p>No immediate threats detected, but exercise caution.</p>
                <p><strong>Risk Score:</strong> ${Math.round(result.score * 100)}%</p>
              `;
            } else {
              detailsContainer.innerHTML = `
                <p>This website appears to be safe.</p>
              `;
            }
          }
        }
      );
    }
  });