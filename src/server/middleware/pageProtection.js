// pageProtection.js
export function createPageProtection(sessionManager) {
    return (req, res, next) => {
      const path = req.path.toLowerCase();
      
      // Allow access to static assets and admin panel
      if (!path.endsWith('.html') || path.includes('/admin')) {
        return next();
      }
  
      // Prevent direct access to pages
      if (path.includes('/pages/')) {
        return res.redirect('/');
      }
  
      // Check for valid session
      const params = new URLSearchParams(req.url.split('?')[1] || '');
      const clientId = params.get('client_id');
      const oauthChallenge = params.get('oauth_challenge');
  
      if (!clientId || !oauthChallenge || 
          !sessionManager.validateSession(clientId, oauthChallenge)) {
        return res.redirect('/');
      }
  
      next();
    };
  }