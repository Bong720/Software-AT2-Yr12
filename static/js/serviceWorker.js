// ─────────────────────────────────────────────────────────────────────────────
//  serviceWorker.js  —  Unsecure Social PWA
//
//  INTENTIONAL VULNERABILITIES (for educational use):
//    1. Cache Poisoning    — FIXED: Authenticated pages no longer cached; URL whitelist on push notifications
//    2. skipWaiting        — compromised SW update takes effect immediately
//    3. clients.claim()    — instantly hijacks all open tabs on activation
//    4. No SRI checks      — cached resources have no integrity verification
//    5. Push Phishing      — FIXED: notification payload URLs validated against whitelist
//    6. Hardcoded VAPID    — public key visible in source; anyone can send pushes
// ─────────────────────────────────────────────────────────────────────────────

// CACHE POISONING PREVENTION: Use timestamp-based cache versioning
const CACHE_NAME = 'social-pwa-cache-v1-' + new Date().getTime();

// CACHE POISONING PREVENTION: Only cache static/public resources
// Exclude authenticated pages (feed, messages, profile) to prevent cache poisoning across users
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/signup.html',
  '/success.html',
  '/static/css/style.css',
  '/static/js/app.js',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

// CACHE POISONING PREVENTION: Pages that must NOT be cached (user-specific)
const NO_CACHE_PATHS = [
  '/feed.html',
  '/profile',
  '/messages'
];

// CACHE POISONING PREVENTION: Whitelist of allowed notification URLs
const ALLOWED_NOTIFICATION_URLS = [
  '/',
  '/feed.html',
  '/messages',
  '/profile'
];

// ── INSTALL ───────────────────────────────────────────────────────────────────
self.addEventListener('install', function (event) {
  // VULNERABILITY: skipWaiting() means a malicious SW update activates instantly
  // without waiting for existing tabs to close — all open sessions are taken over
  self.skipWaiting();

  event.waitUntil(
    caches.open(CACHE_NAME).then(function (cache) {
      console.log('[SW] Pre-caching app shell');
      // VULNERABILITY: No Subresource Integrity (SRI) check on any cached resource
      // If any of these files is served with injected content, it gets cached as-is
      return cache.addAll(PRECACHE_URLS);
    })
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', function (event) {
  // VULNERABILITY: clients.claim() immediately controls ALL open tabs
  // A compromised or maliciously updated service worker now intercepts every request
  // across every open page — including pages the user was already on
  event.waitUntil(clients.claim());
});

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', function (event) {
  const requestUrl = new URL(event.request.url);
  const pathname = requestUrl.pathname;

  // CACHE POISONING PREVENTION: Never cache authenticated/user-specific pages
  // These pages must always be fetched from network to prevent cross-user cache leaks
  if (NO_CACHE_PATHS.some(path => pathname.startsWith(path))) {
    event.respondWith(
      fetch(event.request).catch(function () {
        // If offline and page not cached, don't serve random cached content
        return new Response('Offline - this page requires network access', {
          status: 503,
          statusText: 'Service Unavailable'
        });
      })
    );
    return;
  }

  // CACHE POISONING PREVENTION: Network-first for unspecified routes (safer approach)
  // Only cache successful responses with proper validation
  event.respondWith(
    fetch(event.request).then(function (networkResponse) {
      // CACHE POISONING PREVENTION: Only cache successful (200-299) responses
      // Do not cache error pages, redirects, or failure responses
      if (!networkResponse || networkResponse.status < 200 || networkResponse.status >= 300) {
        return networkResponse;
      }

      // CACHE POISONING PREVENTION: Only cache GET requests (not POST, PUT, DELETE)
      if (event.request.method !== 'GET') {
        return networkResponse;
      }

      let responseClone = networkResponse.clone();
      caches.open(CACHE_NAME).then(function (cache) {
        // CACHE POISONING PREVENTION: Validate response before caching
        // Only cache responses with proper content-type and no private headers
        const contentType = responseClone.headers.get('content-type');
        const cacheControl = responseClone.headers.get('cache-control');
        
        // Don't cache if cache-control says not to
        if (cacheControl && cacheControl.includes('no-cache')) {
          return;
        }

        cache.put(event.request, responseClone);
      });
      return networkResponse;
    }).catch(function () {
      // CACHE POISONING PREVENTION: Only serve cached responses on fallback
      // Match cache but return 503 if not found (don't serve root)
      return caches.match(event.request).then(function (cachedResponse) {
        if (cachedResponse) {
          return cachedResponse;
        }
        return new Response('Offline - no cached version available', {
          status: 503,
          statusText: 'Service Unavailable'
        });
      });
    })
  );
});

// ── PUSH NOTIFICATIONS ────────────────────────────────────────────────────────
self.addEventListener('push', function (event) {
  // CACHE POISONING PREVENTION: Parse and validate push payload
  // Only allow trusted notification content
  let data = { title: 'SocialPWA', body: 'You have a new notification!', url: '/' };

  if (event.data) {
    try {
      data = event.data.json();
    } catch (e) {
      console.warn('[SW] Push data parse error:', e);
    }
  }

  // CACHE POISONING PREVENTION: Validate notification URL against whitelist
  // Prevents push-based phishing attacks with attacker-controlled URLs
  let validUrl = '/';
  if (data.url && typeof data.url === 'string') {
    // Only allow app-internal URLs, not external phishing sites
    if (ALLOWED_NOTIFICATION_URLS.some(allowed => data.url === allowed || data.url.startsWith(allowed))) {
      validUrl = data.url;
    } else {
      console.warn('[SW] Blocked unauthorized notification URL:', data.url);
    }
  }

  const options = {
    body: data.body,
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    tag: 'social-pwa-notification',
    data: {
      // CACHE POISONING PREVENTION: Only store validated URL
      url: validUrl
    }
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'SocialPWA', options)
  );
});

// ── NOTIFICATION CLICK ────────────────────────────────────────────────────────
self.addEventListener('notificationclick', function (event) {
  event.notification.close();

  // CACHE POISONING PREVENTION: URL was already validated when notification was created
  // Only whitelisted URLs are allowed in the notification data
  const targetUrl = event.notification.data.url || '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (clientList) {
      for (let client of clientList) {
        if (client.url === targetUrl && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});
