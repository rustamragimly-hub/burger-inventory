// Service worker Revisi. Даёт установку как PWA/TWA и офлайн-оболочку.
const CACHE_NAME = 'revisi-v2';
const OFFLINE_URL = '/static/offline.html';

// Минимальная оболочка, которую держим офлайн (страница-заглушка + иконки).
const PRECACHE = [
  OFFLINE_URL,
  '/static/icon-192.png?v=4',
  '/static/icon-512.png?v=4',
  '/static/manifest.json?v=4',
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;

  // Навигация (переходы по страницам): сеть-первым, при офлайне — заглушка.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(() => caches.match(OFFLINE_URL))
    );
    return;
  }

  // Прочие GET (иконки, статика): сеть-первым, при неудаче — из кэша.
  event.respondWith(
    fetch(req).then(resp => {
      // Кэшируем успешную статику для последующего офлайна.
      if (resp && resp.status === 200 && req.url.indexOf('/static/') !== -1) {
        const copy = resp.clone();
        caches.open(CACHE_NAME).then(cache => cache.put(req, copy)).catch(() => {});
      }
      return resp;
    }).catch(() => caches.match(req))
  );
});

// ============== PUSH-УВЕДОМЛЕНИЯ ==============
self.addEventListener('push', event => {
  const data = event.data ? event.data.json() : {};
  const title = data.title || 'Ревизия';
  const body = data.body || 'Новое уведомление';
  event.waitUntil(
    self.registration.showNotification(title, {
      body: body,
      icon: '/static/icon-512.png',
      badge: '/static/icon-192.png',
      vibrate: [200, 100, 200],
      tag: 'revision-request',
      renotify: true,
      data: { url: '/admin' }
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data ? event.notification.data.url : '/admin';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if (client.url.endsWith(url) && 'focus' in client) {
          return client.focus();
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});
