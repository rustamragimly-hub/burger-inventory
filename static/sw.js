const CACHE_NAME = 'burger-inventory-v1';

self.addEventListener('install', event => {
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
    if (event.request.method !== 'GET') return;
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});

// ============== PUSH NOTIFICATIONS ==============
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
