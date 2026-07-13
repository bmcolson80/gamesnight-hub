/**
 * GamesNight Hub — Service Worker
 * Handles push notifications (invites) when the app is backgrounded or closed.
 */

const CACHE_NAME = 'gamesnight-hub-v1';

// ── Push event ─────────────────────────────────────────────
self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { title: 'GamesNight', body: event.data?.text() || 'You have a new notification' };
  }

  const title   = data.title || 'GamesNight';
  const options = {
    body:    data.body    || 'You have a new invite!',
    icon:    data.icon    || '/icon-192.png',
    badge:   data.badge   || '/icon-192.png',
    tag:     data.tag     || 'gamesnight',
    data:    data.data    || {},
    vibrate: [200, 100, 200],
    requireInteraction: false,
    actions: [
      { action: 'open', title: 'Open' },
      { action: 'dismiss', title: 'Dismiss' },
    ],
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// ── Notification click ─────────────────────────────────────
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  const url = event.notification.data?.url || '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      // A game-launch URL is a different origin, so always open a fresh tab for
      // those; only reuse an existing tab when it's staying on the hub itself.
      const sameOrigin = url.startsWith('/') || url.startsWith(self.location.origin);
      if (sameOrigin) {
        for (const client of windowClients) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            return client.focus().then(c => c.navigate ? c.navigate(url) : c);
          }
        }
      }
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});

// ── Install & activate ─────────────────────────────────────
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => {
  event.waitUntil(clients.claim());
});
