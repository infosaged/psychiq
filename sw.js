const CACHE = 'psychic-1778728330306';
const PRECACHE = [
  './psychic-test.html',
  './manifest.json',
  './icon.svg',
  'https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Raleway:wght@300;400;500;600&display=swap',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(PRECACHE).catch(() => {}))
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Service workers cannot fetch file:// URLs — skip and let the browser handle it
  if (url.protocol === 'file:') return;

  const isSameOrigin = url.origin === self.location.origin;
  const isFont = url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com';

  if (!isSameOrigin && !isFont) return;

  e.respondWith(
    caches.match(e.request).then(cached => {
      // Cache hit — return immediately
      if (cached) return cached;

      // Cache miss — try the network, cache on success
      return fetch(e.request).then(resp => {
        if (resp && resp.status === 200) {
          caches.open(CACHE).then(c => c.put(e.request, resp.clone()));
        }
        return resp;
      });
      // No .catch() — let network failures surface naturally so the browser
      // shows its own error page instead of getting an undefined response.
    })
  );
});
