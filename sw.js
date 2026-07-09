const CACHE = 'psychic-1783616877518';
const PRECACHE = [
  './psychic-test.html',
  './manifest.json',
  './icon.svg',
  'https://fonts.googleapis.com/css2?family=Cinzel:wght@400;600;700&family=Raleway:wght@300;400;500;600&display=swap',
  // Gems (~576KB) — pre-cached so gems topic works offline from first install
  './Images/Gems/Amethyst.jpg',
  './Images/Gems/Diamond.jpg',
  './Images/Gems/Garnet.jpg',
  './Images/Gems/Obsidian.jpg',
  './Images/Gems/Opal.jpg',
  './Images/Gems/RoseQuartz.jpg',
  './Images/Gems/Ruby.jpg',
  './Images/Gems/Sapphire.jpg',
  './Images/Gems/Topaz.jpg',
  './Images/Gems/Turquoise.jpg',
  // Planets (~880KB)
  './Images/Planets/Earth.jpg',
  './Images/Planets/Jupiter.jpg',
  './Images/Planets/Mars.jpg',
  './Images/Planets/Mercury.jpg',
  './Images/Planets/Neptune.jpg',
  './Images/Planets/Pluto.jpg',
  './Images/Planets/Saturn.jpg',
  './Images/Planets/Sun.jpg',
  './Images/Planets/Uranus.jpg',
  './Images/Planets/Venus.jpg',
  // Animals (~2.8MB)
  './Images/Animals/Dargo.png',
  './Images/Animals/panther.jpg',
  // Mythical Creatures
  './Images/Mythical Creatures/centaur.png',
  './Images/Mythical Creatures/dragon.png',
  './Images/Mythical Creatures/dryad.png',
  './Images/Mythical Creatures/fairy.png',
  './Images/Mythical Creatures/gnome.png',
  './Images/Mythical Creatures/griffin.png',
  './Images/Mythical Creatures/jackalope.png',
  './Images/Mythical Creatures/mermaid.png',
  './Images/Mythical Creatures/pegasus.png',
  './Images/Mythical Creatures/phoenix.png',
  './Images/Mythical Creatures/selkie.png',
  './Images/Mythical Creatures/unicorn.png',
  // Places
  './Images/Places/beach.png',
  './Images/Places/library.png',
  './Images/Places/park.png',
  './Images/Places/policestation.png',
  './Images/Places/restaurant.png',
  './Images/Places/school.png',
  './Images/Places/stores.png',
  './Images/Places/zoo.png',
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

  // These must always hit the network — never serve from cache
  if (isSameOrigin && (url.pathname.startsWith('/api/') || url.pathname === '/privacy' || url.pathname === '/delete-account')) return;

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
