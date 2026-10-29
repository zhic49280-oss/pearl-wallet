// Pearl 珍珠币移动钱包 Service Worker - 实现 iOS 离线持久化与脱机秒开
// 采用 Network-First (网络优先) 机制，杜绝旧版本死锁，联网时秒级同步最新代码
const CACHE_NAME = 'pearl-wallet-cache-v11';
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './style.css?v=3.7',
  './bip39-wordlist.js?v=3.7',
  './qrcode.min.js?v=3.7',
  './app.js?v=3.7',
  './manifest.json',
  'https://cdn.tailwindcss.com'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[ServiceWorker] 预缓存离线核心资源 v5');
      return cache.addAll(ASSETS_TO_CACHE);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keyList) => {
      return Promise.all(
        keyList.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[ServiceWorker] 清理过时缓存', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // 只处理 GET 请求
  if (event.request.method !== 'GET') return;

  // 网络优先策略 (Network-First): 联网状态下确保获取最新逻辑，离线时优雅降级
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200) {
          const resClone = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, resClone);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        // 网络异常时，尝试从缓存提供
        return caches.match(event.request).then((cachedResponse) => {
          return cachedResponse || caches.match('./index.html');
        });
      })
  );
});
