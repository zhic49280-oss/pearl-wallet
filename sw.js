// Pearl 珍珠币移动钱包 Service Worker - 实现 iOS 离线持久化与脱机秒开
// 采用 Network-First (网络优先) 机制，杜绝旧版本死锁，联网时秒级同步最新代码
const CACHE_NAME = 'pearl-wallet-cache-v18';
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './style.css?v=5.0',
  './bip39-wordlist.js?v=5.0',
  './qrcode.min.js?v=5.0',
  './app.js?v=5.0',
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

// ======================== Feature 15: 外部 API 保护与服务缓存隔离 ========================
self.addEventListener('fetch', (event) => {
  // 只处理 GET 请求
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // 1. 外部区块链与矿池 API 保护：严禁缓存至离线外壳，严禁在网络故障时回退至 HTML
  const isExternalApi =
    url.hostname.includes('prlscan.com') ||
    url.hostname.includes('herominers.com') ||
    url.hostname.includes('kryptex.com') ||
    url.hostname.includes('qrserver.com') ||
    url.pathname.startsWith('/v1/') ||
    url.pathname.startsWith('/api/');

  if (isExternalApi) {
    event.respondWith(
      fetch(event.request).catch((err) => {
        // 网络失败时返回标准 503 JSON 错误，杜绝 HTML 字符串污染 JSON 解析
        return new Response(
          JSON.stringify({ error: 'Network request failed', message: err.message || 'Service Unavailable' }),
          {
            status: 503,
            statusText: 'Service Unavailable',
            headers: { 'Content-Type': 'application/json' }
          }
        );
      })
    );
    return;
  }

  // 2. 本地静态资源 (HTML/CSS/JS/Icons) 采用 Network-First 策略
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200 && event.request.url.startsWith('http')) {
          const resClone = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, resClone);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) return cachedResponse;
          // 仅当用户导航页面时才回退至 index.html
          if (event.request.mode === 'navigate') {
            return caches.match('./index.html');
          }
          return new Response('Not found', { status: 404, statusText: 'Not Found' });
        });
      })
  );
});
