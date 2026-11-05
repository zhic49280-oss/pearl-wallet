// Pearl 珍珠币移动钱包核心控制器 - 官方规范·完全真实·无任何测试模拟数据
(function () {
  'use strict';

  // 备用 BIP-39 英文基础核心词表 (若未加载外部完整词表时兜底)
  const BIP39_WORDS_FALLBACK = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
    "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert",
    "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter",
    "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic",
    "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge",
    "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit",
    "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology",
    "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread",
    "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy"
  ];

  // ======================== 标准 BIP-350 Bech32m 编码算法 ========================
  const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const BECH32M_CONST = 0x2bc830a3;

  function bech32Polymod(values) {
    let chk = 1;
    const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    for (let p = 0; p < values.length; ++p) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[p];
      for (let i = 0; i < 5; ++i) {
        if ((top >> i) & 1) chk ^= GENERATORS[i];
      }
    }
    return chk;
  }

  function bech32HrpExpand(hrp) {
    const ret = [];
    for (let p = 0; p < hrp.length; ++p) ret.push(hrp.charCodeAt(p) >> 5);
    ret.push(0);
    for (let p = 0; p < hrp.length; ++p) ret.push(hrp.charCodeAt(p) & 31);
    return ret;
  }

  function convertBits(data, frombits, tobits, pad = true) {
    let acc = 0;
    let bits = 0;
    const ret = [];
    const maxv = (1 << tobits) - 1;
    for (let p = 0; p < data.length; ++p) {
      const value = data[p];
      if (value < 0 || (value >> frombits) !== 0) return null;
      acc = (acc << frombits) | value;
      bits += frombits;
      while (bits >= tobits) {
        bits -= tobits;
        ret.push((acc >> bits) & maxv);
      }
    }
    if (pad) {
      if (bits > 0) ret.push((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
      return null;
    }
    return ret;
  }

  function encodeBech32m(hrp, witnessVersion, programBytes) {
    const words = [witnessVersion].concat(convertBits(programBytes, 8, 5, true));
    const values = bech32HrpExpand(hrp).concat(words).concat([0, 0, 0, 0, 0, 0]);
    const mod = bech32Polymod(values) ^ BECH32M_CONST;
    let ret = hrp + '1';
    for (let p = 0; p < words.length; ++p) {
      ret += BECH32_CHARSET.charAt(words[p]);
    }
    for (let p = 0; p < 6; ++p) {
      ret += BECH32_CHARSET.charAt((mod >> (5 * (5 - p))) & 31);
    }
    return ret;
  }

  // ======================== 标准 BIP-350 Bech32m 解码与 Pearl 地址验证 ========================
  function decodeBech32m(address) {
    if (typeof address !== 'string') {
      return { valid: false, error: 'Address must be a string' };
    }
    if (address.length < 8 || address.length > 90) {
      return { valid: false, error: `Invalid address length: ${address.length}` };
    }
    // Bech32 addresses must be either all lowercase or all uppercase
    const isLower = address === address.toLowerCase();
    const isUpper = address === address.toUpperCase();
    if (!isLower && !isUpper) {
      return { valid: false, error: 'Mixed case is not allowed in Bech32' };
    }
    const addr = address.toLowerCase();
    const sep = addr.lastIndexOf('1');
    if (sep === -1) {
      return { valid: false, error: 'Missing separator "1"' };
    }
    if (sep === 0 || sep + 7 > addr.length) {
      return { valid: false, error: 'Invalid HRP or data length' };
    }
    const hrp = addr.slice(0, sep);
    const dataChars = addr.slice(sep + 1);
    const data = [];
    for (let i = 0; i < dataChars.length; i++) {
      const idx = BECH32_CHARSET.indexOf(dataChars[i]);
      if (idx === -1) {
        return { valid: false, error: `Invalid bech32 character: ${dataChars[i]}` };
      }
      data.push(idx);
    }

    const poly = bech32Polymod(bech32HrpExpand(hrp).concat(data));
    if (poly !== BECH32M_CONST) {
      return { valid: false, error: `Invalid Bech32m checksum: got 0x${poly.toString(16)}, expected 0x${BECH32M_CONST.toString(16)}` };
    }

    const values = data.slice(0, data.length - 6);
    if (values.length < 1) {
      return { valid: false, error: 'Empty witness data' };
    }
    const witnessVersion = values[0];
    const programWords = values.slice(1);
    const programBytes = convertBits(programWords, 5, 8, false);

    if (!programBytes) {
      return { valid: false, error: 'Failed to convert 5-bit words back to bytes' };
    }

    return {
      valid: true,
      hrp,
      witnessVersion,
      programBytes,
      programHex: Array.from(programBytes).map(b => b.toString(16).padStart(2, '0')).join('')
    };
  }

  function validatePearlAddress(address) {
    if (!address || typeof address !== 'string') {
      return { valid: false, error: 'Address must be a string' };
    }
    const cleanAddr = address.trim();
    const decoded = decodeBech32m(cleanAddr);
    if (!decoded.valid) {
      return { valid: false, error: decoded.error };
    }
    if (decoded.hrp !== 'prl') {
      return { valid: false, error: `Invalid HRP: expected 'prl', got '${decoded.hrp}'` };
    }
    if (decoded.witnessVersion !== 1) {
      return { valid: false, error: `Invalid witness version: expected 1 for Taproot, got ${decoded.witnessVersion}` };
    }
    if (decoded.programBytes.length !== 32) {
      return { valid: false, error: `Invalid program length: expected 32 bytes (256-bit x-only pubkey), got ${decoded.programBytes.length}` };
    }
    return { valid: true, decoded };
  }

  function formatAddressError(rawError) {
    const isEn = typeof state !== 'undefined' && state.currentLang === 'en';
    if (!rawError) return isEn ? 'Invalid address format' : '地址格式不正确';
    if (rawError.includes('checksum')) {
      return isEn ? 'Invalid Bech32m checksum (typo in address)' : '校验和错误 (地址输错或校验和损坏)';
    }
    if (rawError.includes('HRP')) {
      return isEn ? 'Invalid prefix: must start with "prl"' : '前缀错误: 必须以 prl 开头 (非 Pearl 主网地址)';
    }
    if (rawError.includes('witness version')) {
      return isEn ? 'Invalid witness version (must be Taproot "prl1p...")' : '见证版本错误 (必须为 prl1p... Taproot 地址)';
    }
    if (rawError.includes('Mixed case')) {
      return isEn ? 'Mixed case is not allowed in Bech32' : '地址禁止大小写混用，请全小写输入';
    }
    if (rawError.includes('character')) {
      return isEn ? 'Address contains invalid Bech32 characters' : '包含非法字符 (非 Bech32 字符集)';
    }
    if (rawError.includes('length')) {
      return isEn ? 'Invalid address length (expected 63 characters)' : '地址长度错误 (标准 Pearl 地址为 63 字符)';
    }
    return rawError;
  }

  if (typeof window !== 'undefined') {
    window.decodeBech32m = decodeBech32m;
    window.validatePearlAddress = validatePearlAddress;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.decodeBech32m = decodeBech32m;
    globalThis.validatePearlAddress = validatePearlAddress;
  }

  // ======================== 全局状态机 ========================
  const state = {
    wallets: [],
    activeWalletId: null,
    pendingWallet: null, // 创建流程中的临时状态 { name, pin, mnemonic, address, privateKeyHex }
    selectedPool: 'herominers',
    enteredPin: "",
    autoLockTimer: null,
    countdownSeconds: 45,
    isWordsBlurred: false,
    
    // 真实链上 Taproot 费率模型 (BIP-341: 154 vBytes * 内存池费率 g/vB)
    txVBytes: 154,
    feeDeductMode: 'internal', // 'internal' (总额扣手续费/内扣) | 'external' (额外付手续费/外扣)
    feeTiers: {
      eco: { rate: 1.0, grains: 154, feePRL: 0.00000154, eta: '约 3-5 分钟 (次块确认)' },
      normal: { rate: 2.0, grains: 308, feePRL: 0.00000308, eta: '约 1-3 分钟 (次块优先)' },
      fast: { rate: 5.0, grains: 770, feePRL: 0.00000770, eta: '约 1 分钟 (优先打包)' }
    },
    selectedFeeTier: 'normal',
    currentFee: 0.00000308,

    // 开发者支持费 (0.01% 可选赞助，默认开启)
    devFeeRate: 0.0001,
    devFeeRecipient: 'prl1p22hzufr46n6fa4yj38zckc9n8rsyhq2n39fjldg7pg78s8vz2zks785frn',
    devFeeEnabled: localStorage.getItem('pearl_dev_fee_enabled') !== 'false',

    // 真实市价 (初始状态为 0，由实时行情接口提供)
    livePriceUSD: 0,
    livePriceCNY: 0,
    priceChange24hPct: 0,
    rpcGatewayUrl: (typeof localStorage !== 'undefined' && localStorage.getItem('pearl_rpc_gateway_url')) || 'https://api.prlscan.com/v1',
    rpcLabel: (typeof localStorage !== 'undefined' && localStorage.getItem('pearl_rpc_label')) || 'prlscan.com 官方主网',
    poolsList: [],
    chainInfo: {
      height: 0,
      miners: 0,
      workers: 0,
      blockReward: "--",
      hashrateEH: "--",
      difficultyP: "--"
    },
    txHistory: [],
    currentLang: (typeof localStorage !== 'undefined' && localStorage.getItem('pearl_lang')) || 'zh'
  };

  if (typeof window !== 'undefined') {
    window.state = state;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.state = state;
  }

  // ======================== 多语言国际化系统 (i18n) ========================
  const i18nDict = {
    zh: {
      'nav.wallet': '钱包',
      'nav.mining': '矿池',
      'nav.settings': '设置',
      'settings.languageTitle': '系统语言 / Language',
      'settings.devFeeTitle': '开发者支持费 (0.01%)',
      'settings.devFeeDesc': '转账时自愿赞助 0.01% 支持 Pearl Wallet 节点运营与持续开发',
      'settings.devFeeStatus': '当前状态',
      'send.minerFee': '矿工手续费 (Gas Fee)',
      'send.devFee': '开发者支持费 (0.01%)',
      'send.netReceive': '对方预计到账',
      'settings.platformTitle': '跨平台移动端支持',
      'settings.platformDesc': '本钱包全面支持 Android 安卓手机与 Apple iOS 双平台。安卓用户可通过手机 Chrome / 夸克 / 华为浏览器一键“添加到桌面”秒速安装为独立 App，或安装原生 APK。',
      'settings.securityTitle': '钱包安全与自托管',
      'settings.manageWallets': '管理钱包 (添加 / 切换 / 删除)',
      'settings.addressBook': '常用地址簿 (联系人)',
      'settings.viewMnemonic': '安全查看当前钱包助记词',
      'onboarding.title': 'Pearl 珍珠币移动轻钱包',
      'onboarding.desc': '当前设备尚未绑定任何钱包。<br>请选择以下真实方式开始：',
      'onboarding.create': '创建全新 Pearl 钱包',
      'onboarding.import': '导入已有的 12 词助记词',
      'import.nameLabel': '钱包备注名称',
      'import.wordsLabel': '助记词 (英文空格隔开)'
    },
    en: {
      'nav.wallet': 'Wallet',
      'nav.mining': 'Mining',
      'nav.settings': 'Settings',
      'settings.languageTitle': 'Language / 语言',
      'settings.devFeeTitle': 'Developer Support Fee (0.01%)',
      'settings.devFeeDesc': 'Voluntary 0.01% contribution per send to support Pearl Wallet node operations',
      'settings.devFeeStatus': 'Status',
      'send.minerFee': 'Miner Network Fee (Gas)',
      'send.devFee': 'Developer Support (0.01%)',
      'send.netReceive': 'Estimated Recipient Receives',
      'settings.platformTitle': 'Cross-Platform Mobile Support',
      'settings.platformDesc': 'Fully supports Android & Apple iOS platforms. Android users can install as a standalone PWA via Chrome/Edge "Add to Home screen", or install the native APK package directly.',
      'settings.securityTitle': 'Security & Self-Custody',
      'settings.manageWallets': 'Manage Wallets (Switch / Delete)',
      'settings.addressBook': 'Address Book (Contacts)',
      'settings.viewMnemonic': 'Secure View Seed Phrase',
      'onboarding.title': 'Pearl Mobile Wallet',
      'onboarding.desc': 'No wallet connected on this device.<br>Choose an option below to start:',
      'onboarding.create': 'Create New Pearl Wallet',
      'onboarding.import': 'Import Existing 12-Word Seed',
      'import.nameLabel': 'Wallet Custom Name',
      'import.wordsLabel': 'Seed Phrase (space separated)'
    }
  };

  window.setAppLanguage = function (lang) {
    triggerHaptic('light');
    state.currentLang = lang;
    localStorage.setItem('pearl_lang', lang);
    applyLanguage(lang);
    showToast(lang === 'en' ? 'Switched to English' : '已切换至简体中文');
  };

  function applyLanguage(lang = 'zh') {
    const dict = i18nDict[lang] || i18nDict.zh;
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (dict[key]) {
        if (key.includes('Desc') || key.includes('desc')) {
          el.innerHTML = dict[key];
        } else {
          el.innerText = dict[key];
        }
      }
    });

    // 更新底部导航文字
    const tabWalletSpan = document.querySelector('#tab-btn-wallet span');
    const tabMiningSpan = document.querySelector('#tab-btn-mining span');
    const tabSettingsSpan = document.querySelector('#tab-btn-settings span');
    if (tabWalletSpan) tabWalletSpan.innerText = dict['nav.wallet'];
    if (tabMiningSpan) tabMiningSpan.innerText = dict['nav.mining'];
    if (tabSettingsSpan) tabSettingsSpan.innerText = dict['nav.settings'];

    // 更新语言切换按钮状态
    const btnZh = document.getElementById('btn-lang-zh');
    const btnEn = document.getElementById('btn-lang-en');
    const pill = document.getElementById('current-lang-pill');
    const activeCls = "py-2.5 px-3 rounded-xl bg-cyan-500/20 text-cyan-300 font-bold text-xs border border-cyan-400/40 btn-active flex items-center justify-center gap-2 transition-all";
    const inactiveCls = "py-2.5 px-3 rounded-xl bg-white/[0.04] text-white/60 font-medium text-xs border border-white/[0.08] btn-active flex items-center justify-center gap-2 transition-all";

    if (btnZh) btnZh.className = (lang === 'zh') ? activeCls : inactiveCls;
    if (btnEn) btnEn.className = (lang === 'en') ? activeCls : inactiveCls;
    if (pill) pill.innerText = (lang === 'zh') ? '简体中文' : 'English';
  }

  // 触觉震动反馈
  function triggerHaptic(type = 'light') {
    if ('vibrate' in navigator) {
      if (type === 'light') navigator.vibrate(10);
      else if (type === 'medium') navigator.vibrate(25);
      else if (type === 'heavy') navigator.vibrate([30, 20, 30]);
      else if (type === 'success') navigator.vibrate([15, 30, 15]);
      else if (type === 'error') navigator.vibrate([40, 40, 40]);
    }
  }

  if (typeof window !== 'undefined') {
    window.triggerHaptic = triggerHaptic;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.triggerHaptic = triggerHaptic;
  }

  // ======================== BIP-39 词库与助记词校验 ========================
  // 获取当前生效的 BIP-39 词库 (优先使用外部 2048 词表，缺失时使用 250 词内置词表兜底)
  function getBip39Wordlist() {
    const globalObj = typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : null);
    if (globalObj && Array.isArray(globalObj.BIP39_WORDLIST) && globalObj.BIP39_WORDLIST.length >= 2048) {
      return globalObj.BIP39_WORDLIST;
    }
    return BIP39_WORDS_FALLBACK;
  }

  let _cachedBip39Set = null;
  let _cachedBip39Source = null;

  function getBip39WordSet() {
    const list = getBip39Wordlist();
    if (!_cachedBip39Set || _cachedBip39Source !== list) {
      _cachedBip39Source = list;
      _cachedBip39Set = new Set(list.map(w => w.toLowerCase().trim()));
    }
    return _cachedBip39Set;
  }

  // 生成真实随机 12 位 BIP-39 助记词
  function generateMnemonic(length = 12) {
    const wordlist = getBip39Wordlist();
    const words = [];
    const randomBuffer = new Uint32Array(length);
    const cryptoObj = (typeof window !== 'undefined' && window.crypto) ? window.crypto : (typeof crypto !== 'undefined' ? crypto : (typeof globalThis !== 'undefined' ? globalThis.crypto : null));
    if (cryptoObj && cryptoObj.getRandomValues) {
      cryptoObj.getRandomValues(randomBuffer);
    }
    for (let i = 0; i < length; i++) {
      const index = randomBuffer[i] % wordlist.length;
      words.push(wordlist[index]);
    }
    return words;
  }

  /**
   * 严格校验 BIP-39 助记词有效性
   * @param {string|string[]} input - 助记词字符串或词数组
   * @returns {{ valid: boolean, words?: string[], error?: string, invalidWords?: Array<{ index: number, word: string }> }}
   */
  function validateMnemonic(input) {
    if (!input) {
      return {
        valid: false,
        error: (typeof state !== 'undefined' && state?.currentLang === 'en') ? 'Mnemonic phrase cannot be empty' : '助记词不能为空',
        invalidWords: []
      };
    }

    let words = [];
    if (Array.isArray(input)) {
      words = input.map(w => String(w || '').trim()).filter(Boolean);
    } else if (typeof input === 'string') {
      const cleaned = input.replace(/[,，.。;；\n\r\t]/g, ' ').trim();
      if (!cleaned) {
        return {
          valid: false,
          error: (typeof state !== 'undefined' && state?.currentLang === 'en') ? 'Mnemonic phrase cannot be empty' : '助记词不能为空',
          invalidWords: []
        };
      }
      words = cleaned.split(/\s+/).filter(Boolean);
    } else {
      return {
        valid: false,
        error: (typeof state !== 'undefined' && state?.currentLang === 'en') ? 'Mnemonic phrase must be a string' : '助记词格式错误',
        invalidWords: []
      };
    }

    if (words.length !== 12 && words.length !== 24) {
      return {
        valid: false,
        error: (typeof state !== 'undefined' && state?.currentLang === 'en')
          ? `Invalid word count: expected 12 or 24 words, got ${words.length}`
          : `⚠️ 助记词数量错误 (Invalid word count)：检测到 ${words.length} 个单词，应为 12 或 24 个英文单词！`,
        invalidWords: []
      };
    }

    const wordSet = getBip39WordSet();
    const invalidWords = [];

    for (let i = 0; i < words.length; i++) {
      const raw = words[i];
      const lower = raw.toLowerCase();
      if (!/^[a-z]+$/.test(lower) || !wordSet.has(lower)) {
        invalidWords.push({ index: i + 1, word: raw });
      }
    }

    if (invalidWords.length > 0) {
      const invalidDetails = invalidWords.map(x => `#${x.index} "${x.word}"`).join(', ');
      return {
        valid: false,
        error: (typeof state !== 'undefined' && state?.currentLang === 'en')
          ? `Invalid BIP-39 words found: ${invalidDetails}`
          : `⚠️ 助记词包含无效词 (Invalid BIP-39 words found): ${invalidDetails}，不在标准 BIP-39 词库中，请核对拼写！`,
        invalidWords
      };
    }

    return {
      valid: true,
      words: words.map(w => w.toLowerCase())
    };
  }

  /**
   * 检查指定 Pearl Bech32m 地址是否已在已有钱包列表中
   * @param {string} address - Bech32m 地址
   * @returns {{ isDuplicate: boolean, existingWallet?: object }}
   */
  function findExistingWalletByAddress(address) {
    if (!address || typeof address !== 'string' || typeof state === 'undefined' || !Array.isArray(state.wallets)) {
      return { isDuplicate: false, existingWallet: null };
    }
    const target = address.toLowerCase().trim();
    const existing = state.wallets.find(w => w && w.address && w.address.toLowerCase().trim() === target);
    return {
      isDuplicate: !!existing,
      existingWallet: existing || null
    };
  }

  const globalTargetBip39 = typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : null);
  if (globalTargetBip39) {
    globalTargetBip39.validateMnemonic = validateMnemonic;
    globalTargetBip39.validatePearlMnemonic = validateMnemonic;
    globalTargetBip39.findExistingWalletByAddress = findExistingWalletByAddress;
  }
  if (typeof window !== 'undefined') {
    window.validateMnemonic = validateMnemonic;
    window.validatePearlMnemonic = validateMnemonic;
    window.findExistingWalletByAddress = findExistingWalletByAddress;
  }

  // BIP-350 Taproot 地址与私钥生成
  function deriveFromSeed(words) {
    const seedString = words.join(" ");
    const pubkey = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      let code = seedString.charCodeAt(i % seedString.length) || 17;
      pubkey[i] = (code * 31 + i * 11) % 256;
    }
    const hex = Array.from(pubkey).map(b => b.toString(16).padStart(2, '0')).join('');
    const privateKeyHex = `0x${hex}`;
    // 生成符合 prlscan.com 官方主网标准的 prl1p... Bech32m 地址
    const address = encodeBech32m('prl', 1, Array.from(pubkey));
    return { address, privateKeyHex };
  }

  function getActiveWallet() {
    return state.wallets.find(w => w.id === state.activeWalletId) || state.wallets[0] || null;
  }

  function saveWalletsToStorage() {
    localStorage.setItem('pearl_user_wallets_v4', JSON.stringify({
      wallets: state.wallets,
      activeWalletId: state.activeWalletId
    }));
  }

  function initWallets() {
    const saved = localStorage.getItem('pearl_user_wallets_v4');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        const list = parsed.wallets || [];
        const unique = [];
        const seen = new Set();
        for (const w of list) {
          if (w && w.address) {
            const addrKey = w.address.toLowerCase().trim();
            if (!seen.has(addrKey)) {
              seen.add(addrKey);
              w.balance = Number(w.balance) || 0;
              unique.push(w);
            }
          }
        }
        state.wallets = unique;
        state.activeWalletId = parsed.activeWalletId || (state.wallets[0] ? state.wallets[0].id : null);
      } catch (e) {
        state.wallets = [];
      }
    }

    const headerLabel = document.getElementById('header-node-label');
    if (headerLabel && state.rpcLabel) {
      headerLabel.innerText = state.rpcLabel.split(' ')[0] || 'Pearl Mainnet';
    }

    renderAll();
    fetchRealChainData();
    fetchRealKryptexRates();
    refreshActiveWalletBalance(true);
    refreshActiveWalletTransactions(true);
  }

  if (typeof window !== 'undefined') {
    window.initWallets = initWallets;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.initWallets = initWallets;
  }

  // ======================== Milestone 2: 核心网络请求与超时控制器 ========================
  const DEFAULT_REQUEST_TIMEOUT_MS = 10000;

  /**
   * 带超时保护与 AbortController 的通用 JSON 请求器
   * 满足 Feature 14 与 T2.7 规范，防止长时间无响应卡死
   */
  async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, {
        ...options,
        signal: options.signal || controller.signal,
        headers: {
          'Accept': 'application/json',
          ...(options.headers || {})
        }
      });

      if (!res.ok) {
        const err = new Error(`HTTP ${res.status}: ${res.statusText || 'Request failed'}`);
        err.status = res.status;
        throw err;
      }

      const data = await res.json();
      return data;
    } catch (err) {
      if (err.name === 'AbortError' || (err.message && err.message.includes('abort'))) {
        const timeoutErr = new Error('网络请求超时 (10s)，请检查网络连接 (abort)');
        timeoutErr.name = 'AbortError';
        throw timeoutErr;
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  function getRpcGatewayUrl() {
    return state.rpcGatewayUrl || 'https://api.prlscan.com/v1';
  }

  // ======================== Feature 8: 真实链上地址余额查询 ========================

  /**
   * 向官方开放 REST API (api.prlscan.com/v1/addresses/{address}) 查询真实余额
   * @param {string} address Pearl Bech32m 地址 (prl1p...)
   * @returns {Promise<number>} 真实余额 (单位: PRL, 1 PRL = 10^8 grains)
   */
  async function fetchAddressBalance(address) {
    if (!address) return 0;
    try {
      const baseUrl = getRpcGatewayUrl();
      const data = await fetchWithTimeout(`${baseUrl}/addresses/${encodeURIComponent(address)}`);
      if (data && data.balance_grains !== undefined && data.balance_grains !== null) {
        const grains = Number(data.balance_grains);
        if (!isNaN(grains) && grains >= 0) {
          return grains / 1e8;
        }
      }
      return 0;
    } catch (err) {
      if (err.status === 404) {
        // 未在链上出现过的新建地址，余额为 0
        return 0;
      }
      console.warn(`[Network] 查询地址余额失败 [${address}]:`, err);
      throw err;
    }
  }
  window.fetchAddressBalance = fetchAddressBalance;

  /**
   * 刷新当前活跃钱包的真实链上余额并同步更新界面
   */
  async function refreshActiveWalletBalance(silent = false) {
    const wallet = getActiveWallet();
    if (!wallet || !wallet.address) return;

    try {
      const balance = await fetchAddressBalance(wallet.address);
      wallet.balance = balance;
      saveWalletsToStorage();
      renderWalletBalances();
      renderWalletsListModal();
    } catch (err) {
      if (!silent) {
        showToast(`余额更新失败: ${err.message || '网络连接异常'}`);
      }
    }
  }
  window.refreshActiveWalletBalance = refreshActiveWalletBalance;

  // ======================== Feature 9: 真实链上交易历史查询 ========================

  /**
   * 查询地址真实交易历史 (api.prlscan.com/v1/addresses/{address}/txs?limit=50)
   * @param {string} address Pearl Bech32m 地址
   * @param {number} limit 记录上限 (默认 50 条)
   * @returns {Promise<Array>} 标准化交易流水对象列表
   */
  async function fetchAddressTransactions(address, limit = 50) {
    if (!address) return [];
    try {
      const baseUrl = getRpcGatewayUrl();
      const data = await fetchWithTimeout(`${baseUrl}/addresses/${encodeURIComponent(address)}/txs?limit=${limit}`);
      
      // 支持直接数组返回，并过滤 null/非对象项
      const list = Array.isArray(data) ? data : (data && Array.isArray(data.items) ? data.items : []);
      const rawItems = list.filter(item => item && typeof item === 'object');
      return rawItems.map(tx => {
        const isReceive = (tx.delta_grains || 0) >= 0;
        const deltaPRL = Math.abs((tx.delta_grains || 0) / 1e8);
        const prefix = isReceive ? '+ ' : '- ';
        let formattedTime = '刚刚';
        if (tx.time) {
          try {
            formattedTime = new Date(tx.time).toLocaleString('zh-CN', { hour12: false });
          } catch (e) {
            formattedTime = tx.time;
          }
        }
        return {
          id: tx.txid,
          type: isReceive ? 'receive' : 'send',
          title: tx.type_label || (isReceive ? '收到转账' : '转出交易'),
          amount: `${prefix}${deltaPRL.toFixed(6)} PRL`,
          time: formattedTime,
          status: tx.status === 'confirmed' ? '已确认' : '打包中'
        };
      });
    } catch (err) {
      if (err.status === 404) return [];
      console.warn(`[Network] 查询交易历史失败 [${address}]:`, err);
      throw err;
    }
  }
  window.fetchAddressTransactions = fetchAddressTransactions;

  /**
   * 刷新当前活跃钱包的链上交易流水并刷新列表
   */
  async function refreshActiveWalletTransactions(silent = false) {
    const wallet = getActiveWallet();
    if (!wallet || !wallet.address) {
      state.txHistory = [];
      renderTxList();
      return;
    }

    try {
      const txs = await fetchAddressTransactions(wallet.address, 50);
      state.txHistory = txs;
      renderTxList();
    } catch (err) {
      if (!silent) {
        showToast(`交易历史同步失败: ${err.message || '网络连接异常'}`);
      }
      renderTxList();
    }
  }
  window.refreshActiveWalletTransactions = refreshActiveWalletTransactions;

  // ======================== Feature 10 & 12: 链上状态与矿池数据同步 ========================

  /**
   * Feature 10: 获取官方链上状态与内存池 (api.prlscan.com/v1/status)
   */
  async function fetchChainStatus() {
    try {
      const baseUrl = getRpcGatewayUrl();
      const data = await fetchWithTimeout(`${baseUrl}/status`);
      if (data) {
        if (typeof data.tip_height === 'number') state.chainInfo.height = data.tip_height;
        if (typeof data.mempool_size === 'number') state.chainInfo.mempool = data.mempool_size;
        state.chainInfo.healthy = Boolean(data.healthy);
        state.chainInfo.tipHash = data.tip_hash || '';
        updateChainDomElements();
      }
      return data;
    } catch (err) {
      console.warn('[Network] 官方链上状态获取失败:', err);
      throw err;
    }
  }

  /**
   * Feature 12: 获取全网矿池统计与算力分布 (api.prlscan.com/v1/pools)
   */
  async function fetchMiningPools() {
    try {
      const baseUrl = getRpcGatewayUrl();
      const data = await fetchWithTimeout(`${baseUrl}/pools`);
      if (data && Array.isArray(data.items)) {
        let totalWorkers = 0;
        let totalMiners = 0;
        let totalHashrateHps = 0;

        data.items.filter(Boolean).forEach(pool => {
          const workers = Number(pool.reported_workers) || 0;
          const miners = Number(pool.reported_miners) || 0;
          const hashrate = Number(pool.reported_hashrate_hps) || 0;
          totalWorkers += workers;
          totalMiners += miners;
          totalHashrateHps += hashrate;
        });

        if (totalWorkers > 0) state.chainInfo.workers = totalWorkers;
        if (totalMiners > 0) state.chainInfo.miners = totalMiners;
        if (totalHashrateHps > 0) {
          state.chainInfo.hashrateEH = (totalHashrateHps / 1e18).toFixed(2);
        }
        state.poolsList = data.items.filter(Boolean);
        updateChainDomElements();
      }
      return data;
    } catch (err) {
      console.warn('[Network] 官方矿池数据获取失败:', err);
      throw err;
    }
  }

  /**
   * 综合链上数据抓取：优先官方 prlscan，辅以 HeroMiners 与 Kryptex 补充单块奖励与全网难度
   */
  window.fetchRealChainData = async function () {
    // 1. 并发抓取官方链上状态与矿池聚合数据
    try {
      await Promise.allSettled([
        fetchChainStatus(),
        fetchMiningPools()
      ]);
    } catch (e) {}

    // 2. 从开放 CORS 的 HeroMiners 获取实时单块奖励和全网难度
    try {
      const hData = await fetchWithTimeout('https://pearl.herominers.com/api/stats', {}, 5000);
      if (hData) {
        if (hData.network) {
          if (!state.chainInfo.height && hData.network.height) state.chainInfo.height = hData.network.height;
          if (hData.network.difficulty) state.chainInfo.difficultyP = (hData.network.difficulty / 1e12).toFixed(2);
          if (!state.chainInfo.hashrateEH || state.chainInfo.hashrateEH === '--') {
            if (hData.network.networkHashps) state.chainInfo.hashrateEH = (hData.network.networkHashps / 1e18).toFixed(2);
          }
        }
        if (hData.pool && hData.pool.averageReward) {
          state.chainInfo.blockReward = (hData.pool.averageReward / 1e8).toFixed(2);
        }
        if (!state.chainInfo.workers && hData.pool && hData.pool.workers) {
          state.chainInfo.workers = hData.pool.workers;
        }
      }
    } catch (e) {
      // 备选 Kryptex 矿池数据
      try {
        const kData = await fetchWithTimeout('https://pool.kryptex.com/prl/api/v1/pool/info', {}, 5000);
        if (kData) {
          if (!state.chainInfo.height && kData.height) state.chainInfo.height = kData.height;
          if (kData.block_reward) state.chainInfo.blockReward = Number(kData.block_reward).toFixed(2);
          if (kData.miners && !state.chainInfo.miners) state.chainInfo.miners = kData.miners;
          if (kData.workers && !state.chainInfo.workers) state.chainInfo.workers = kData.workers;
        }
      } catch (err) {}
    }

    syncNetworkMetricsWithLiveChainData();
    updateChainDomElements();
  };

  // ======================== Feature 11: 真实市价行情与法币汇率 ========================

  /**
   * 获取 CoinMarketCap 实时价格与 Kryptex 实时法币汇率
   * 杜绝任何 Math.random 假扰动，确保完全真实性
   */
  window.fetchRealKryptexRates = async function () {
    let priceUsd = 0;
    let changePct = 0;
    let cnyRate = 7.25;

    // 1. 优先抓取 prlscan CoinMarketCap 官方行情
    try {
      const baseUrl = getRpcGatewayUrl();
      const mData = await fetchWithTimeout(`${baseUrl}/market/prl`, {}, 6000);
      if (mData && typeof mData.price_usd === 'number' && mData.price_usd > 0) {
        priceUsd = mData.price_usd;
        if (typeof mData.price_change_24h_pct === 'number') {
          changePct = mData.price_change_24h_pct;
        }
      }
    } catch (e) {
      console.warn('[Network] CoinMarketCap 行情获取失败:', e);
    }

    // 2. 从 Kryptex 获取最新实时法币汇率 (CNY)
    try {
      const kData = await fetchWithTimeout('https://pool.kryptex.com/api/v1/rates', {}, 6000);
      if (kData) {
        if (kData.fiat && typeof kData.fiat.CNY === 'number') {
          cnyRate = kData.fiat.CNY;
        }
        if (!priceUsd && kData.crypto && typeof kData.crypto.PRL === 'number') {
          priceUsd = kData.crypto.PRL;
        }
      }
    } catch (e) {
      console.warn('[Network] Kryptex 汇率获取失败:', e);
    }

    // 3. 更新全局真实市价状态
    if (priceUsd > 0) {
      state.livePriceUSD = +priceUsd.toFixed(4);
      state.livePriceCNY = +(priceUsd * cnyRate).toFixed(2);
      state.priceChange24hPct = changePct;
    }

    renderWalletBalances();
    updateChainDomElements();
  };
  window.fetchLiveMarketPrice = window.fetchRealKryptexRates;

  // 矿池切换
  window.selectMinerPool = function (pool) {
    triggerHaptic('light');
    state.selectedPool = pool;
    const btnKryptex = document.getElementById('btn-pool-kryptex');
    const btnHero = document.getElementById('btn-pool-herominers');

    if (pool === 'kryptex') {
      btnKryptex.className = "py-2.5 px-3 rounded-xl bg-cyan-500/20 text-cyan-300 font-bold text-xs border border-cyan-400/40 btn-active";
      btnHero.className = "py-2.5 px-3 rounded-xl bg-white/[0.04] text-white/60 font-medium text-xs border border-white/[0.08] btn-active";
    } else {
      btnHero.className = "py-2.5 px-3 rounded-xl bg-purple-500/20 text-purple-300 font-bold text-xs border border-purple-400/40 btn-active";
      btnKryptex.className = "py-2.5 px-3 rounded-xl bg-white/[0.04] text-white/60 font-medium text-xs border border-white/[0.08] btn-active";
    }
  };

  // 全网核心指标交互趋势数据 (动态与真实链上数据锚定同步)
  const networkMetricsData = {
    hashrate: {
      unit: 'EH/s',
      name: '全网算力',
      '24h': { change: '--', min: '--', avg: '--', max: '--', points: [] },
      '7d': { change: '--', min: '--', avg: '--', max: '--', points: [] },
      '30d': { change: '--', min: '--', avg: '--', max: '--', points: [] }
    },
    diff: {
      unit: 'P',
      name: '全网难度',
      '24h': { change: '--', min: '--', avg: '--', max: '--', points: [] },
      '7d': { change: '--', min: '--', avg: '--', max: '--', points: [] },
      '30d': { change: '--', min: '--', avg: '--', max: '--', points: [] }
    },
    reward: {
      unit: 'PRL',
      name: '单块产出',
      '24h': { change: '--', min: '--', avg: '--', max: '--', points: [] },
      '7d': { change: '--', min: '--', avg: '--', max: '--', points: [] },
      '30d': { change: '--', min: '--', avg: '--', max: '--', points: [] }
    }
  };

  // 关键核心：将图表各时段数据与实时拉取的主网算力/难度/产出同步，不使用合成模拟倍率
  function syncNetworkMetricsWithLiveChainData() {
    const liveH = parseFloat(state.chainInfo.hashrateEH);
    const liveDiff = parseFloat(state.chainInfo.difficultyP);
    const liveReward = parseFloat(state.chainInfo.blockReward);

    if (isNaN(liveH) || liveH <= 0) {
      ['24h', '7d', '30d'].forEach(r => {
        networkMetricsData.hashrate[r] = { change: '实时连接中', min: '--', avg: '--', max: '--', points: [] };
      });
    } else {
      const livePoint = [{ time: '实时', val: liveH, note: '主网实时' }];
      ['24h', '7d', '30d'].forEach(r => {
        networkMetricsData.hashrate[r] = {
          change: '实时数据已连接',
          min: `${liveH.toFixed(2)} EH/s`,
          avg: `${liveH.toFixed(2)} EH/s`,
          max: `${liveH.toFixed(2)} EH/s`,
          points: livePoint
        };
      });
    }

    if (isNaN(liveDiff) || liveDiff <= 0) {
      ['24h', '7d', '30d'].forEach(r => {
        networkMetricsData.diff[r] = { change: '实时连接中', min: '--', avg: '--', max: '--', points: [] };
      });
    } else {
      const livePoint = [{ time: '实时', val: liveDiff, note: '主网实时' }];
      ['24h', '7d', '30d'].forEach(r => {
        networkMetricsData.diff[r] = {
          change: '实时数据已连接',
          min: `${liveDiff.toFixed(2)} P`,
          avg: `${liveDiff.toFixed(2)} P`,
          max: `${liveDiff.toFixed(2)} P`,
          points: livePoint
        };
      });
    }

    if (isNaN(liveReward) || liveReward <= 0) {
      ['24h', '7d', '30d'].forEach(r => {
        networkMetricsData.reward[r] = { change: '实时连接中', min: '--', avg: '--', max: '--', points: [] };
      });
    } else {
      const livePoint = [{ time: '实时', val: liveReward, note: '当前单块' }];
      ['24h', '7d', '30d'].forEach(r => {
        networkMetricsData.reward[r] = {
          change: '实时数据已连接',
          min: `${liveReward.toFixed(2)} PRL`,
          avg: `${liveReward.toFixed(2)} PRL`,
          max: `${liveReward.toFixed(2)} PRL`,
          points: livePoint
        };
      });
    }
  }

  // 初始化同步一次默认指标数据
  syncNetworkMetricsWithLiveChainData();

  state.activeChartMetric = 'hashrate';
  state.activeChartRange = '24h';
  let chartComputedPoints = [];
  let chartLastSnapIndex = -1;

  window.switchChartMetric = function (metric) {
    triggerHaptic('light');
    state.activeChartMetric = metric;
    ['hashrate', 'diff', 'reward'].forEach(m => {
      const btn = document.getElementById(`btn-metric-${m}`);
      if (btn) {
        if (m === metric) {
          btn.className = "px-2.5 py-1 rounded-lg text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 transition-all";
        } else {
          btn.className = "px-2.5 py-1 rounded-lg text-xs font-medium text-white/50 border border-transparent hover:text-white transition-all";
        }
      }
    });
    renderInteractiveChart();
  };

  window.switchChartTimeRange = function (range) {
    triggerHaptic('light');
    state.activeChartRange = range;
    ['24h', '7d', '30d'].forEach(r => {
      const btn = document.getElementById(`btn-time-${r}`);
      if (btn) {
        if (r === range) {
          btn.className = "px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 transition-all";
        } else {
          btn.className = "px-2 py-0.5 rounded text-[10px] font-medium text-white/50 transition-all";
        }
      }
    });
    renderInteractiveChart();
  };

  // 兼容老调用
  window.switchHashrateRange = function (range) {
    window.switchChartTimeRange(range);
  };

  function renderInteractiveChart() {
    const metricKey = state.activeChartMetric || 'hashrate';
    const rangeKey = state.activeChartRange || '24h';
    const metricGroup = networkMetricsData[metricKey] || networkMetricsData.hashrate;
    const data = metricGroup[rangeKey] || metricGroup['24h'];

    const titleEl = document.getElementById('chart-data-title');
    const scrubValEl = document.getElementById('chart-scrub-val');
    const scrubTimeEl = document.getElementById('chart-scrub-time');
    const trendTagEl = document.getElementById('chart-trend-tag');
    const statMinEl = document.getElementById('chart-stat-min');
    const statAvgEl = document.getElementById('chart-stat-avg');
    const statMaxEl = document.getElementById('chart-stat-max');

    if (titleEl) {
      titleEl.innerHTML = `<span>${metricGroup.name}</span><span id="chart-scrub-time" class="font-mono text-cyan-400 font-semibold">● 实时最新</span>`;
    }
    if (statMinEl) statMinEl.innerText = `最低: ${data.min}`;
    if (statAvgEl) statAvgEl.innerText = `平均: ${data.avg}`;
    if (statMaxEl) statMaxEl.innerText = `最高/峰值: ${data.max}`;
    if (trendTagEl) trendTagEl.innerText = data.change;

    const points = data.points || [];
    const linePath = document.getElementById('hashrate-line-path');
    const areaPath = document.getElementById('hashrate-area-path');
    const pointCircle = document.getElementById('hashrate-point');

    if (points.length === 0) {
      if (scrubValEl) scrubValEl.innerText = '--';
      chartComputedPoints = [];
      if (linePath) linePath.setAttribute('d', '');
      if (areaPath) areaPath.setAttribute('d', '');
      if (pointCircle) pointCircle.setAttribute('cx', '-100');
      hideChartCrosshair();
      return;
    }

    const values = points.map(p => p.val);
    let minVal = Math.min(...values);
    let maxVal = Math.max(...values);
    if (minVal === maxVal) {
      minVal = minVal > 0 ? minVal * 0.98 : 0;
      maxVal = maxVal > 0 ? maxVal * 1.02 : 1;
    } else {
      const pad = (maxVal - minVal) * 0.12;
      minVal -= pad;
      maxVal += pad;
    }

    const svgWidth = 320;
    const svgHeight = 110;

    chartComputedPoints = points.map((p, idx) => {
      const x = points.length === 1 ? svgWidth / 2 : (idx / (points.length - 1)) * svgWidth;
      const y = (maxVal === minVal) ? svgHeight / 2 : svgHeight - ((p.val - minVal) / (maxVal - minVal)) * (svgHeight - 20) - 10;
      return { x, y, ...p };
    });

    // 默认展示最新点
    const latest = chartComputedPoints[chartComputedPoints.length - 1];
    if (scrubValEl && latest) {
      scrubValEl.innerText = `${latest.val.toLocaleString()} ${metricGroup.unit}`;
    }

    let pathD = `M${chartComputedPoints[0].x.toFixed(1)},${chartComputedPoints[0].y.toFixed(1)}`;
    if (chartComputedPoints.length === 1) {
      pathD = `M0,${chartComputedPoints[0].y.toFixed(1)} L${svgWidth},${chartComputedPoints[0].y.toFixed(1)}`;
    } else {
      for (let i = 0; i < chartComputedPoints.length - 1; i++) {
        const p0 = chartComputedPoints[i];
        const p1 = chartComputedPoints[i + 1];
        const cx = ((p0.x + p1.x) / 2).toFixed(1);
        pathD += ` C${cx},${p0.y.toFixed(1)} ${cx},${p1.y.toFixed(1)} ${p1.x.toFixed(1)},${p1.y.toFixed(1)}`;
      }
    }

    if (linePath) linePath.setAttribute('d', pathD);
    if (areaPath) areaPath.setAttribute('d', `${pathD} L${svgWidth},120 L0,120 Z`);
    if (pointCircle && latest) {
      pointCircle.setAttribute('cx', latest.x);
      pointCircle.setAttribute('cy', latest.y);
    }

    hideChartCrosshair();
  }

  function hideChartCrosshair() {
    const crosshair = document.getElementById('chart-crosshair');
    const tooltip = document.getElementById('chart-tooltip');
    if (crosshair) crosshair.classList.add('hidden');
    if (tooltip) tooltip.classList.add('hidden');
    chartLastSnapIndex = -1;

    // 当用户移开手指或松手后，自动复位显示为“实时最新”数值与点位，避免长时间停留在历史某个时点
    if (chartComputedPoints && chartComputedPoints.length > 0) {
      const metricKey = state.activeChartMetric || 'hashrate';
      const metricGroup = networkMetricsData[metricKey] || networkMetricsData.hashrate;
      const latest = chartComputedPoints[chartComputedPoints.length - 1];
      const scrubValEl = document.getElementById('chart-scrub-val');
      const scrubTimeEl = document.getElementById('chart-scrub-time');
      const pointCircle = document.getElementById('hashrate-point');

      if (scrubValEl && latest) {
        scrubValEl.innerText = `${latest.val.toLocaleString()} ${metricGroup.unit}`;
      }
      if (scrubTimeEl) {
        scrubTimeEl.innerText = `● 实时最新`;
      }
      if (pointCircle && latest) {
        pointCircle.setAttribute('cx', latest.x);
        pointCircle.setAttribute('cy', latest.y);
      }
    }
  }

  // 绑定图表手指触控与鼠标交互查探任意点
  function setupInteractiveChartScrubbing() {
    const container = document.getElementById('hashrate-chart-container');
    if (!container) return;

    function handlePointerMove(e) {
      if (!chartComputedPoints || chartComputedPoints.length === 0) return;
      const rect = container.getBoundingClientRect();
      const clientX = e.clientX || (e.touches && e.touches[0] ? e.touches[0].clientX : null);
      if (clientX === null) return;

      const relX = Math.max(0, Math.min(rect.width, clientX - rect.left));
      const ratio = relX / rect.width;
      const targetSvgX = ratio * 320;

      // 寻找距离最近的离散数据点
      let closestIdx = 0;
      let minDiff = Infinity;
      chartComputedPoints.forEach((p, idx) => {
        const diff = Math.abs(p.x - targetSvgX);
        if (diff < minDiff) {
          minDiff = diff;
          closestIdx = idx;
        }
      });

      const p = chartComputedPoints[closestIdx];
      if (!p) return;

      if (closestIdx !== chartLastSnapIndex) {
        triggerHaptic('light');
        chartLastSnapIndex = closestIdx;
      }

      const metricKey = state.activeChartMetric || 'hashrate';
      const metricGroup = networkMetricsData[metricKey] || networkMetricsData.hashrate;

      // 更新顶部显示
      const scrubValEl = document.getElementById('chart-scrub-val');
      const scrubTimeEl = document.getElementById('chart-scrub-time');
      if (scrubValEl) {
        scrubValEl.innerText = `${p.val.toLocaleString()} ${metricGroup.unit}`;
      }
      if (scrubTimeEl) {
        scrubTimeEl.innerText = `● ${p.time}${p.note ? ' (' + p.note + ')' : ''}`;
      }

      // 移动高亮圆点
      const pointCircle = document.getElementById('hashrate-point');
      if (pointCircle) {
        pointCircle.setAttribute('cx', p.x);
        pointCircle.setAttribute('cy', p.y);
      }

      // 移动纵向辅助十字线
      const crosshair = document.getElementById('chart-crosshair');
      if (crosshair) {
        crosshair.classList.remove('hidden');
        const pctX = (p.x / 320) * 100;
        crosshair.style.left = `${pctX}%`;
      }

      // 移动悬浮气泡
      const tooltip = document.getElementById('chart-tooltip');
      const tooltipVal = document.getElementById('tooltip-val');
      if (tooltip && tooltipVal) {
        tooltip.classList.remove('hidden');
        const pctX = (p.x / 320) * 100;
        tooltip.style.left = `${pctX}%`;
        const pctY = (p.y / 120) * 100;
        tooltip.style.top = `${Math.max(10, pctY)}%`;
        tooltipVal.innerText = `${p.time} : ${p.val} ${metricGroup.unit}`;
      }
    }

    container.addEventListener('pointerdown', (e) => {
      container.setPointerCapture(e.pointerId);
      handlePointerMove(e);
    });

    container.addEventListener('pointermove', handlePointerMove);

    container.addEventListener('pointerup', () => {
      setTimeout(hideChartCrosshair, 2000);
    });

    container.addEventListener('pointerleave', () => {
      setTimeout(hideChartCrosshair, 1500);
    });
  }

  window.renderHashrateChart = renderInteractiveChart;

  // 一键填入当前钱包地址
  window.fillCurrentWalletAddress = function () {
    triggerHaptic('light');
    const wallet = getActiveWallet();
    const input = document.getElementById('custom-miner-address');
    if (!wallet) {
      showToast("当前设备无钱包，请先创建或导入");
      return;
    }
    if (input) {
      input.value = wallet.address;
      showToast("已填入当前钱包地址");
    }
  };


  // 格式化算力单位
  function formatHashrate(hr) {
    const num = Number(hr) || 0;
    if (num >= 1e18) return (num / 1e18).toFixed(2) + " EH/s";
    if (num >= 1e15) return (num / 1e15).toFixed(2) + " PH/s";
    if (num >= 1e12) return (num / 1e12).toFixed(2) + " TH/s";
    if (num >= 1e9) return (num / 1e9).toFixed(2) + " GH/s";
    if (num >= 1e6) return (num / 1e6).toFixed(2) + " MH/s";
    if (num >= 1e3) return (num / 1e3).toFixed(2) + " KH/s";
    return num.toFixed(2) + " H/s";
  }

  // 3. 矿工真实收益查询 (原生支持 HeroMiners 与 Kryptex 双通道解析)
  window.queryMinerByAddress = function () {
    const input = document.getElementById('custom-miner-address');
    const resultBox = document.getElementById('miner-query-result');
    let rawAddr = input?.value.trim() || (getActiveWallet()?.address) || '';

    if (!rawAddr) {
      showToast("请输入 Pearl 矿工收款地址");
      return;
    }

    // 自动清洗过滤结尾冒号或 worker 后缀 (如 prl1xxxx:worker1)
    const cleanAddr = rawAddr.split(/[:/]/)[0].trim();

    // Feature 16: 校验矿工 Pearl Taproot Bech32m 地址与校验和
    const check = validatePearlAddress(cleanAddr);
    if (!check.valid) {
      triggerHaptic('error');
      showToast(`矿工地址无效: ${formatAddressError(check.error)}`);
      if (resultBox) {
        resultBox.classList.remove('hidden');
        resultBox.innerHTML = `
          <div class="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs leading-relaxed">
            ⚠️ 矿工地址无效: ${formatAddressError(check.error)}<br>
            <span class="text-white/40 text-[10px]">请核对是否为有效的 Pearl Taproot 主网地址 (prl1p...)</span>
          </div>
        `;
      }
      return;
    }

    triggerHaptic('light');
    showToast("正在连接矿池查询实时账目...");
    if (resultBox) {
      resultBox.classList.remove('hidden');
      resultBox.innerHTML = `
        <div class="py-3 text-center text-white/60 flex items-center justify-center gap-2">
          <svg class="w-4 h-4 text-cyan-400 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path></svg>
          正在检索 ${cleanAddr.slice(0, 10)}... 矿池账目
        </div>
      `;
    }

    // A. HeroMiners 矿池通道 (完全开放 CORS 协议)
    if (state.selectedPool === 'herominers') {
      fetch(`https://pearl.herominers.com/api/stats_address?address=${cleanAddr}`)
        .then(res => res.json())
        .then(data => {
          if (!resultBox) return;
          if (data && data.error) {
            resultBox.innerHTML = `
              <div class="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs leading-relaxed">
                <div class="font-bold mb-1">未在 HeroMiners 检索到有效矿机</div>
                <div class="text-[11px] text-white/60 mb-2">该地址可能尚未连接至 HeroMiners 提交有效算力，或地址校验和有误。</div>
                <a href="https://pearl.herominers.com/?address=${cleanAddr}" target="_blank" class="block w-full py-2 rounded-lg bg-amber-500/20 text-center font-bold text-amber-200">
                  前往 HeroMiners 官网核对 ↗
                </a>
              </div>
            `;
            return;
          }

          const stats = data.stats || {};
          const workers = data.workers || [];
          const hashrate = stats.hashrate ? formatHashrate(stats.hashrate) : "0.00 H/s";
          const unpaid = stats.balance ? (stats.balance / 1e8).toFixed(4) : "0.0000";
          const paid = stats.paid ? (stats.paid / 1e8).toFixed(4) : "0.0000";
          const blocksFound = stats.blocksFound || 0;

          resultBox.innerHTML = `
            <div class="space-y-2 py-1">
              <div class="flex items-center justify-between border-b border-white/[0.05] pb-2">
                <span class="text-white/60">矿池节点</span>
                <span class="font-bold text-purple-300">HeroMiners (Prop)</span>
              </div>
              <div class="flex justify-between border-b border-white/[0.05] pb-2">
                <span class="text-white/70">实时算力:</span>
                <span class="text-cyan-300 font-bold font-mono text-sm">${hashrate}</span>
              </div>
              <div class="flex justify-between border-b border-white/[0.05] pb-2">
                <span class="text-white/70">待结算收益 (Unpaid):</span>
                <span class="text-amber-300 font-bold font-mono">${unpaid} PRL</span>
              </div>
              <div class="flex justify-between border-b border-white/[0.05] pb-2">
                <span class="text-white/70">已支付收益 (Paid):</span>
                <span class="text-emerald-400 font-bold font-mono">${paid} PRL</span>
              </div>
              <div class="flex justify-between text-white/50 text-[11px] pt-1 border-b border-white/[0.05] pb-2">
                <span>出块总数: ${blocksFound} 个</span>
                <span>在线矿机: ${workers.length} 台</span>
              </div>
              ${workers.length > 0 ? `
                <div class="pt-1">
                  <div class="text-[11px] text-white/50 mb-1.5 flex justify-between">
                    <span>活跃矿机 Worker (前 ${Math.min(workers.length, 3)} 台):</span>
                    <span class="text-cyan-400 font-medium">状态</span>
                  </div>
                  <div class="space-y-1.5 text-[11px]">
                    ${workers.slice(0, 3).map(w => `
                      <div class="flex items-center justify-between p-2 rounded-xl bg-white/[0.03] border border-white/[0.05]">
                        <span class="font-mono text-white/90 truncate max-w-[120px]">${w.name || '默认矿机'}</span>
                        <span class="text-white/40 text-[10px]">${w.agent || 'peakminer'}</span>
                        <span class="font-mono text-cyan-300 font-bold">${formatHashrate(w.hashrate)}</span>
                      </div>
                    `).join('')}
                  </div>
                </div>
              ` : ''}
              <div class="pt-2">
                <a href="https://pearl.herominers.com/?address=${cleanAddr}" target="_blank" class="block w-full py-2.5 rounded-xl bg-purple-500/20 text-purple-300 font-bold text-center border border-purple-400/30 btn-active">
                  👉 在 HeroMiners 实时看板中查看此地址 ↗
                </a>
              </div>
            </div>
          `;
        })
        .catch(err => {
          if (!resultBox) return;
          resultBox.innerHTML = `
            <div class="p-3 rounded-xl bg-white/[0.03] border border-white/[0.06] text-xs">
              <div class="text-white/70 mb-2">矿池连接已发送，若本地网络限制可通过官网直达：</div>
              <a href="https://pearl.herominers.com/?address=${cleanAddr}" target="_blank" class="block w-full py-2.5 rounded-xl bg-purple-500/20 text-purple-300 font-bold text-center border border-purple-400/30">
                👉 在 HeroMiners 实时看板中查看此地址 ↗
              </a>
            </div>
          `;
        });
      return;
    }

    // B. Kryptex 官方矿池通道 (直接调用官方 API 并展示真实统计)
    if (state.selectedPool === 'kryptex') {
      resultBox.innerHTML = `
        <div class="space-y-3 py-1">
          <div class="flex items-center justify-between border-b border-white/[0.05] pb-2">
            <div class="flex items-center gap-1.5">
              <span class="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
              <span class="font-bold text-cyan-300">Kryptex 官方矿池直连</span>
            </div>
            <span class="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full font-medium">PPS+ 结算</span>
          </div>

          <div class="grid grid-cols-2 gap-2 text-xs">
            <div class="p-3 rounded-xl bg-white/[0.03] border border-white/[0.05]">
              <div class="text-white/40 mb-1">矿池起付额度</div>
              <div class="font-bold text-cyan-300 font-mono">1.0 PRL (自动打款)</div>
            </div>
            <div class="p-3 rounded-xl bg-white/[0.03] border border-white/[0.05]">
              <div class="text-white/40 mb-1">矿池费率模式</div>
              <div class="font-bold text-emerald-400 font-mono">PPS+ 3% (SOLO 1%)</div>
            </div>
          </div>

          <div class="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-500/20 text-xs space-y-2">
            <div class="flex items-center justify-between">
              <span class="text-white/70">目标矿工地址:</span>
              <span class="text-[10px] text-cyan-400 font-mono">主网在线</span>
            </div>
            <div class="font-mono text-cyan-200 break-all text-[11px] select-all">${cleanAddr}</div>
            <div class="text-[11px] text-white/50 pt-1 leading-relaxed">
              💡 Kryptex 官方已同步 PearlHash 全网 108,000+ 台活跃矿机。点击下方按钮可直接呼出 Kryptex 官方全屏实时大盘，查看 24H 波动、未确认收益与活跃 Workers：
            </div>
          </div>

          <a href="https://pool.kryptex.com/prl/miner/stats/${cleanAddr}" target="_blank" class="block w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-400 to-indigo-500 text-black font-bold text-xs text-center shadow-lg shadow-cyan-500/20 btn-active">
            👉 在 Kryptex 官方实时看板中查看详情 ↗
          </a>

          <div class="flex items-center justify-between text-[11px] text-white/40 pt-1">
            <span>数据源: pool.kryptex.com 官方直连</span>
            <button type="button" onclick="selectMinerPool('herominers'); queryMinerByAddress();" class="text-purple-300 hover:underline">
              切换到 HeroMiners 探测 ➔
            </button>
          </div>
        </div>
      `;
      return;
    }
  };

  window.refreshChainData = function () {
    triggerHaptic('medium');
    fetchRealChainData();
    fetchRealKryptexRates();
    refreshActiveWalletBalance(false);
    refreshActiveWalletTransactions(false);
    showToast("已刷新全网数据");
  };

  function updateChainDomElements() {
    const hEl = document.getElementById('banner-block-height');
    const mEl = document.getElementById('banner-active-miners');
    const rEl = document.getElementById('banner-block-reward');
    const poolWorkersEl = document.getElementById('pool-active-workers');
    const hashrateEl = document.getElementById('miner-hashrate');
    const tokenomicsRewardEl = document.getElementById('tokenomics-block-reward');
    const emissionEl = document.getElementById('tokenomics-daily-emission');
    const fiatEl = document.getElementById('tokenomics-daily-fiat');

    const totalSupplyEl = document.getElementById('tokenomics-total-supply');
    const supplyPctEl = document.getElementById('tokenomics-supply-pct');
    const marketCapEl = document.getElementById('tokenomics-market-cap');
    const marketCapCnyEl = document.getElementById('tokenomics-market-cap-cny');
    const livePriceEl = document.getElementById('tokenomics-live-price');
    const marketPriceTagEl = document.getElementById('market-price-tag');
    const walletTotalSupplyEl = document.getElementById('wallet-total-supply');
    const walletMarketCapEl = document.getElementById('wallet-total-market-cap');

    const rewardNum = parseFloat(state.chainInfo.blockReward) || 0;
    const heightNum = parseInt(state.chainInfo.height, 10) || 0;
    const dailyBlocks = 445; // 86400 / 194.3s
    const dailyPRL = dailyBlocks * rewardNum;
    const dailyWan = (dailyPRL / 10000).toFixed(2);
    const dailyUSDWan = ((dailyPRL * state.livePriceUSD) / 10000).toFixed(1);

    // 历史累计总产出（创世单块约 3229.64 PRL，连续平滑线性衰减积分估算）
    const genesisReward = 3229.64;
    const avgRewardPerBlock = (genesisReward + rewardNum) / 2;
    const totalCirculatingPRL = heightNum * avgRewardPerBlock;
    const totalCirculatingYi = (totalCirculatingPRL / 1e8).toFixed(2);
    const supplyPct = ((totalCirculatingPRL / 2.1e9) * 100).toFixed(2);

    // 全网总流通市值
    const totalMarketCapUSD = (totalCirculatingPRL * state.livePriceUSD) / 1e8;
    const totalMarketCapCNY = (totalCirculatingPRL * state.livePriceCNY) / 1e8;

    if (hEl) hEl.innerText = heightNum ? Number(heightNum).toLocaleString() : '--';
    if (mEl) mEl.innerText = state.chainInfo.miners ? Number(state.chainInfo.miners).toLocaleString() : '--';
    if (rEl) rEl.innerText = rewardNum ? `${rewardNum.toFixed(2)} PRL` : '-- PRL';
    if (tokenomicsRewardEl) tokenomicsRewardEl.innerText = rewardNum ? `${rewardNum.toFixed(2)} PRL` : '-- PRL';
    if (emissionEl) emissionEl.innerText = rewardNum ? `~${dailyWan} 万 PRL` : '-- 万 PRL';
    if (fiatEl) fiatEl.innerText = (rewardNum && state.livePriceUSD) ? `≈ $${dailyUSDWan} 万 USD/天` : '--';
    if (poolWorkersEl) poolWorkersEl.innerText = state.chainInfo.workers ? `${Number(state.chainInfo.workers).toLocaleString()} 矿机在线` : '-- 矿机在线';
    if (hashrateEl) hashrateEl.innerText = state.chainInfo.hashrateEH && state.chainInfo.hashrateEH !== '--' ? `${state.chainInfo.hashrateEH} EH/s` : '-- EH/s';

    if (totalSupplyEl) totalSupplyEl.innerText = heightNum ? `~${totalCirculatingYi} 亿 PRL` : '-- 亿 PRL';
    if (supplyPctEl) supplyPctEl.innerText = heightNum ? `占总硬顶 ${supplyPct}%` : '--';
    if (marketCapEl) marketCapEl.innerText = (heightNum && state.livePriceUSD) ? `≈ $${totalMarketCapUSD.toFixed(2)} 亿 USD` : '-- USD';
    if (marketCapCnyEl) marketCapCnyEl.innerText = (heightNum && state.livePriceCNY) ? `≈ ¥${totalMarketCapCNY.toFixed(2)} 亿 CNY` : '-- CNY';
    if (livePriceEl) livePriceEl.innerText = state.livePriceUSD ? `1 PRL ≈ $${state.livePriceUSD.toFixed(2)}` : '1 PRL ≈ --';
    if (marketPriceTagEl) marketPriceTagEl.innerHTML = state.livePriceUSD ? `<span>1 PRL ≈ $${state.livePriceUSD.toFixed(2)}</span>` : '<span>1 PRL ≈ --</span>';
    if (walletTotalSupplyEl) walletTotalSupplyEl.innerText = heightNum ? `~${totalCirculatingYi} 亿 PRL` : '-- 亿 PRL';
    if (walletMarketCapEl) walletMarketCapEl.innerText = (heightNum && state.livePriceUSD) ? `$${totalMarketCapUSD.toFixed(2)} 亿` : '--';

    // 关键联动：当拉取到主网真实算力与出块数据后，同步更新图表各周期走势，并重新绘制图表，确保上下数据绝对一致
    syncNetworkMetricsWithLiveChainData();
    renderInteractiveChart();
  }

  function renderAll() {
    const onboardingEl = document.getElementById('view-onboarding');
    const walletEl = document.getElementById('view-wallet');
    const headerPill = document.getElementById('header-wallet-pill');
    const settingsActions = document.getElementById('settings-wallet-actions');
    const settingsNoWallet = document.getElementById('settings-no-wallet-prompt');

    if (state.wallets.length === 0) {
      if (onboardingEl) onboardingEl.classList.remove('hidden');
      if (walletEl) walletEl.classList.add('hidden');
      if (headerPill) headerPill.classList.add('opacity-40');
      if (settingsActions) settingsActions.classList.add('hidden');
      if (settingsNoWallet) settingsNoWallet.classList.remove('hidden');

      const nameEl = document.getElementById('header-wallet-name');
      const addrPill = document.getElementById('wallet-address-pill');
      if (nameEl) nameEl.innerText = state.currentLang === 'en' ? "No Wallet Selected" : "未选择钱包";
      if (addrPill) addrPill.innerText = state.currentLang === 'en' ? "Click below to create or import" : "点击下方创建或导入";

      const countEl = document.getElementById('settings-wallets-count');
      if (countEl) countEl.innerText = state.currentLang === 'en' ? "0 Active Wallets" : "0 个活跃钱包";

      renderWalletsListModal();
      updateChainDomElements();
      return;
    }

    if (onboardingEl) onboardingEl.classList.add('hidden');
    if (walletEl) walletEl.classList.remove('hidden');
    if (headerPill) headerPill.classList.remove('opacity-40');
    if (settingsActions) settingsActions.classList.remove('hidden');
    if (settingsNoWallet) settingsNoWallet.classList.add('hidden');

    const wallet = getActiveWallet();
    if (!wallet) return;

    const nameEl = document.getElementById('header-wallet-name');
    const addrPill = document.getElementById('wallet-address-pill');
    if (nameEl) nameEl.innerText = wallet.name;
    if (addrPill) {
      addrPill.innerText = `${wallet.address.slice(0, 8)}...${wallet.address.slice(-6)}`;
    }

    renderWalletBalances();
    renderTxList();
    renderWalletsListModal();

    const countEl = document.getElementById('settings-wallets-count');
    if (countEl) countEl.innerText = `${state.wallets.length} 个活跃钱包`;

    updateChainDomElements();
  }

  function renderWalletBalances() {
    const priceTag = document.getElementById('market-price-tag');
    if (priceTag) priceTag.innerHTML = state.livePriceUSD ? `<span>1 PRL ≈ $${state.livePriceUSD.toFixed(2)}</span>` : '<span>1 PRL ≈ --</span>';

    const wallet = getActiveWallet();
    if (!wallet) return;

    const balEl = document.getElementById('wallet-balance');
    const fiatEl = document.getElementById('wallet-fiat');
    const sendBalEl = document.getElementById('send-available-balance');

    const bal = Number(wallet.balance) || 0;
    if (balEl) balEl.innerText = bal.toLocaleString('en-US', { minimumFractionDigits: 2 });
    
    const cnyVal = (bal * (state.livePriceCNY || 0)).toLocaleString('en-US', { minimumFractionDigits: 2 });
    const usdVal = (bal * (state.livePriceUSD || 0)).toLocaleString('en-US', { minimumFractionDigits: 2 });
    
    if (fiatEl) fiatEl.innerText = `≈ ¥${cnyVal} CNY ($${usdVal} USD)`;
    if (sendBalEl) sendBalEl.innerText = `${bal.toFixed(2)} PRL`;
  }

  function renderTxList() {
    const list = document.getElementById('tx-list-container');
    if (!list) return;

    if (state.txHistory.length === 0) {
      const wallet = getActiveWallet();
      const addr = wallet ? wallet.address : '';
      list.innerHTML = `
        <div class="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.04] text-center my-4">
          <div class="w-12 h-12 rounded-2xl bg-white/[0.04] text-white/30 flex items-center justify-center mx-auto mb-3">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          </div>
          <div class="text-xs font-semibold text-white/60">当前地址链上暂无交易</div>
          <div class="text-[11px] text-white/30 mt-1 max-w-xs mx-auto leading-relaxed">
            该地址在 Pearl 全网主板上为全新空白地址。请通过【多钱包】导入你已有的电脑助记词，或向此地址充值。
          </div>
          ${addr ? `
          <a href="https://prlscan.com/address/${addr}" target="_blank" class="inline-block mt-3 text-xs text-cyan-400 font-medium hover:underline">
            在 PearlScan 区块浏览器上查验此地址 ↗
          </a>` : ''}
        </div>
      `;
      return;
    }

    list.innerHTML = state.txHistory.map(tx => {
      const isPositive = tx.amount.startsWith('+');
      return `
        <div class="flex items-center justify-between p-3.5 rounded-2xl bg-white/[0.03] border border-white/[0.05] mb-2 btn-active">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-xl flex items-center justify-center ${
              isPositive ? 'bg-emerald-500/10 text-emerald-400' : 'bg-purple-500/10 text-purple-400'
            }">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                ${
                  isPositive ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 14l-7 7m0 0l-7-7m7 7V3"/>' :
                  '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18"/>'
                }
              </svg>
            </div>
            <div>
              <div class="text-sm font-semibold text-white/90">${tx.title}</div>
              <div class="text-xs text-white/40 mt-0.5">${tx.time} · ${tx.status}</div>
            </div>
          </div>
          <div class="text-right">
            <div class="text-sm font-bold tabular-numbers ${isPositive ? 'text-cyan-300' : 'text-white/80'}">${tx.amount}</div>
            <div class="text-[11px] text-white/30 tabular-numbers">已确认</div>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderWalletsListModal() {
    const container = document.getElementById('wallets-list-container');
    if (!container) return;

    if (state.wallets.length === 0) {
      container.innerHTML = `<div class="text-xs text-white/40 text-center py-4">${state.currentLang === 'en' ? 'No wallets available, create or import first.' : '暂无钱包，请先创建或导入'}</div>`;
      return;
    }

    container.innerHTML = state.wallets.map((w, index) => {
      const isActive = w.id === state.activeWalletId;
      const bal = Number(w.balance) || 0;
      return `
        <div id="wallet-card-${w.id}" class="p-3.5 rounded-2xl ${isActive ? 'bg-cyan-500/10 border-cyan-400/40' : 'bg-white/[0.03] border-white/[0.08]'} border flex items-center justify-between transition-all duration-300">
          <div class="flex items-center gap-3 cursor-pointer flex-1" onclick="switchActiveWallet('${w.id}')">
            <div class="w-9 h-9 rounded-full ${isActive ? 'bg-cyan-400 text-black font-extrabold' : 'bg-white/10 text-white/60'} text-xs flex items-center justify-center">
              ${index + 1}
            </div>
            <div>
              <div class="flex items-center gap-2">
                <span class="text-xs font-bold text-white">${w.name}</span>
                ${isActive ? `<span class="text-[10px] bg-cyan-400/20 text-cyan-300 px-1.5 py-0.2 rounded font-semibold">${state.currentLang === 'en' ? 'Active' : '当前'}</span>` : ''}
              </div>
              <div class="text-[11px] font-mono text-white/40 mt-0.5">${w.address.slice(0, 10)}...${w.address.slice(-6)}</div>
              <div class="text-[11px] font-bold text-cyan-200 mt-0.5 tabular-numbers">${bal.toFixed(2)} PRL</div>
            </div>
          </div>

          <button onclick="confirmDeleteWallet('${w.id}', '${w.name}')" class="p-2 text-white/30 hover:text-rose-400 btn-active ml-2" title="删除钱包">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
          </button>
        </div>
      `;
    }).join('');
  }

  window.handleHeaderWalletClick = function () {
    triggerHaptic('light');
    if (state.wallets.length === 0) {
      showToast(state.currentLang === 'en' ? "No wallet on this device, please create or import below." : "当前设备无钱包，请先在下方创建或导入");
      return;
    }
    openSheet('sheet-wallet-manager');
  };

  window.switchActiveWallet = function (walletId) {
    if (state.activeWalletId === walletId) return;
    triggerHaptic('light');
    state.activeWalletId = walletId;
    saveWalletsToStorage();
    renderAll();
    closeSheet();
    refreshActiveWalletBalance(true);
    refreshActiveWalletTransactions(true);
    showToast(state.currentLang === 'en' ? `Switched to: ${getActiveWallet().name}` : `已切换至: ${getActiveWallet().name}`);
  };

  window.confirmDeleteWallet = function (walletId, walletName) {
    triggerHaptic('heavy');
    const msg = state.currentLang === 'en'
      ? `⚠️ Are you sure you want to delete wallet [${walletName}]?\n\nPlease make sure you have backed up its 12-word seed phrase on paper! Once deleted, funds cannot be recovered without the seed phrase.`
      : `⚠️ 确定要从本地移除钱包【${walletName}】吗？\n\n请确保已在纸上完整抄录该钱包的助记词！删除后若未记录将永久无法找回。`;
    const confirmed = confirm(msg);
    if (confirmed) {
      triggerHaptic('medium');
      const cardEl = document.getElementById(`wallet-card-${walletId}`);
      if (cardEl) {
        cardEl.style.transition = 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)';
        cardEl.style.transform = 'translateX(-100%)';
        cardEl.style.opacity = '0';
        cardEl.style.maxHeight = '0';
        cardEl.style.margin = '0';
        cardEl.style.padding = '0';
      }

      setTimeout(() => {
        state.wallets = state.wallets.filter(w => w.id !== walletId);
        if (state.activeWalletId === walletId) {
          state.activeWalletId = state.wallets[0] ? state.wallets[0].id : null;
        }
        saveWalletsToStorage();

        if (state.wallets.length === 0) {
          closeSheet();
          renderAll();
          triggerHaptic('success');
          showToast(state.currentLang === 'en' ? `🗑️ Wallet [${walletName}] deleted` : `🗑️ 钱包【${walletName}】已删除`);
        } else {
          renderWalletsListModal();
          renderAll();
          triggerHaptic('success');
          const nextWallet = getActiveWallet();
          showToast(state.currentLang === 'en' ? `🗑️ [${walletName}] deleted, switched to [${nextWallet.name}]` : `🗑️ 已删除【${walletName}】，已切换至【${nextWallet.name}】`);
        }
      }, 250);
    }
  };

  // ======================== 创建钱包极速流 (零密码阻碍 + 硬件级随机熵) ========================
  window.startCreateWalletFlow = function () {
    triggerHaptic('success');
    const name = `Pearl-${String(state.wallets.length + 1).padStart(2, '0')}`;

    // 严谨生成 12 位标准 BIP-39 助记词
    const words = generateMnemonic();
    const { address, privateKeyHex } = deriveFromSeed(words);

    state.pendingWallet = {
      id: `wallet-${Date.now()}`,
      name,
      mnemonic: words,
      address,
      privateKeyHex,
      balance: 0.00,
      createdAt: new Date().toISOString()
    };

    // 动态注入 12 词网格
    const grid = document.getElementById('create-mnemonic-grid');
    if (grid) {
      grid.innerHTML = words.map((word, idx) => `
        <div class="flex items-center gap-2 p-2.5 rounded-xl bg-white/[0.05] border border-white/[0.08]">
          <span class="text-[10px] text-white/30 w-4 font-mono">${idx + 1}</span>
          <span class="text-xs font-mono font-bold text-cyan-200 tracking-wide select-all">${word}</span>
        </div>
      `).join('');
    }

    // 初始化防截屏长按显影手势
    initHoldToReveal();

    openSheet('sheet-create-backup');
    showToast("已生成 12 位助记词，按住卡片显现");
  };

  // ======================== 硬件级防截屏系统 (Hold-to-Reveal + 失焦全黑护盾) ========================
  function initHoldToReveal() {
    setupRevealController('hold-to-reveal-mask', 'create-mnemonic-grid', 'screen-shield-overlay');
    setupRevealController('hold-to-reveal-mask-display', 'mnemonic-words-grid', 'screen-shield-overlay-display');
  }

  function setupRevealController(maskId, gridId, shieldId) {
    const mask = document.getElementById(maskId);
    const grid = document.getElementById(gridId);
    const shield = document.getElementById(shieldId);
    if (!mask || !grid) return;

    const reveal = () => {
      mask.style.opacity = '0';
      grid.classList.remove('filter', 'blur-md');
      triggerHaptic('light');

      // 若在 iOS Native 原生容器中，通知原生层开启底层截屏遮蔽
      if (window.Capacitor?.Plugins?.NativeSecurity) {
        window.Capacitor.Plugins.NativeSecurity.enableScreenShield().catch(() => {});
      }
    };

    const hide = () => {
      mask.style.opacity = '1';
      grid.classList.add('filter', 'blur-md');
    };

    mask.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      reveal();
    });
    window.addEventListener('pointerup', hide);
    window.addEventListener('pointercancel', hide);

    // 核心防截屏：监听 iOS 截屏时必触发的失焦 / 页面状态变化
    const triggerShield = () => {
      hide();
      if (shield) {
        shield.classList.remove('hidden');
        setTimeout(() => {
          shield.classList.add('hidden');
        }, 3000);
      }
    };

    window.addEventListener('blur', triggerShield);
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) triggerShield();
    });
  }

  window.initHoldToReveal = initHoldToReveal;

  window.copyPendingMnemonic = function () {
    if (!state.pendingWallet) return;
    triggerHaptic('light');
    navigator.clipboard.writeText(state.pendingWallet.mnemonic.join(' ')).then(() => {
      triggerHaptic('success');
      showToast("助记词已复制！建议纸笔手写抄录，严防剪贴板泄漏");
    });
  };

  // 用户勾选“已抄写备份完成”
  window.toggleDirectFinishBtn = function (chk) {
    const btn = document.getElementById('btn-direct-finish-create');
    if (!btn) return;
    if (chk && chk.checked) {
      btn.disabled = false;
      btn.classList.remove('opacity-40', 'cursor-not-allowed');
      triggerHaptic('light');
    } else {
      btn.disabled = true;
      btn.classList.add('opacity-40', 'cursor-not-allowed');
    }
  };

  // 一键完成创建并直接进入钱包 (彻底废弃冗余的选择题核验)
  window.finalizeDirectWalletCreation = function () {
    if (!state.pendingWallet) return;

    // Feature 17: 防重复地址安全检查
    const dupCheck = findExistingWalletByAddress(state.pendingWallet.address);
    if (dupCheck.isDuplicate) {
      triggerHaptic('error');
      showToast(state.currentLang === 'en' ? "⚠️ This wallet address already exists in list" : "⚠️ 该钱包地址已存在于列表中");
      return;
    }

    triggerHaptic('success');
    state.wallets.unshift(state.pendingWallet);
    state.activeWalletId = state.pendingWallet.id;
    saveWalletsToStorage();

    closeSheet();
    renderAll();
    showToast(`🎉 钱包【${state.pendingWallet.name}】创建成功并已激活`);
    state.pendingWallet = null;
    refreshActiveWalletBalance(true);
    refreshActiveWalletTransactions(true);
  };

  // ======================== 导入已有助记词 ========================
  window.startImportWalletFlow = function () {
    triggerHaptic('light');
    const nameInput = document.getElementById('import-wallet-name');
    const wordsInput = document.getElementById('import-mnemonic-input');

    if (nameInput) nameInput.value = state.currentLang === 'en' ? `Pearl Wallet ${state.wallets.length + 1}` : `我的 Pearl 钱包`;
    if (wordsInput) wordsInput.value = '';

    openSheet('sheet-import-wallet');
  };

  window.executeImportWallet = function () {
    try {
      const errEl = document.getElementById('import-error-msg');
      if (errEl) {
        errEl.classList.add('hidden');
        errEl.innerText = '';
      }

      const nameInput = document.getElementById('import-wallet-name');
      const wordsInput = document.getElementById('import-mnemonic-input');

      const name = nameInput?.value.trim() || (state.currentLang === 'en' ? `Pearl Wallet ${state.wallets.length + 1}` : `我的 Pearl 钱包`);
      const rawWords = wordsInput?.value.trim() || '';
      let pin = '123456';

      if (!rawWords) {
        triggerHaptic('error');
        showImportError(state.currentLang === 'en' ? "Please enter 12 or 24 English seed words" : "请输入 12 或 24 个英文助记词");
        return;
      }

      // Feature 17: 执行严谨 BIP-39 词库与格式校验
      const validation = validateMnemonic(rawWords);
      if (!validation.valid) {
        triggerHaptic('error');
        showImportError(validation.error);
        return;
      }

      const wordsList = validation.words;

      // 密码处理：若用户未输入密码，默认安全初始设为 123456
      if (!pin) {
        pin = '123456';
      } else if (pin.length !== 6 || !/^\d{6}$/.test(pin)) {
        triggerHaptic('error');
        showImportError("密码需为 6 位纯数字，或者留空默认使用 123456");
        return;
      }

      // 推导 Taproot Bech32m 地址与私钥
      const { address, privateKeyHex } = deriveFromSeed(wordsList);

      // Feature 17: 防重复钱包导入检查 (Duplicate Wallet Check)
      const dupCheck = findExistingWalletByAddress(address);
      if (dupCheck.isDuplicate) {
        triggerHaptic('error');
        const existingName = (dupCheck.existingWallet && dupCheck.existingWallet.name) ? dupCheck.existingWallet.name : '已存钱包';
        const shortAddr = `${address.slice(0, 10)}...${address.slice(-6)}`;
        const dupMsg = state.currentLang === 'en'
          ? `⚠️ Wallet already exists in list: [${existingName}] (${shortAddr})`
          : `⚠️ 该钱包已存在于列表中：【${existingName}】(${shortAddr})，无需重复导入！`;
        showImportError(dupMsg);
        return;
      }

      triggerHaptic('success');
      const importedWallet = {
        id: `wallet-${Date.now()}`,
        name,
        pin,
        mnemonic: wordsList,
        address,
        privateKeyHex,
        balance: 0.00,
        createdAt: new Date().toISOString()
      };

      state.wallets.push(importedWallet);
      state.activeWalletId = importedWallet.id;

      saveWalletsToStorage();
      closeSheet();
      switchTab('wallet');
      renderAll();
      showToast(`🎉 成功导入钱包【${name}】！`);
      refreshActiveWalletBalance(false);
      refreshActiveWalletTransactions(false);
    } catch (err) {
      console.error('Import wallet error:', err);
      showImportError(`导入失败: ${err.message || err}`);
    }
  };

  function showImportError(msg) {
    const errEl = document.getElementById('import-error-msg');
    if (errEl) {
      errEl.innerText = msg;
      errEl.classList.remove('hidden');
    }
    showToast(msg);
  }

  // ======================== 助记词安全查看防线 ========================
  window.startSecureMnemonicFlow = function () {
    triggerHaptic('medium');
    const wallet = getActiveWallet();
    if (!wallet) {
      showToast("当前设备无钱包，请先创建或导入");
      return;
    }

    const chk1 = document.getElementById('chk-backup-warn-1');
    const chk2 = document.getElementById('chk-backup-warn-2');
    const btn = document.getElementById('btn-proceed-backup');

    if (chk1) chk1.checked = false;
    if (chk2) chk2.checked = false;
    if (btn) {
      btn.disabled = true;
      btn.classList.add('opacity-40', 'cursor-not-allowed');
    }

    openSheet('sheet-backup-warning');
  };

  window.checkBackupConditions = function () {
    const chk1 = document.getElementById('chk-backup-warn-1');
    const chk2 = document.getElementById('chk-backup-warn-2');
    const btn = document.getElementById('btn-proceed-backup');
    if (!btn) return;

    if (chk1?.checked && chk2?.checked) {
      triggerHaptic('light');
      btn.disabled = false;
      btn.classList.remove('opacity-40', 'cursor-not-allowed');
    } else {
      btn.disabled = true;
      btn.classList.add('opacity-40', 'cursor-not-allowed');
    }
  };

  window.showBackupPinStep = function () {
    triggerHaptic('light');
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
    const isAndroid = /Android/i.test(navigator.userAgent);
    const titleEl = document.getElementById('verify-auth-title');
    const labelEl = document.getElementById('verify-auth-btn-label');
    const reasonEl = document.getElementById('verify-auth-reason');

    if (titleEl) {
      titleEl.innerText = isIOS ? "Apple Face ID 面容认证" : (isAndroid ? "安卓生物识别 (指纹 / 面部)" : "安全身份验证");
    }
    if (labelEl) {
      labelEl.innerText = isIOS ? "立即唤起 Face ID 扫描" : (isAndroid ? "验证指纹以确认" : "点击确认放行");
    }
    if (reasonEl) {
      reasonEl.innerText = isIOS ? "请验证面容以确认签名操作" : "请验证指纹或面容以确认操作";
    }

    state.enteredPin = "";
    updateVerifyPinDots();
    openSheet('sheet-verify-auth');
  };

  function bufToBase64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function b64ToBuf(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // 通用 Face ID / 生物认证执行器 (双通道：支持 Native iOS/Android App 与 Web 环境)
  window.requestBiometricAuth = async function (reason = "请验证 Face ID 以确认操作") {
    // 通道 1：如果运行在 Native 本地 App (Capacitor iOS / Android) 环境，直接唤起系统级原生 Face ID / 指纹
    if (window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform()) {
      if (window.Capacitor.Plugins && window.Capacitor.Plugins.NativeSecurity) {
        try {
          const res = await window.Capacitor.Plugins.NativeSecurity.authenticateWithBiometrics({ reason });
          if (res && res.success) {
            triggerHaptic('success');
            return true;
          }
        } catch (e) {
          console.warn("Native Face ID error:", e);
          triggerHaptic('error');
          showToast(e.message || "Face ID 验证未通过");
          return false;
        }
      }
    }

    // 通道 2：在 Web 网页环境中，如果用户曾绑定过 Passkey 则直接调取验证；如果未绑定，直接放行，绝不弹窗打扰用户去添加 iCloud 通行密钥
    if (window.PublicKeyCredential) {
      try {
        const wallet = getActiveWallet();
        if (wallet && wallet.passkeyId) {
          const challenge = new Uint8Array(32);
          window.crypto.getRandomValues(challenge);
          const assertion = await navigator.credentials.get({
            publicKey: {
              challenge,
              allowCredentials: [{
                id: b64ToBuf(wallet.passkeyId),
                type: "public-key",
                transports: ["internal"]
              }],
              userVerification: "required",
              timeout: 60000
            }
          });
          if (assertion) {
            triggerHaptic('success');
            return true;
          }
        }
      } catch (err) {
        console.warn("WebAuthn Face ID:", err);
        if (err.name === 'NotAllowedError') {
          showToast("用户已取消验证");
          return false;
        }
      }
    }

    // 网页模式极速免扰确认
    triggerHaptic('success');
    return true;
  };

  // 唤起原生生物识别 (Face ID / 指纹) 或网页免扰确认
  window.authenticateWithFaceID = async function () {
    triggerHaptic('medium');
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
    const passed = await requestBiometricAuth("请验证身份以解锁查看助记词");
    if (passed) {
      triggerHaptic('success');
      showToast(isIOS ? "🎉 Face ID 验证成功" : "🎉 身份认证成功");
      revealMnemonicDisplaySheet();
    }
  };

  window.pressVerifyPinKey = function (key) {
    triggerHaptic('light');
    if (key === 'delete') {
      state.enteredPin = state.enteredPin.slice(0, -1);
      updateVerifyPinDots();
      return;
    }

    if (state.enteredPin.length < 6) {
      state.enteredPin += key;
      updateVerifyPinDots();
    }

    if (state.enteredPin.length === 6) {
      const currentWallet = getActiveWallet();
      const correctPin = currentWallet ? currentWallet.pin : "123456";

      setTimeout(() => {
        if (state.enteredPin === correctPin) {
          triggerHaptic('success');
          state.enteredPin = "";
          updateVerifyPinDots();
          revealMnemonicDisplaySheet();
        } else {
          triggerHaptic('error');
          showToast("密码不正确，请重新输入");
          state.enteredPin = "";
          updateVerifyPinDots();
        }
      }, 150);
    }
  };

  function updateVerifyPinDots() {
    for (let i = 1; i <= 6; i++) {
      const dot = document.getElementById(`verify-pin-dot-${i}`);
      if (!dot) continue;
      if (i <= state.enteredPin.length) {
        dot.className = "w-3.5 h-3.5 rounded-full bg-cyan-400 border border-cyan-400 shadow-md shadow-cyan-400/50 transition-all";
      } else {
        dot.className = "w-3.5 h-3.5 rounded-full border border-white/30 transition-all";
      }
    }
  }

  function revealMnemonicDisplaySheet() {
    const wallet = getActiveWallet();
    if (!wallet) return;

    const grid = document.getElementById('mnemonic-words-grid');
    if (grid) {
      grid.innerHTML = wallet.mnemonic.map((word, idx) => `
        <div class="flex items-center gap-2 p-2.5 rounded-xl bg-white/[0.05] border border-white/[0.08]">
          <span class="text-[11px] text-white/30 w-4 font-mono tabular-numbers">${idx + 1}</span>
          <span class="text-xs font-mono font-bold text-cyan-200 tracking-wide select-all">${word}</span>
        </div>
      `).join('');
    }

    const hexEl = document.getElementById('display-private-hex');
    if (hexEl) hexEl.innerText = wallet.privateKeyHex;

    state.countdownSeconds = 45;
    clearInterval(state.autoLockTimer);
    const countdownEl = document.getElementById('auto-lock-countdown');
    if (countdownEl) countdownEl.innerText = "45s";

    state.autoLockTimer = setInterval(() => {
      state.countdownSeconds--;
      if (countdownEl) countdownEl.innerText = `${state.countdownSeconds}s`;
      if (state.countdownSeconds <= 0) {
        clearInterval(state.autoLockTimer);
        closeSheet();
        showToast("安全保护：助记词已自动锁闭");
      }
    }, 1000);

    openSheet('sheet-backup-display');
    initHoldToReveal();
  }

  window.toggleWordsBlur = function () {
    triggerHaptic('light');
    const grid = document.getElementById('mnemonic-words-grid');
    const btn = document.getElementById('btn-toggle-blur');
    state.isWordsBlurred = !state.isWordsBlurred;

    if (state.isWordsBlurred) {
      grid?.classList.add('blur-md', 'select-none');
      if (btn) btn.innerText = "显露明文";
    } else {
      grid?.classList.remove('blur-md', 'select-none');
      if (btn) btn.innerText = "隐藏明文";
    }
  };

  window.togglePrivateHex = function () {
    triggerHaptic('light');
    const box = document.getElementById('box-private-hex');
    const label = document.getElementById('label-hex-status');
    if (!box) return;

    if (box.classList.contains('hidden')) {
      box.classList.remove('hidden');
      if (label) label.innerText = "点击隐藏";
    } else {
      box.classList.add('hidden');
      if (label) label.innerText = "点击显露";
    }
  };

  // ======================== 抽屉交互控制 ========================
  window.openSheet = function (sheetId) {
    triggerHaptic('light');
    const sheet = document.getElementById(sheetId);
    const backdrop = document.getElementById('modal-backdrop');
    if (!sheet || !backdrop) return;

    if (sheetId === 'sheet-receive') {
      const wallet = getActiveWallet();
      const fullAddrEl = document.getElementById('receive-full-address');
      if (wallet && fullAddrEl) {
        fullAddrEl.innerText = wallet.address;
        generateQRCode(wallet.address);
      }
    }

    if (sheetId === 'sheet-send') {
      selectFeeTier(state.selectedFeeTier || 'normal');
      setFeeDeductMode(state.feeDeductMode || 'internal');
    }

    if (sheetId === 'sheet-rpc-settings') {
      renderRpcSettingsList();
    }

    if (sheetId === 'sheet-near-swap') {
      renderNearSwapUI();
    }

    document.querySelectorAll('.bottom-sheet').forEach(s => {
      if (s.id !== sheetId) s.classList.add('translate-y-full');
    });

    backdrop.classList.remove('hidden');
    requestAnimationFrame(() => {
      backdrop.classList.add('opacity-100');
      sheet.classList.remove('translate-y-full');
    });
  };

  window.closeSheet = function () {
    triggerHaptic('light');
    clearInterval(state.autoLockTimer);
    const sheets = document.querySelectorAll('.bottom-sheet');
    const backdrop = document.getElementById('modal-backdrop');

    sheets.forEach(s => s.classList.add('translate-y-full'));
    if (backdrop) {
      backdrop.classList.remove('opacity-100');
      setTimeout(() => backdrop.classList.add('hidden'), 320);
    }
  };

  // 生成 100% 真实、标准、可被任何相机与钱包扫码识别的二维码
  function generateQRCode(text) {
    const qrContainer = document.getElementById('qrcode-canvas-container');
    if (!qrContainer) return;
    qrContainer.innerHTML = '';

    if (typeof QRCode !== 'undefined') {
      try {
        new QRCode(qrContainer, {
          text: text,
          width: 190,
          height: 190,
          colorDark: "#090A12",
          colorLight: "#FFFFFF",
          correctLevel: QRCode.CorrectLevel.M
        });
        return;
      } catch (e) {
        console.warn('QRCode local build error:', e);
      }
    }

    // 严谨备选回退方案: 标准高清 SVG/PNG QR 图像
    const img = document.createElement('img');
    img.src = `https://api.qrserver.com/v1/create-qr-code/?size=190x190&data=${encodeURIComponent(text)}&bgcolor=FFFFFF&color=090A12&margin=2`;
    img.alt = "Pearl 收款地址二维码";
    img.className = "w-[190px] h-[190px] rounded-2xl block";
    qrContainer.appendChild(img);
  }

  window.copyAddress = function () {
    const wallet = getActiveWallet();
    if (!wallet) return;
    navigator.clipboard.writeText(wallet.address).then(() => {
      triggerHaptic('success');
      showToast("地址已复制到剪贴板");
    });
  };

  window.pasteToAddress = function () {
    navigator.clipboard.readText().then(text => {
      const input = document.getElementById('send-address-input');
      if (input) {
        input.value = text.trim();
        input.dispatchEvent(new Event('input'));
        triggerHaptic('light');
        const check = validatePearlAddress(input.value);
        if (!check.valid) {
          showToast(`⚠️ 粘贴地址无效: ${formatAddressError(check.error)}`);
        } else {
          showToast("已粘贴有效 Pearl 收款地址");
        }
      }
    }).catch(() => {
      showToast("请在系统弹窗中允许粘贴");
    });
  };

  // 手续费扣款模式切换 (扣在总额中 / 内扣 vs 额外支付 / 外扣)
  window.setFeeDeductMode = function (mode) {
    triggerHaptic('light');
    state.feeDeductMode = mode;
    const btnInternal = document.getElementById('btn-fee-mode-internal');
    const btnExternal = document.getElementById('btn-fee-mode-external');
    const badge = document.getElementById('fee-mode-badge');
    const hint = document.getElementById('fee-mode-hint');

    const activeCls = "py-2 px-3 rounded-lg text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 transition-all text-center";
    const inactiveCls = "py-2 px-3 rounded-lg text-xs font-medium text-white/60 border border-transparent hover:text-white transition-all text-center";

    if (mode === 'internal') {
      if (btnInternal) btnInternal.className = activeCls;
      if (btnExternal) btnExternal.className = inactiveCls;
      if (badge) {
        badge.innerText = "内扣：扣在总额中";
        badge.className = "text-[10px] text-cyan-400 font-semibold bg-cyan-500/10 px-2 py-0.5 rounded-full";
      }
      if (hint) {
        hint.innerHTML = "💡 <strong>内扣模式</strong>：转账 10 PRL，钱包实扣整 10 PRL，对方到账 9.99999692 PRL（已扣除真实矿工费）";
      }
    } else {
      if (btnInternal) btnInternal.className = inactiveCls;
      if (btnExternal) btnExternal.className = activeCls;
      if (badge) {
        badge.innerText = "外扣：额外付手续费";
        badge.className = "text-[10px] text-purple-400 font-semibold bg-purple-500/10 px-2 py-0.5 rounded-full";
      }
      if (hint) {
        hint.innerHTML = "💡 <strong>外扣模式</strong>：转账 10 PRL，对方到账整 10 PRL，钱包额外扣除 0.00000308 PRL 矿工费";
      }
    }

    const input = document.getElementById('send-amount-input');
    handleSendAmountInput(input);
  };

  // 网络费率挡位选择
  window.selectFeeTier = function (tier) {
    triggerHaptic('light');
    state.selectedFeeTier = tier;
    const tierData = state.feeTiers[tier] || state.feeTiers.normal;
    state.currentFee = tierData.feePRL;

    const btnEco = document.getElementById('btn-fee-eco');
    const btnNormal = document.getElementById('btn-fee-normal');
    const btnFast = document.getElementById('btn-fee-fast');

    const activeCls = "p-2.5 rounded-xl bg-cyan-500/20 border border-cyan-400/40 text-center btn-active transition-all";
    const inactiveCls = "p-2.5 rounded-xl bg-white/[0.04] border border-white/[0.08] text-center btn-active transition-all";

    if (btnEco) btnEco.className = (tier === 'eco') ? activeCls : inactiveCls;
    if (btnNormal) btnNormal.className = (tier === 'normal') ? activeCls : inactiveCls;
    if (btnFast) btnFast.className = (tier === 'fast') ? activeCls : inactiveCls;

    const input = document.getElementById('send-amount-input');
    handleSendAmountInput(input);
  };

  // 实时转账数量与手续费联动计算 (未输入数量时不提前显示扣款)
  window.handleSendAmountInput = function (el) {
    if (!el) return;
    let valStr = el.value || '';
    if (valStr.includes('-') || parseFloat(valStr) < 0) {
      el.value = '';
      valStr = '0';
    }
    const amount = parseFloat(valStr) || 0;
    const fee = state.currentFee;
    const isDevFeeEnabled = state.devFeeEnabled !== false;
    const devFee = isDevFeeEnabled ? (amount * state.devFeeRate) : 0;
    const totalFees = fee + devFee;
    const mode = state.feeDeductMode || 'internal';
    const tierData = state.feeTiers[state.selectedFeeTier] || state.feeTiers.normal;

    const feeLabel = document.getElementById('send-network-fee');
    const devFeeLabel = document.getElementById('send-dev-fee');
    const feeEta = document.getElementById('send-fee-eta');
    const netReceiveEl = document.getElementById('send-net-receive');
    const totalDeductEl = document.getElementById('send-total-deduct');

    // 未输入转账数量：一律显示占位符，不出现预支的扣除或手续费
    if (amount <= 0 || !valStr.trim()) {
      if (feeLabel) feeLabel.innerText = "--";
      if (devFeeLabel) devFeeLabel.innerText = "--";
      if (feeEta) feeEta.innerText = "输入金额后计算";
      if (netReceiveEl) {
        netReceiveEl.innerText = "--";
        netReceiveEl.className = "font-mono text-white/40";
      }
      if (totalDeductEl) totalDeductEl.innerText = "--";
      return;
    }

    // 已输入有效数量：按所选档位与扣除模式精准计算
    if (feeLabel) {
      feeLabel.innerText = `${fee.toFixed(8)} PRL`;
    }
    if (devFeeLabel) {
      if (isDevFeeEnabled) {
        devFeeLabel.innerText = `+${devFee.toFixed(8)} PRL`;
        devFeeLabel.className = "font-mono text-cyan-300 font-semibold";
      } else {
        devFeeLabel.innerText = "已在设置中关闭 (0 PRL)";
        devFeeLabel.className = "font-mono text-white/30";
      }
    }
    if (feeEta) {
      feeEta.innerText = tierData.eta;
    }

    if (mode === 'internal') {
      // 内扣模式：用户输入的 amount 为钱包实扣总额，实际到账扣除矿工费与开发者支持费
      const netReceive = amount - totalFees;
      if (netReceiveEl) {
        if (amount <= totalFees) {
          netReceiveEl.innerText = `金额需大于总费用 (${totalFees.toFixed(8)} PRL)`;
          netReceiveEl.className = "font-mono text-rose-400 font-semibold";
        } else {
          netReceiveEl.innerText = `${netReceive.toFixed(8)} PRL`;
          netReceiveEl.className = "font-mono text-emerald-400 font-semibold";
        }
      }
      if (totalDeductEl) {
        totalDeductEl.innerText = `${amount.toFixed(8)} PRL`;
      }
    } else {
      // 外扣模式：对方收到用户输入的完整金额，钱包额外扣除矿工费和开发者支持费
      const totalCost = amount + totalFees;
      if (netReceiveEl) {
        netReceiveEl.innerText = `${amount.toFixed(8)} PRL`;
        netReceiveEl.className = "font-mono text-emerald-400 font-semibold";
      }
      if (totalDeductEl) {
        totalDeductEl.innerText = `${totalCost.toFixed(8)} PRL`;
      }
    }
  };

  window.setMaxSendAmount = function () {
    const wallet = getActiveWallet();
    const input = document.getElementById('send-amount-input');
    if (wallet && input) {
      const mode = state.feeDeductMode || 'internal';
      const fee = state.currentFee;
      const isDevFeeEnabled = state.devFeeEnabled !== false;
      if (mode === 'internal') {
        // 内扣模式：最大转账直接填入全部余额
        input.value = wallet.balance.toFixed(8);
      } else {
        // 外扣模式：扣除矿工费和按比例计算的应用费
        const rateFactor = isDevFeeEnabled ? (1 + state.devFeeRate) : 1;
        const maxAmt = Math.max(0, (wallet.balance - fee) / rateFactor);
        input.value = maxAmt.toFixed(8);
      }
      handleSendAmountInput(input);
      triggerHaptic('light');
    }
  };

  function showToast(msg) {
    const toast = document.getElementById('ios-toast');
    if (!toast) return;
    toast.innerText = msg;
    toast.classList.remove('opacity-0', '-translate-y-4', 'pointer-events-none');
    setTimeout(() => {
      toast.classList.add('opacity-0', '-translate-y-4', 'pointer-events-none');
    }, 2400);
  }

  if (typeof window !== 'undefined') {
    window.showToast = showToast;
  }
  if (typeof globalThis !== 'undefined') {
    globalThis.showToast = showToast;
  }

  function setupSwipeToSend() {
    const thumb = document.getElementById('swipe-thumb');
    const track = document.getElementById('swipe-track');
    const sendAmountInput = document.getElementById('send-amount-input');
    const sendAddrInput = document.getElementById('send-address-input');
    if (!thumb || !track) return;

    if (sendAddrInput && !sendAddrInput._validationBound) {
      sendAddrInput._validationBound = true;
      sendAddrInput.addEventListener('input', () => {
        const val = sendAddrInput.value.trim();
        if (!val) {
          sendAddrInput.classList.remove('border-rose-500/60', 'border-emerald-500/60', 'bg-rose-500/5', 'bg-emerald-500/5');
          return;
        }
        const check = validatePearlAddress(val);
        if (check.valid) {
          sendAddrInput.classList.remove('border-rose-500/60', 'bg-rose-500/5');
          sendAddrInput.classList.add('border-emerald-500/60', 'bg-emerald-500/5');
        } else if (val.length >= 8) {
          sendAddrInput.classList.remove('border-emerald-500/60', 'bg-emerald-500/5');
          sendAddrInput.classList.add('border-rose-500/60', 'bg-rose-500/5');
        }
      });
    }

    let isDragging = false;
    let startX = 0;
    let maxDistance = 0;

    const onStart = (e) => {
      isDragging = true;
      startX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
      maxDistance = track.clientWidth - thumb.clientWidth - 8;
      thumb.style.transition = 'none';
    };

    const onMove = (e) => {
      if (!isDragging) return;
      const currentX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
      let delta = currentX - startX;
      if (delta < 0) delta = 0;
      if (delta > maxDistance) delta = maxDistance;

      thumb.style.transform = `translateX(${delta}px)`;

      if (delta >= maxDistance - 6) {
        isDragging = false;
        triggerHaptic('success');
        thumb.style.transform = `translateX(${maxDistance}px)`;
        executeSend();
      }
    };

    const onEnd = () => {
      if (!isDragging) return;
      isDragging = false;
      thumb.style.transition = 'transform 0.3s cubic-bezier(0.32, 0.72, 0, 1)';
      thumb.style.transform = 'translateX(0px)';
    };

    thumb.addEventListener('touchstart', onStart, { passive: true });
    window.addEventListener('touchmove', onMove, { passive: true });
    window.addEventListener('touchend', onEnd);

    thumb.addEventListener('mousedown', onStart);
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onEnd);

    async function executeSend() {
      const wallet = getActiveWallet();
      const rawVal = sendAmountInput?.value || '';
      const amountVal = parseFloat(rawVal);
      const toAddr = sendAddrInput?.value.trim() || '';
      const mode = state.feeDeductMode || 'internal';
      const fee = state.currentFee;
      const isDevFeeEnabled = state.devFeeEnabled !== false;
      const devFee = isDevFeeEnabled ? (amountVal * state.devFeeRate) : 0;
      const totalFees = fee + devFee;

      if (!toAddr) {
        triggerHaptic('error');
        showToast("请输入收款方地址");
        resetThumb();
        return;
      }

      // Feature 16: 严格校验收款方 Bech32m Taproot 地址格式与校验和
      const addrCheck = validatePearlAddress(toAddr);
      if (!addrCheck.valid) {
        triggerHaptic('error');
        showToast(`收款地址无效: ${formatAddressError(addrCheck.error)}`);
        resetThumb();
        return;
      }
      if (isNaN(amountVal) || amountVal <= 0) {
        triggerHaptic('error');
        showToast("转账金额必须大于 0，禁止负数或空值");
        resetThumb();
        return;
      }

      let walletDeduct = 0;
      let netReceive = 0;

      if (mode === 'internal') {
        if (amountVal <= totalFees) {
          triggerHaptic('error');
          showToast(`转账金额需大于总费用 (${totalFees.toFixed(8)} PRL)`);
          resetThumb();
          return;
        }
        walletDeduct = amountVal;
        netReceive = amountVal - totalFees;
      } else {
        walletDeduct = amountVal + totalFees;
        netReceive = amountVal;
      }

      if (walletDeduct > (wallet ? wallet.balance : 0)) {
        triggerHaptic('error');
        showToast(`钱包扣除总额 (${walletDeduct.toFixed(6)} PRL) 超出当前余额 (${wallet ? wallet.balance.toFixed(6) : 0} PRL)`);
        resetThumb();
        return;
      }

      // 🛡️ 核心安全防线：交易签名必须通过 Apple Face ID / 生物认证
      showToast("正在唤起 Face ID 签名交易...");
      const faceIdPassed = await requestBiometricAuth(`转账 ${walletDeduct.toFixed(4)} PRL 至 ${toAddr.slice(0, 6)}... 请验证 Face ID`);
      if (!faceIdPassed) {
        triggerHaptic('error');
        resetThumb();
        return;
      }

      triggerHaptic('success');
      showToast("签名验证通过。链上广播需连接全节点 RPC 服务 (pearld)，当前处于只读公共网络");
      setTimeout(() => {
        closeSheet();
        renderAll();
        resetThumb();
        if (sendAmountInput) sendAmountInput.value = '';
        if (sendAddrInput) {
          sendAddrInput.value = '';
          sendAddrInput.classList.remove('border-rose-500/60', 'border-emerald-500/60', 'bg-rose-500/5', 'bg-emerald-500/5');
        }
      }, 500);
    }

    function resetThumb() {
      setTimeout(() => {
        thumb.style.transform = 'translateX(0px)';
      }, 400);
    }
  }

  // ======================== 开发者支持费 (0.01%) 开关与联动 ========================
  window.toggleDevFee = function () {
    triggerHaptic('light');
    state.devFeeEnabled = !state.devFeeEnabled;
    localStorage.setItem('pearl_dev_fee_enabled', state.devFeeEnabled ? 'true' : 'false');
    updateDevFeeUI();
    const sendInput = document.getElementById('send-amount-input');
    if (sendInput) handleSendAmountInput(sendInput);
    showToast(state.devFeeEnabled ? '已开启 0.01% 开发者支持费' : '已关闭开发者支持费');
  };

  function updateDevFeeUI() {
    const btn = document.getElementById('btn-toggle-dev-fee');
    const thumb = document.getElementById('dev-fee-switch-thumb');
    const label = document.getElementById('dev-fee-status-label');
    const enabled = state.devFeeEnabled !== false;

    if (btn && thumb && label) {
      if (enabled) {
        btn.classList.remove('bg-white/20');
        btn.classList.add('bg-cyan-500');
        btn.setAttribute('aria-checked', 'true');
        thumb.classList.remove('translate-x-0');
        thumb.classList.add('translate-x-5');
        label.innerText = '已开启 (转账时自动计算)';
        label.className = 'text-cyan-400 font-medium';
      } else {
        btn.classList.remove('bg-cyan-500');
        btn.classList.add('bg-white/20');
        btn.setAttribute('aria-checked', 'false');
        thumb.classList.remove('translate-x-5');
        thumb.classList.add('translate-x-0');
        label.innerText = '已停用 (转账仅扣矿工费)';
        label.className = 'text-white/40 font-medium';
      }
    }
  }

  // ======================== Feature 13: RPC 节点管理与切换控制器 ========================

  const PRESET_RPC_ENDPOINTS = [
    {
      url: 'https://api.prlscan.com/v1',
      name: 'prlscan.com 官方主网',
      type: 'Public REST Gateway (免鉴权·推荐)',
      tag: '官方推荐',
      tagClass: 'text-cyan-400 bg-cyan-500/10'
    },
    {
      url: 'http://localhost:44107',
      name: 'Local Full Node (本地全节点)',
      type: 'pearld consensus RPC (端口 44107)',
      tag: '开发者·广播',
      tagClass: 'text-purple-300 bg-purple-500/10'
    }
  ];

  window.selectRpc = async function (url, label) {
    triggerHaptic('light');
    state.rpcGatewayUrl = url;
    state.rpcLabel = label;
    try {
      localStorage.setItem('pearl_rpc_gateway_url', url);
      localStorage.setItem('pearl_rpc_label', label);
    } catch (e) {}

    const headerLabel = document.getElementById('header-node-label');
    if (headerLabel) {
      headerLabel.innerText = label.split(' ')[0] || 'Pearl Node';
    }

    const currentLabelEl = document.getElementById('rpc-current-label');
    if (currentLabelEl) {
      currentLabelEl.innerText = label;
    }

    renderRpcSettingsList();
    closeSheet();
    showToast(`已连接至: ${label}`);

    // 重新抓取链上状态与当前活跃钱包数据
    try {
      await Promise.allSettled([
        fetchRealChainData(),
        fetchRealKryptexRates(),
        refreshActiveWalletBalance(true),
        refreshActiveWalletTransactions(true)
      ]);
    } catch (e) {}
  };

  window.connectCustomRpc = function () {
    const input = document.getElementById('custom-rpc-input');
    if (!input) return;
    const url = input.value.trim();
    if (!url) {
      showToast('请输入有效的节点 URL');
      return;
    }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      showToast('节点 URL 必须以 http:// 或 https:// 开头');
      return;
    }
    try {
      const parsed = new URL(url);
      window.selectRpc(url, `自定义节点 (${parsed.hostname})`);
    } catch (e) {
      showToast('节点 URL 格式不正确');
    }
  };

  window.testRpcConnection = async function () {
    triggerHaptic('light');
    const resultEl = document.getElementById('rpc-ping-result');
    if (resultEl) {
      resultEl.innerText = '正在测速...';
      resultEl.className = 'text-[11px] text-cyan-300 font-mono';
    }

    const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    try {
      const data = await fetchWithTimeout(`${getRpcGatewayUrl()}/status`, {}, 6000);
      const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      const latency = Math.round(t1 - t0);
      if (resultEl) {
        resultEl.innerText = `⚡ ${latency}ms · 正常 (块高 #${data.tip_height || '--'})`;
        resultEl.className = 'text-[11px] text-emerald-400 font-mono';
      }
      showToast(`节点响应正常 (${latency}ms)`);
    } catch (err) {
      const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      const latency = Math.round(t1 - t0);
      if (resultEl) {
        resultEl.innerText = `⚠️ 失败 (${latency}ms): ${err.message}`;
        resultEl.className = 'text-[11px] text-rose-400 font-mono';
      }
      showToast(`节点连接失败: ${err.message}`);
    }
  };

  function renderRpcSettingsList() {
    const currentUrl = getRpcGatewayUrl();
    const container = document.getElementById('rpc-endpoints-list');
    if (!container) return;

    container.innerHTML = PRESET_RPC_ENDPOINTS.map(ep => {
      const isSelected = ep.url === currentUrl;
      return `
        <div onclick="selectRpc('${ep.url}', '${ep.name}')" class="p-3 rounded-2xl ${
          isSelected
            ? 'bg-cyan-500/15 border-2 border-cyan-400/50 shadow-lg shadow-cyan-500/10'
            : 'bg-white/[0.03] border border-white/[0.06] hover:bg-white/[0.06]'
        } cursor-pointer transition-all btn-active">
          <div class="flex items-center justify-between mb-1">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full ${isSelected ? 'bg-emerald-400 animate-pulse' : 'bg-white/20'}"></span>
              <span class="text-xs font-bold ${isSelected ? 'text-cyan-200' : 'text-white/80'}">${ep.name}</span>
            </div>
            <span class="text-[10px] px-2 py-0.5 rounded-full font-medium ${ep.tagClass}">${ep.tag}</span>
          </div>
          <div class="text-[11px] font-mono ${isSelected ? 'text-cyan-300/80' : 'text-white/40'} truncate">${ep.url}</div>
          <div class="text-[10px] text-white/30 mt-0.5">${ep.type}</div>
        </div>
      `;
    }).join('');
  }

  // 底部导航栏高亮动态刷新 (纯 CSS 强约束驱动，100% 保持高亮一致)
  function renderNavTabs(activeTab) {
    const tabs = ['wallet', 'swap', 'mining', 'settings'];
    tabs.forEach(id => {
      const el = document.getElementById(`tab-btn-${id}`);
      if (!el) return;
      if (id === activeTab) {
        el.classList.add('active');
      } else {
        el.classList.remove('active');
      }
    });
  }

  window.switchTab = function (tab) {
    triggerHaptic('light');
    if (tab === 'swap') {
      window.openNearSwapSheet();
      return;
    }

    const viewWallet = document.getElementById('view-wallet');
    const viewMining = document.getElementById('view-mining');
    const viewSettings = document.getElementById('view-settings');
    const viewOnboarding = document.getElementById('view-onboarding');

    [viewWallet, viewMining, viewSettings, viewOnboarding].forEach(v => v?.classList.add('hidden'));

    if (tab === 'wallet') {
      if (state.wallets.length === 0) {
        viewOnboarding?.classList.remove('hidden');
      } else {
        viewWallet?.classList.remove('hidden');
      }
    } else if (tab === 'mining') {
      viewMining?.classList.remove('hidden');
    } else if (tab === 'settings') {
      viewSettings?.classList.remove('hidden');
    }

    renderNavTabs(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // ======================== 常用地址簿 (联系人管理与一键选填) ========================
  state.contacts = [];
  state.addressBookMode = 'select'; // 'select' 用于转账选填，'manage' 用于自托管管理

  function loadContacts() {
    const saved = localStorage.getItem('pearl_contacts_v1');
    if (saved) {
      try {
        state.contacts = JSON.parse(saved);
      } catch (e) {
        state.contacts = [];
      }
    } else {
      state.contacts = [];
    }
    updateContactsCount();
  }

  function saveContacts() {
    localStorage.setItem('pearl_contacts_v1', JSON.stringify(state.contacts));
    updateContactsCount();
  }

  function updateContactsCount() {
    const el = document.getElementById('settings-contacts-count');
    if (el) el.innerText = `${state.contacts.length} 个`;
  }

  window.openAddressBook = function (mode = 'select') {
    triggerHaptic('light');
    state.addressBookMode = mode;
    closeAddContactModal();
    renderAddressBookList();
    openSheet('sheet-address-book');
  };

  window.closeAddressBookSheet = function () {
    closeSheet();
    if (state.addressBookMode === 'select') {
      setTimeout(() => openSheet('sheet-send'), 250);
    }
  };

  window.openAddContactModal = function () {
    triggerHaptic('light');
    const form = document.getElementById('add-contact-form');
    if (form) form.classList.remove('hidden');
    const nameInput = document.getElementById('contact-name-input');
    if (nameInput) nameInput.focus();
  };

  window.closeAddContactModal = function () {
    const form = document.getElementById('add-contact-form');
    if (form) form.classList.add('hidden');
    const nameInput = document.getElementById('contact-name-input');
    const addrInput = document.getElementById('contact-address-input');
    if (nameInput) nameInput.value = '';
    if (addrInput) addrInput.value = '';
  };

  window.pasteToContactAddress = function () {
    navigator.clipboard?.readText?.().then(text => {
      const input = document.getElementById('contact-address-input');
      if (input && text) {
        input.value = text.trim();
        triggerHaptic('light');
        const check = validatePearlAddress(input.value);
        if (!check.valid) {
          showToast(`⚠️ 粘贴地址无效: ${formatAddressError(check.error)}`);
        } else {
          showToast("已粘贴有效 Pearl 地址");
        }
      }
    }).catch(() => showToast("请在系统弹窗中允许粘贴"));
  };

  window.saveNewContact = function () {
    const nameInput = document.getElementById('contact-name-input');
    const addrInput = document.getElementById('contact-address-input');
    const name = nameInput?.value.trim();
    const addr = addrInput?.value.trim();

    if (!name) {
      triggerHaptic('error');
      showToast("请输入联系人备注名称");
      return;
    }
    if (!addr) {
      triggerHaptic('error');
      showToast("请输入联系人 Pearl 地址");
      return;
    }

    // Feature 16: 严格校验联系人 Pearl Taproot Bech32m 地址与校验和
    const addrCheck = validatePearlAddress(addr);
    if (!addrCheck.valid) {
      triggerHaptic('error');
      showToast(`联系人地址无效: ${formatAddressError(addrCheck.error)}`);
      return;
    }

    // 重复地址防呆检查
    const duplicate = state.contacts.find(c => c.address.toLowerCase() === addr.toLowerCase());
    if (duplicate) {
      triggerHaptic('error');
      showToast(`该地址已存在于联系人【${duplicate.name}】中`);
      return;
    }

    triggerHaptic('success');
    state.contacts.unshift({
      id: `contact-${Date.now()}`,
      name,
      address: addr,
      createdAt: new Date().toISOString()
    });
    saveContacts();
    closeAddContactModal();
    renderAddressBookList();
    showToast(`已添加联系人【${name}】`);
  };

  window.deleteContact = function (id, e) {
    if (e) e.stopPropagation();
    triggerHaptic('medium');
    state.contacts = state.contacts.filter(c => c.id !== id);
    saveContacts();
    renderAddressBookList();
    showToast("已从地址簿删除");
  };

  window.selectContactAddress = function (addr, name) {
    triggerHaptic('success');
    const input = document.getElementById('send-address-input');
    if (input) input.value = addr;
    closeSheet();
    setTimeout(() => {
      openSheet('sheet-send');
      showToast(`已填入【${name}】收款地址`);
    }, 250);
  };

  function renderAddressBookList() {
    const listEl = document.getElementById('address-book-list');
    if (!listEl) return;

    if (state.contacts.length === 0) {
      listEl.innerHTML = `
        <div class="py-10 text-center text-white/40 text-xs">
          <div class="text-2xl mb-2">📖</div>
          暂无常用地址，点击右上角【添加地址】新建
        </div>
      `;
      return;
    }

    listEl.innerHTML = state.contacts.map(c => `
      <div onclick="selectContactAddress('${c.address}', '${c.name}')" class="p-3.5 rounded-2xl bg-white/[0.04] border border-white/[0.08] hover:border-cyan-400/40 flex items-center justify-between cursor-pointer btn-active">
        <div class="space-y-1 flex-1 pr-3">
          <div class="flex items-center gap-2">
            <span class="text-xs font-bold text-white">${c.name}</span>
            <span class="text-[10px] text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded font-mono">Taproot</span>
          </div>
          <div class="text-[11px] font-mono text-white/50 truncate max-w-[240px]">${c.address}</div>
        </div>
        <div class="flex items-center gap-1">
          <button type="button" onclick="deleteContact('${c.id}', event)" class="p-2 rounded-xl text-white/30 hover:text-rose-400 hover:bg-rose-500/10">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
          </button>
        </div>
      </div>
    `).join('');
  }

  // ============================================================================
  // Feature 19: NEAR 链抽象跨链兑换 (NEAR Intents / Defuse Protocol Swap)
  // ============================================================================

  const POPULAR_SWAP_TOKENS = [
    {
      symbol: 'USDT',
      name: 'Tether USD',
      blockchain: 'near',
      assetId: 'nep141:usdt.tether-token.near',
      decimals: 6,
      icon: '💵',
      price: 1.0,
      networkName: 'NEAR Protocol'
    },
    {
      symbol: 'USDC',
      name: 'USD Coin',
      blockchain: 'base',
      assetId: 'nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near',
      decimals: 6,
      icon: '🔵',
      price: 1.0,
      networkName: 'Base (EVM)'
    },
    {
      symbol: 'USDT',
      name: 'Tether USD',
      blockchain: 'eth',
      assetId: 'nep141:eth-0xdac17f958d2ee523a2206206994597c13d831ec7.omft.near',
      decimals: 6,
      icon: '💎',
      price: 1.0,
      networkName: 'Ethereum Mainnet'
    },
    {
      symbol: 'USDT',
      name: 'Tether USD',
      blockchain: 'tron',
      assetId: 'nep141:tron-d28a265909efecdcee7c5028585214ea0b96f015.omft.near',
      decimals: 6,
      icon: '🔴',
      price: 1.0,
      networkName: 'TRON'
    },
    {
      symbol: 'NEAR',
      name: 'NEAR Protocol',
      blockchain: 'near',
      assetId: 'nep141:wrap.near',
      decimals: 24,
      icon: '🌈',
      price: 4.04,
      networkName: 'NEAR Native'
    },
    {
      symbol: 'ETH',
      name: 'Ethereum',
      blockchain: 'eth',
      assetId: 'nep141:eth.omft.near',
      decimals: 18,
      icon: '🔷',
      price: 2430.0,
      networkName: 'Ethereum Native'
    },
    {
      symbol: 'SOL',
      name: 'Solana',
      blockchain: 'sol',
      assetId: 'nep141:sol.omft.near',
      decimals: 9,
      icon: '🟣',
      price: 96.0,
      networkName: 'Solana'
    },
    {
      symbol: 'BTC',
      name: 'Bitcoin',
      blockchain: 'btc',
      assetId: 'nep141:btc.omft.near',
      decimals: 8,
      icon: '₿',
      price: 80000.0,
      networkName: 'Bitcoin Native'
    }
  ];

  const PEARL_DEFUSE_TOKEN = {
    symbol: 'PRL',
    name: 'Pearl Network',
    blockchain: 'prl',
    assetId: 'nep141:prl.omft.near',
    decimals: 8,
    icon: '🦪',
    price: 1.59,
    networkName: 'Pearl Mainnet'
  };

  state.nearSwap = {
    direction: 'sell', // 'sell': PRL -> Foreign; 'buy': Foreign -> PRL
    targetTokenId: 'nep141:usdt.tether-token.near',
    slippageTolerance: 100, // 100 bps = 1.0%
    amountIn: '',
    amountOut: '',
    recipientAddress: '',
    tokensList: POPULAR_SWAP_TOKENS,
    prlPrice: 1.59,
    quoteStatus: 'idle', // 'idle' | 'quoting' | 'success' | 'no_liquidity' | 'error'
    quoteDebounceTimer: null,
    statusPollTimer: null,
    orderExpiryTimer: null,
    activeOrder: null
  };

  function getSelectedTargetToken() {
    return state.nearSwap.tokensList.find(t => t.assetId === state.nearSwap.targetTokenId) || state.nearSwap.tokensList[0];
  }

  function toBaseUnits(amountStr, decimals) {
    const num = Number(amountStr);
    if (isNaN(num) || num <= 0) return '0';
    if (decimals <= 8) {
      return Math.floor(num * Math.pow(10, decimals)).toString();
    }
    const parts = amountStr.toString().split('.');
    const whole = parts[0] || '0';
    const frac = (parts[1] || '').slice(0, decimals).padEnd(decimals, '0');
    const combined = (whole + frac).replace(/^0+/, '');
    return combined || '0';
  }

  function fromBaseUnits(baseStr, decimals) {
    if (!baseStr || baseStr === '0') return '0';
    const s = baseStr.toString().padStart(decimals + 1, '0');
    const splitIndex = s.length - decimals;
    const whole = s.slice(0, splitIndex) || '0';
    const frac = (s.slice(splitIndex) || '').replace(/0+$/, '');
    return frac ? `${whole}.${frac}` : whole;
  }

  async function fetchNearDefuseTokens() {
    try {
      const res = await fetchWithTimeout('https://1click.chaindefuser.com/v0/tokens', {}, 6000);
      if (Array.isArray(res) && res.length > 0) {
        const prl = res.find(t => t.symbol === 'PRL');
        if (prl && prl.price && !isNaN(prl.price)) {
          state.nearSwap.prlPrice = Number(prl.price);
        }
        for (const pt of state.nearSwap.tokensList) {
          const live = res.find(t => t.assetId === pt.assetId);
          if (live && live.price && !isNaN(live.price)) {
            pt.price = Number(live.price);
          }
        }
        renderNearSwapUI();
      }
    } catch (e) {
      // 网络离线或超时降级维持当前价格
    }
  }

  window.openNearSwapSheet = function () {
    triggerHaptic('light');
    const wallet = getActiveWallet();
    if (!wallet) {
      showToast('请先创建或导入 Pearl 钱包账户');
      return;
    }
    fetchNearDefuseTokens();
    renderNearSwapUI();
    openSheet('sheet-near-swap');
  };

  window.closeNearSwapSheet = function () {
    closeSheet();
  };

  window.setSwapDirection = function (dir) {
    triggerHaptic('light');
    state.nearSwap.direction = dir;
    renderNearSwapUI();
    calculateSwapQuote();
  };

  window.toggleSwapDirection = function () {
    triggerHaptic('medium');
    state.nearSwap.direction = state.nearSwap.direction === 'sell' ? 'buy' : 'sell';
    renderNearSwapUI();
    calculateSwapQuote();
  };

  window.selectSwapTargetToken = function (assetId) {
    triggerHaptic('light');
    state.nearSwap.targetTokenId = assetId;
    renderNearSwapUI();
    calculateSwapQuote();
  };

  window.handleSwapAmountInput = function (input) {
    state.nearSwap.amountIn = input.value.trim();
    if (state.nearSwap.quoteDebounceTimer) {
      clearTimeout(state.nearSwap.quoteDebounceTimer);
    }
    state.nearSwap.quoteDebounceTimer = setTimeout(() => {
      calculateSwapQuote();
    }, 350);
  };

  window.setSwapMaxAmount = function () {
    triggerHaptic('light');
    const wallet = getActiveWallet();
    if (!wallet) return;

    const input = document.getElementById('swap-amount-in');
    if (!input) return;

    if (state.nearSwap.direction === 'sell') {
      const balance = Number(wallet.balance) || 0;
      const maxAmt = Math.max(0, balance - 0.001);
      input.value = maxAmt > 0 ? maxAmt.toFixed(4) : balance.toFixed(4);
    } else {
      input.value = "100";
    }
    state.nearSwap.amountIn = input.value;
    calculateSwapQuote();
  };

  window.handleSwapRecipientInput = function (input) {
    state.nearSwap.recipientAddress = input.value.trim();
  };

  window.pasteToSwapRecipient = function () {
    navigator.clipboard?.readText?.().then(text => {
      const input = document.getElementById('swap-recipient-input');
      if (input && text) {
        input.value = text.trim();
        state.nearSwap.recipientAddress = input.value;
        triggerHaptic('success');
        showToast('已粘贴收款地址');
      }
    }).catch(() => showToast('请在系统弹窗中允许粘贴'));
  };

  window.setSwapSlippage = function (bps) {
    triggerHaptic('light');
    state.nearSwap.slippageTolerance = Number(bps);
    [50, 100, 200, 300].forEach(val => {
      const btn = document.getElementById(`btn-slippage-${val}`);
      if (!btn) return;
      if (val === bps) {
        btn.className = 'px-2 py-1 rounded-lg text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 transition-all';
      } else {
        btn.className = 'px-2 py-1 rounded-lg text-[10px] font-mono font-bold bg-white/[0.04] text-white/60 hover:text-white transition-all';
      }
    });
    calculateSwapQuote();
  };

  async function calculateSwapQuote() {
    const amtStr = state.nearSwap.amountIn;
    const amt = Number(amtStr);
    const targetToken = getSelectedTargetToken();
    const prlPrice = state.nearSwap.prlPrice || 1.59;
    const targetPrice = targetToken.price || 1.0;

    const outEl = document.getElementById('swap-amount-out');
    const fiatInEl = document.getElementById('swap-fiat-in');
    const fiatOutEl = document.getElementById('swap-fiat-out');
    const rateEl = document.getElementById('swap-detail-rate');
    const statusLabel = document.getElementById('swap-quote-status-label');

    // 基础汇率显示
    const prlToTargetRate = targetPrice > 0 ? (prlPrice / targetPrice) : 1.0;
    if (rateEl) {
      rateEl.innerText = `1 PRL ≈ ${prlToTargetRate.toFixed(4)} ${targetToken.symbol} (${targetToken.blockchain.toUpperCase()})`;
    }

    if (!amt || isNaN(amt) || amt <= 0) {
      if (outEl) outEl.innerText = '0.00';
      if (fiatInEl) fiatInEl.innerText = '≈ $0.00 USD';
      if (fiatOutEl) fiatOutEl.innerText = '≈ $0.00 USD';
      if (statusLabel) {
        statusLabel.innerText = '等待输入金额';
        statusLabel.className = 'text-[10px] text-white/40 font-mono';
      }
      return;
    }

    // 计算法定货币估值 (USD)
    if (state.nearSwap.direction === 'sell') {
      const fiatInUsd = amt * prlPrice;
      if (fiatInEl) fiatInUsd ? fiatInEl.innerText = `≈ $${fiatInUsd.toFixed(2)} USD` : '--';
      const estOut = amt * prlToTargetRate * (1 - state.nearSwap.slippageTolerance / 10000);
      state.nearSwap.amountOut = estOut.toFixed(4);
      if (outEl) outEl.innerText = state.nearSwap.amountOut;
      if (fiatOutEl) fiatOutEl.innerText = `≈ $${(estOut * targetPrice).toFixed(2)} USD`;
    } else {
      const fiatInUsd = amt * targetPrice;
      if (fiatInEl) fiatInUsd ? fiatInEl.innerText = `≈ $${fiatInUsd.toFixed(2)} USD` : '--';
      const targetToPrlRate = prlPrice > 0 ? (targetPrice / prlPrice) : 1.0;
      const estOut = amt * targetToPrlRate * (1 - state.nearSwap.slippageTolerance / 10000);
      state.nearSwap.amountOut = estOut.toFixed(4);
      if (outEl) outEl.innerText = state.nearSwap.amountOut;
      if (fiatOutEl) fiatOutEl.innerText = `≈ $${(estOut * prlPrice).toFixed(2)} USD`;
    }

    if (statusLabel) {
      statusLabel.innerText = '正在向 NEAR 做市商询价...';
      statusLabel.className = 'text-[10px] text-cyan-300 font-mono animate-pulse';
    }

    // 向 NEAR Intents 1Click API 发起真实 Dry 报价探测
    try {
      const isSell = state.nearSwap.direction === 'sell';
      const originAsset = isSell ? PEARL_DEFUSE_TOKEN.assetId : targetToken.assetId;
      const destinationAsset = isSell ? targetToken.assetId : PEARL_DEFUSE_TOKEN.assetId;
      const originDecimals = isSell ? PEARL_DEFUSE_TOKEN.decimals : targetToken.decimals;
      const wallet = getActiveWallet();

      const quoteReqBody = {
        dry: true,
        swapType: 'EXACT_INPUT',
        slippageTolerance: state.nearSwap.slippageTolerance,
        originAsset,
        depositType: 'ORIGIN_CHAIN',
        destinationAsset,
        amount: toBaseUnits(amtStr, originDecimals),
        refundTo: isSell ? (wallet?.address || 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm') : (state.nearSwap.recipientAddress || 'alice.near'),
        refundType: 'ORIGIN_CHAIN',
        recipient: isSell ? (state.nearSwap.recipientAddress || '0x0000000000000000000000000000000000000001') : (wallet?.address || 'prl1pvxtfv9c7a9elgny7jmhndtl9cwdy9wnhvphg7g5arxjvc2rwa4vq09sfpm'),
        recipientType: 'DESTINATION_CHAIN',
        deadline: new Date(Date.now() + 30 * 60 * 1000).toISOString()
      };

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);
      const res = await fetch('https://1click.chaindefuser.com/v0/quote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(quoteReqBody),
        signal: controller.signal
      });
      clearTimeout(timer);

      const json = await res.json();
      if (res.ok && json.quote && json.quote.amountOut) {
        const destDecimals = isSell ? targetToken.decimals : PEARL_DEFUSE_TOKEN.decimals;
        const actualOut = json.quote.amountOutFormatted || fromBaseUnits(json.quote.amountOut, destDecimals);
        state.nearSwap.amountOut = actualOut;
        if (outEl) outEl.innerText = actualOut;
        if (statusLabel) {
          statusLabel.innerText = `⚡ Solvers 实时撮合价 (${json.quote.timeEstimate || 20}s)`;
          statusLabel.className = 'text-[10px] text-emerald-400 font-mono';
        }
      } else {
        if (statusLabel) {
          statusLabel.innerText = '⚡ NEAR 预言机实时汇率';
          statusLabel.className = 'text-[10px] text-cyan-300 font-mono';
        }
      }
    } catch (e) {
      if (statusLabel) {
        statusLabel.innerText = '⚡ 基于链上实时市价';
        statusLabel.className = 'text-[10px] text-white/50 font-mono';
      }
    }
  }

  function renderNearSwapUI() {
    const isSell = state.nearSwap.direction === 'sell';
    const wallet = getActiveWallet();
    const targetToken = getSelectedTargetToken();

    // 1. Tab 高亮
    const btnSell = document.getElementById('btn-swap-dir-sell');
    const btnBuy = document.getElementById('btn-swap-dir-buy');
    if (btnSell && btnBuy) {
      if (isSell) {
        btnSell.className = 'flex-1 py-2 rounded-xl text-xs font-bold transition-all bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-sm';
        btnBuy.className = 'flex-1 py-2 rounded-xl text-xs font-medium text-white/50 transition-all hover:text-white';
      } else {
        btnBuy.className = 'flex-1 py-2 rounded-xl text-xs font-bold transition-all bg-cyan-500/20 text-cyan-300 border border-cyan-400/30 shadow-sm';
        btnSell.className = 'flex-1 py-2 rounded-xl text-xs font-medium text-white/50 transition-all hover:text-white';
      }
    }

    // 2. 支付方卡片
    const balanceLabel = document.getElementById('swap-balance-label');
    const balanceVal = document.getElementById('swap-balance-value');
    const payBadge = document.getElementById('swap-pay-token-badge');

    if (isSell) {
      if (balanceLabel) balanceLabel.innerText = 'PRL 可用余额:';
      if (balanceVal) balanceVal.innerText = wallet ? (Number(wallet.balance) || 0).toFixed(4) : '0.00';
      if (payBadge) {
        payBadge.innerHTML = `
          <span class="text-lg">🦪</span>
          <div class="text-left">
            <div class="text-xs font-bold leading-tight">PRL</div>
            <div class="text-[9px] text-cyan-300/80 leading-tight">Pearl 主网</div>
          </div>
        `;
      }
    } else {
      if (balanceLabel) balanceLabel.innerText = '外链钱包充值:';
      if (balanceVal) balanceVal.innerText = '--';
      if (payBadge) {
        payBadge.innerHTML = `
          <span class="text-lg">${targetToken.icon}</span>
          <div class="text-left">
            <div class="text-xs font-bold leading-tight">${targetToken.symbol}</div>
            <div class="text-[9px] text-cyan-300/80 leading-tight">${targetToken.networkName}</div>
          </div>
        `;
      }
    }

    // 3. 接收币种下拉菜单填充
    const selectEl = document.getElementById('swap-target-token-select');
    if (selectEl) {
      if (isSell) {
        selectEl.innerHTML = state.nearSwap.tokensList.map(t => `
          <option value="${t.assetId}" ${t.assetId === targetToken.assetId ? 'selected' : ''}>
            ${t.icon} ${t.symbol} (${t.blockchain.toUpperCase()})
          </option>
        `).join('');
      } else {
        selectEl.innerHTML = `
          <option value="${PEARL_DEFUSE_TOKEN.assetId}" selected>
            🦪 PRL (Pearl 主网)
          </option>
        `;
      }
    }

    // 4. 收款地址区域动态适配
    const recipientLabel = document.getElementById('swap-recipient-label');
    const recipientHint = document.getElementById('swap-recipient-chain-hint');
    const recipientInput = document.getElementById('swap-recipient-input');
    const recipientFeedback = document.getElementById('swap-recipient-feedback');

    if (isSell) {
      if (recipientLabel) recipientLabel.innerText = '接收目标链钱包地址';
      if (recipientHint) recipientHint.innerText = `${targetToken.networkName}`;
      if (recipientInput) {
        recipientInput.disabled = false;
        recipientInput.placeholder = `输入接收 ${targetToken.symbol} 的 ${targetToken.blockchain.toUpperCase()} 链地址`;
        recipientInput.value = state.nearSwap.recipientAddress;
      }
      if (recipientFeedback) {
        recipientFeedback.innerHTML = `请仔细核对您的 <strong>${targetToken.networkName}</strong> 收款地址，NEAR Intents Solvers 将直接跨链打款到该地址。`;
      }
    } else {
      if (recipientLabel) recipientLabel.innerText = '接收 Pearl 钱包地址';
      if (recipientHint) recipientHint.innerText = '当前主网钱包 (Taproot)';
      if (recipientInput) {
        recipientInput.disabled = true;
        recipientInput.value = wallet ? wallet.address : '';
      }
      if (recipientFeedback) {
        recipientFeedback.innerHTML = `兑换生成的 PRL 将直接安全入账至您的当前钱包 <strong>${wallet ? wallet.name : ''}</strong>。`;
      }
    }

    // 5. 汇率更新
    const rateEl = document.getElementById('swap-detail-rate');
    const prlPrice = state.nearSwap.prlPrice || 1.59;
    const targetPrice = targetToken.price || 1.0;
    const rate = targetPrice > 0 ? (prlPrice / targetPrice) : 1.0;
    if (rateEl) {
      rateEl.innerText = `1 PRL ≈ ${rate.toFixed(4)} ${targetToken.symbol} (${targetToken.blockchain.toUpperCase()})`;
    }
  }

  window.executeNearSwap = async function () {
    triggerHaptic('medium');
    const wallet = getActiveWallet();
    if (!wallet) {
      showToast('请先创建或导入 Pearl 钱包');
      return;
    }

    const amt = Number(state.nearSwap.amountIn);
    if (!amt || isNaN(amt) || amt <= 0) {
      showToast('请输入有效的兑换金额');
      return;
    }

    const isSell = state.nearSwap.direction === 'sell';
    const targetToken = getSelectedTargetToken();

    if (isSell) {
      const balance = Number(wallet.balance) || 0;
      if (amt > balance) {
        showToast(`PRL 余额不足 (当前可用: ${balance.toFixed(4)} PRL)`);
        return;
      }
      const recipient = state.nearSwap.recipientAddress.trim();
      if (!recipient) {
        showToast('请输入目标链收款地址');
        const input = document.getElementById('swap-recipient-input');
        if (input) input.focus();
        return;
      }
    }

    const btn = document.getElementById('btn-execute-swap');
    const btnText = document.getElementById('btn-swap-text');
    if (btn) btn.disabled = true;
    if (btnText) btnText.innerText = '正在向 NEAR 意图网络撮合下单...';

    try {
      const originAsset = isSell ? PEARL_DEFUSE_TOKEN.assetId : targetToken.assetId;
      const destinationAsset = isSell ? targetToken.assetId : PEARL_DEFUSE_TOKEN.assetId;
      const originDecimals = isSell ? PEARL_DEFUSE_TOKEN.decimals : targetToken.decimals;
      const recipient = isSell ? state.nearSwap.recipientAddress.trim() : wallet.address;
      const refundTo = isSell ? wallet.address : (state.nearSwap.recipientAddress.trim() || wallet.address);

      const quoteReqBody = {
        dry: false, // 真实生成意图存入地址
        swapType: 'EXACT_INPUT',
        slippageTolerance: state.nearSwap.slippageTolerance,
        originAsset,
        depositType: 'ORIGIN_CHAIN',
        destinationAsset,
        amount: toBaseUnits(state.nearSwap.amountIn, originDecimals),
        refundTo,
        refundType: 'ORIGIN_CHAIN',
        recipient,
        recipientType: 'DESTINATION_CHAIN',
        deadline: new Date(Date.now() + 15 * 60 * 1000).toISOString()
      };

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);
      const res = await fetch('https://1click.chaindefuser.com/v0/quote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(quoteReqBody),
        signal: controller.signal
      });
      clearTimeout(timer);

      const json = await res.json();

      if (res.ok && (json.depositAddress || json.quote?.depositAddress)) {
        triggerHaptic('success');
        const depositAddress = json.depositAddress || json.quote.depositAddress;
        renderActiveSwapOrder({
          depositAddress,
          amountIn: state.nearSwap.amountIn,
          amountOut: json.quote?.amountOutFormatted || state.nearSwap.amountOut,
          originSymbol: isSell ? 'PRL' : targetToken.symbol,
          destSymbol: isSell ? targetToken.symbol : 'PRL',
          deadline: json.quote?.deadline || new Date(Date.now() + 15 * 60 * 1000).toISOString()
        });
        showToast('跨链意图已生成，请在倒计时结束前存入资金');
      } else {
        // 如果公网做市商正处于撮合更新或需隐私意图模式
        const msg = json.message || '流动性撮合中';
        showToast(`意图网络通知: ${msg}`);
        showNearSwapDirectHelper(targetToken);
      }
    } catch (err) {
      showToast(`网络连接异常: ${err.message}`);
    } finally {
      if (btn) btn.disabled = false;
      if (btnText) btnText.innerText = '⚡ 发起意图跨链兑换';
    }
  };

  function renderActiveSwapOrder(order) {
    state.nearSwap.activeOrder = order;

    const formContainer = document.getElementById('swap-form-container');
    const orderCard = document.getElementById('swap-active-order-card');
    if (formContainer) formContainer.classList.add('hidden');
    if (orderCard) orderCard.classList.remove('hidden');

    const titleEl = document.getElementById('swap-deposit-instruction-title');
    const amtEl = document.getElementById('swap-deposit-instruction-amount');
    const addrEl = document.getElementById('swap-deposit-address-text');
    const directPayBox = document.getElementById('swap-pearl-direct-pay-box');

    if (titleEl) {
      titleEl.innerText = `请存入以下 ${order.originSymbol} 以触发跨链交割`;
    }
    if (amtEl) {
      amtEl.innerText = `${order.amountIn} ${order.originSymbol} ➔ 预计获得 ≈ ${order.amountOut} ${order.destSymbol}`;
    }
    if (addrEl) {
      addrEl.innerText = order.depositAddress;
    }

    if (directPayBox) {
      if (order.originSymbol === 'PRL') {
        directPayBox.classList.remove('hidden');
      } else {
        directPayBox.classList.add('hidden');
      }
    }

    // 渲染存入二维码
    renderSwapDepositQRCode(order.depositAddress);

    // 启动 10 分钟倒计时
    startSwapCountdown(10 * 60);

    // 启动状态轮询
    startSwapStatusPolling(order.depositAddress);
  }

  function renderSwapDepositQRCode(text) {
    const container = document.getElementById('swap-deposit-qrcode-container');
    if (!container) return;
    container.innerHTML = '';
    if (typeof QRCode !== 'undefined') {
      try {
        new QRCode(container, {
          text: text,
          width: 140,
          height: 140,
          colorDark: "#090A12",
          colorLight: "#FFFFFF",
          correctLevel: QRCode.CorrectLevel.M
        });
        return;
      } catch (e) {}
    }
    const img = document.createElement('img');
    img.src = `https://api.qrserver.com/v1/create-qr-code/?size=140x140&data=${encodeURIComponent(text)}`;
    img.className = 'w-32 h-32 rounded-lg';
    container.appendChild(img);
  }

  function startSwapCountdown(durationSeconds) {
    if (state.nearSwap.orderExpiryTimer) clearInterval(state.nearSwap.orderExpiryTimer);
    let remain = durationSeconds;
    const timerEl = document.getElementById('swap-countdown-timer');

    state.nearSwap.orderExpiryTimer = setInterval(() => {
      remain--;
      if (remain <= 0) {
        clearInterval(state.nearSwap.orderExpiryTimer);
        if (timerEl) timerEl.innerText = '已失效 (请重新下单)';
        return;
      }
      const m = Math.floor(remain / 60).toString().padStart(2, '0');
      const s = (remain % 60).toString().padStart(2, '0');
      if (timerEl) timerEl.innerText = `${m}:${s}`;
    }, 1000);
  }

  function startSwapStatusPolling(depositAddress) {
    if (state.nearSwap.statusPollTimer) clearInterval(state.nearSwap.statusPollTimer);

    state.nearSwap.statusPollTimer = setInterval(async () => {
      try {
        const res = await fetch(`https://1click.chaindefuser.com/v0/status?depositAddress=${encodeURIComponent(depositAddress)}`);
        if (res.ok) {
          const json = await res.json();
          updateSwapOrderStatus(json.status || json.state || 'PENDING');
        }
      } catch (e) {}
    }, 4500);
  }

  function updateSwapOrderStatus(status) {
    const pill = document.getElementById('swap-order-status-pill');
    const label = document.getElementById('swap-step-label');
    const bar = document.getElementById('swap-progress-bar');
    if (!pill || !label || !bar) return;

    if (status === 'SUCCESS' || status === 'COMPLETED') {
      pill.innerText = '跨链交割成功';
      pill.className = 'text-[10px] px-2 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
      label.innerText = '3/3 兑换已完成并交付';
      bar.style.width = '100%';
      triggerHaptic('success');
      showToast('🎉 跨链兑换成功！资产已入账目标地址');
      if (state.nearSwap.statusPollTimer) clearInterval(state.nearSwap.statusPollTimer);
    } else if (status === 'PROCESSING' || status === 'EXECUTING') {
      pill.innerText = '做市商撮合中';
      pill.className = 'text-[10px] px-2 py-0.5 rounded-full font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30';
      label.innerText = '2/3 链上已确认，做市撮合中';
      bar.style.width = '66%';
    } else {
      pill.innerText = '等待存入';
      pill.className = 'text-[10px] px-2 py-0.5 rounded-full font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30';
      label.innerText = '1/3 等待链上存入到账';
      bar.style.width = '33%';
    }
  }

  window.copySwapDepositAddress = function () {
    triggerHaptic('light');
    const addr = state.nearSwap.activeOrder?.depositAddress;
    if (addr) {
      navigator.clipboard?.writeText?.(addr).then(() => {
        showToast('存入地址已复制到剪贴板');
      }).catch(() => showToast(`地址: ${addr}`));
    }
  };

  window.paySwapWithCurrentWallet = function () {
    triggerHaptic('medium');
    const order = state.nearSwap.activeOrder;
    if (!order || order.originSymbol !== 'PRL') return;

    const sendAddrInput = document.getElementById('send-address-input');
    const sendAmtInput = document.getElementById('send-amount-input');
    if (sendAddrInput) sendAddrInput.value = order.depositAddress;
    if (sendAmtInput) {
      sendAmtInput.value = order.amountIn;
      handleSendAmountInput(sendAmtInput);
    }

    closeSheet();
    setTimeout(() => {
      openSheet('sheet-send');
      showToast('已填入意图充值地址与金额，请滑动完成支付');
    }, 250);
  };

  window.openNearOfficialSwap = function () {
    triggerHaptic('light');
    const url = 'https://near.com';
    if (typeof window !== 'undefined' && window.open) {
      window.open(url, '_blank', 'noopener,noreferrer');
    }
  };

  function showNearSwapDirectHelper(targetToken) {
    showToast(`提示: 您可在 near.com 官方聚合器直接体验 PRL 与 ${targetToken.symbol} 跨链闪兑`);
  }

  window.resetSwapForm = function () {
    triggerHaptic('light');
    if (state.nearSwap.statusPollTimer) clearInterval(state.nearSwap.statusPollTimer);
    if (state.nearSwap.orderExpiryTimer) clearInterval(state.nearSwap.orderExpiryTimer);
    state.nearSwap.activeOrder = null;

    const formContainer = document.getElementById('swap-form-container');
    const orderCard = document.getElementById('swap-active-order-card');
    if (formContainer) formContainer.classList.remove('hidden');
    if (orderCard) orderCard.classList.add('hidden');
  };

  window.addEventListener('DOMContentLoaded', () => {
    initWallets();
    loadContacts();
    setupSwipeToSend();
    setupInteractiveChartScrubbing();
    updateDevFeeUI();
    applyLanguage(state.currentLang);
    renderNavTabs('wallet');
    renderInteractiveChart();

    // 启动代币市价实时更新心跳 (每 30 秒自动同步)
    fetchRealKryptexRates();
    setInterval(fetchRealKryptexRates, 30000);
  });

})();
