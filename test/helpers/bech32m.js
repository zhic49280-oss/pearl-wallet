/**
 * BIP-350 / BIP-341 Bech32m Reference Implementation for Pearl (PRL)
 * Specification: Taproot witness version 1, HRP "prl", 32-byte witness program
 */

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;
const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
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
  if (witnessVersion < 0 || witnessVersion > 16) {
    throw new Error(`Invalid witness version: ${witnessVersion}`);
  }
  const converted = convertBits(programBytes, 8, 5, true);
  if (!converted) {
    throw new Error('Failed to convert bits');
  }
  const words = [witnessVersion].concat(converted);
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
    programHex: Buffer.from(programBytes).toString('hex')
  };
}

function validatePearlAddress(address) {
  const decoded = decodeBech32m(address);
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

module.exports = {
  BECH32_CHARSET,
  BECH32M_CONST,
  bech32Polymod,
  bech32HrpExpand,
  convertBits,
  encodeBech32m,
  decodeBech32m,
  validatePearlAddress
};
