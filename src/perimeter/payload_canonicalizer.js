/**
 * W1™ Payload Canonicalizer & Anti-Evasion Pipeline
 * File: src/perimeter/payload_canonicalizer.js
 *
 * Defeats obfuscation, steganography, homoglyph spoofing, and multi-layer
 * encoding evasion BEFORE inspection by Nuclei, Zero-Day, and Radar engines:
 * 1. Unicode NFKC normalization + zero-width/steganography removal.
 * 2. Confusable Cyrillic/Greek homoglyph normalization to ASCII equivalents.
 * 3. Hidden ASCII control-character detection.
 * 4. Bounded recursive decoding (Base64, Hex, URL-encoding) up to MAX_DECODE_DEPTH = 3
 *    with strict input/output expansion limits to prevent decode bombs.
 */

export const MAX_DECODE_DEPTH = 3;

const DEFAULT_MAX_INPUT_BYTES = 1024 * 1024; // 1 MB
const DEFAULT_MAX_EXPANSION_BYTES = 512 * 1024; // 512 KB

// Zero-width, BOM, directional overrides, and invisible formatting chars
const ZERO_WIDTH_REGEX = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\u00AD]/g;

// Non-printable ASCII control chars (excludes \t \n \r)
const HIDDEN_CONTROL_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

// Common Cyrillic & Greek visual homoglyphs used to spoof ASCII security keywords
const HOMOGLYPH_MAP = new Map([
  ['\u0430', 'a'], ['\u0410', 'A'], // Cyrillic а / А
  ['\u0435', 'e'], ['\u0415', 'E'], // Cyrillic е / Е
  ['\u0451', 'e'], ['\u0401', 'E'], // Cyrillic ё / Ё
  ['\u043E', 'o'], ['\u041E', 'O'], // Cyrillic о / О
  ['\u0440', 'p'], ['\u0420', 'P'], // Cyrillic р / Р
  ['\u0441', 'c'], ['\u0421', 'C'], // Cyrillic с / С
  ['\u0443', 'y'], ['\u0423', 'Y'], // Cyrillic у / У
  ['\u0445', 'x'], ['\u0425', 'X'], // Cyrillic х / Х
  ['\u0456', 'i'], ['\u0406', 'I'], // Cyrillic і / І
  ['\u0458', 'j'], ['\u0408', 'J'], // Cyrillic ј / Ј
  ['\u0455', 's'], ['\u0405', 'S'], // Cyrillic ѕ / Ѕ
  ['\u0412', 'B'],                  // Cyrillic В
  ['\u041A', 'K'], ['\u043A', 'k'], // Cyrillic К / к
  ['\u041C', 'M'],                  // Cyrillic М
  ['\u041D', 'H'],                  // Cyrillic Н
  ['\u0422', 'T'],                  // Cyrillic Т
  ['\u0501', 'd'], ['\u051B', 'q'], // Cyrillic ԁ / ԛ
  ['\u03B1', 'a'], ['\u0391', 'A'], // Greek α / Α
  ['\u03B2', 'b'], ['\u0392', 'B'], // Greek β / Β
  ['\u03B5', 'e'], ['\u0395', 'E'], // Greek ε / Ε
  ['\u03B9', 'i'], ['\u0399', 'I'], // Greek ι / Ι
  ['\u03BA', 'k'], ['\u039A', 'K'], // Greek κ / Κ
  ['\u03BC', 'u'], ['\u039C', 'M'], // Greek μ / Μ
  ['\u03BD', 'v'], ['\u039D', 'N'], // Greek ν / Ν
  ['\u03BF', 'o'], ['\u039F', 'O'], // Greek ο / Ο
  ['\u03C1', 'p'], ['\u03A1', 'P'], // Greek ρ / Ρ
  ['\u03C4', 't'], ['\u03A4', 'T'], // Greek τ / Τ
  ['\u03C7', 'x'], ['\u03A7', 'X'], // Greek χ / Χ
  ['\u0396', 'Z'], ['\u0397', 'H']  // Greek Ζ / Η
]);

export class PayloadCanonicalizer {
  constructor(options = {}) {
    this.maxDecodeDepth = Math.min(
      MAX_DECODE_DEPTH,
      Math.max(1, Number(options.maxDecodeDepth ?? MAX_DECODE_DEPTH))
    );
    this.maxInputBytes = Number(options.maxInputBytes ?? DEFAULT_MAX_INPUT_BYTES);
    this.maxExpansionBytes = Number(options.maxExpansionBytes ?? DEFAULT_MAX_EXPANSION_BYTES);
  }

  /**
   * Normalizes Unicode (NFKC), removes zero-width chars, maps homoglyphs,
   * detects hidden control chars, and recursively decodes nested encodings
   * (Base64, Hex, URL) up to MAX_DECODE_DEPTH.
   *
   * @param {string|Object} input
   * @returns {{
   *   originalText: string,
   *   canonicalText: string,
   *   decodedLayers: string[],
   *   combinedText: string,
   *   maxObservedDepth: number,
   *   evasionDetected: boolean,
   *   riskLevel: string,
   *   evasionReasons: string[],
   *   telemetry: Object
   * }}
   */
  canonicalize(input) {
    const rawText = this._coerceToString(input);
    const evasionReasons = [];

    if (Buffer.byteLength(rawText, 'utf8') > this.maxInputBytes) {
      return {
        originalText: rawText.slice(0, 1024),
        canonicalText: rawText.slice(0, 1024),
        decodedLayers: [],
        combinedText: rawText.slice(0, 1024),
        maxObservedDepth: 0,
        evasionDetected: true,
        riskLevel: 'HIGH',
        evasionReasons: ['INPUT_SIZE_EXCEEDS_CANONICALIZER_CAP'],
        telemetry: {
          zeroWidthRemovedCount: 0,
          homoglyphsMappedCount: 0,
          hiddenControlCharsCount: 0
        }
      };
    }

    const baseNorm = this._normalizeSurface(rawText);
    let zeroWidthTotal = baseNorm.zeroWidthRemovedCount;
    let homoglyphsTotal = baseNorm.homoglyphsMappedCount;
    let hiddenControlTotal = baseNorm.hiddenControlCharsCount;

    if (baseNorm.hiddenControlCharsCount > 0) {
      evasionReasons.push(`HIDDEN_CONTROL_CHARS(${baseNorm.hiddenControlCharsCount})`);
    }

    const decodedLayers = [];
    const seen = new Set([baseNorm.text]);
    let frontier = [baseNorm.text];
    let totalDecodedBytes = 0;
    let maxObservedDepth = 0;
    let expansionBombTriggered = false;

    for (let depth = 1; depth <= this.maxDecodeDepth && frontier.length > 0; depth++) {
      const nextFrontier = [];

      for (const layerText of frontier) {
        const candidates = this._decodeSinglePass(layerText);
        for (const candidate of candidates) {
          const normCandidate = this._normalizeSurface(candidate);
          zeroWidthTotal += normCandidate.zeroWidthRemovedCount;
          homoglyphsTotal += normCandidate.homoglyphsMappedCount;
          hiddenControlTotal += normCandidate.hiddenControlCharsCount;

          if (normCandidate.hiddenControlCharsCount > 0 && !evasionReasons.some((r) => r.startsWith('HIDDEN_CONTROL_CHARS'))) {
            evasionReasons.push(`HIDDEN_CONTROL_CHARS(${normCandidate.hiddenControlCharsCount})`);
          }

          if (!normCandidate.text || seen.has(normCandidate.text)) {
            continue;
          }

          const byteLen = Buffer.byteLength(normCandidate.text, 'utf8');
          if (totalDecodedBytes + byteLen > this.maxExpansionBytes) {
            expansionBombTriggered = true;
            evasionReasons.push('DECODE_EXPANSION_BOMB_CAP');
            break;
          }

          totalDecodedBytes += byteLen;
          seen.add(normCandidate.text);
          decodedLayers.push(normCandidate.text);
          nextFrontier.push(normCandidate.text);
          maxObservedDepth = Math.max(maxObservedDepth, depth);
        }
        if (expansionBombTriggered) break;
      }

      if (expansionBombTriggered) break;
      frontier = nextFrontier;
    }

    // Check if even at depth 3 there is STILL another decodable layer (> 2 nested layers / > max depth)
    if (!expansionBombTriggered && maxObservedDepth >= this.maxDecodeDepth && frontier.length > 0) {
      for (const tailText of frontier) {
        if (this._decodeSinglePass(tailText).length > 0) {
          maxObservedDepth = this.maxDecodeDepth + 1;
          break;
        }
      }
    }

    if (maxObservedDepth > 2) {
      evasionReasons.push(`DEEP_NESTED_OBFUSCATION_DEPTH(${maxObservedDepth})`);
    }

    const evasionDetected = evasionReasons.length > 0;
    const riskLevel = evasionDetected ? 'HIGH' : 'LOW';

    const combinedParts = [rawText];
    if (baseNorm.text !== rawText) combinedParts.push(baseNorm.text);
    for (const layer of decodedLayers) combinedParts.push(layer);

    return {
      originalText: rawText,
      canonicalText: baseNorm.text,
      decodedLayers,
      combinedText: combinedParts.join('\n'),
      maxObservedDepth,
      evasionDetected,
      riskLevel,
      evasionReasons,
      telemetry: {
        zeroWidthRemovedCount: zeroWidthTotal,
        homoglyphsMappedCount: homoglyphsTotal,
        hiddenControlCharsCount: hiddenControlTotal,
        decodedLayersCount: decodedLayers.length
      }
    };
  }

  /**
   * @private
   */
  _coerceToString(input) {
    if (input === null || input === undefined) return '';
    if (typeof input === 'string') return input;
    try {
      return JSON.stringify(input);
    } catch {
      return String(input);
    }
  }

  /**
   * Applies NFKC normalization, strips zero-width chars, maps homoglyphs,
   * and strips non-whitespace ASCII control chars while counting each anomaly.
   * @private
   */
  _normalizeSurface(text) {
    if (!text) {
      return {
        text: '',
        zeroWidthRemovedCount: 0,
        homoglyphsMappedCount: 0,
        hiddenControlCharsCount: 0
      };
    }

    let zeroWidthRemovedCount = 0;
    const withoutZeroWidth = text.replace(ZERO_WIDTH_REGEX, () => {
      zeroWidthRemovedCount++;
      return '';
    });

    const nfkc = withoutZeroWidth.normalize('NFKC');

    let homoglyphsMappedCount = 0;
    let mapped = '';
    for (const ch of nfkc) {
      const replacement = HOMOGLYPH_MAP.get(ch);
      if (replacement !== undefined) {
        homoglyphsMappedCount++;
        mapped += replacement;
      } else {
        mapped += ch;
      }
    }

    let hiddenControlCharsCount = 0;
    const cleanText = mapped.replace(HIDDEN_CONTROL_REGEX, () => {
      hiddenControlCharsCount++;
      return '';
    });

    return {
      text: cleanText,
      zeroWidthRemovedCount,
      homoglyphsMappedCount,
      hiddenControlCharsCount
    };
  }

  /**
   * Performs one pass of URL, Hex, and Base64 decoding on embedded tokens
   * and whole-string segments. Only emits genuinely printable UTF-8 outputs.
   * @private
   */
  _decodeSinglePass(text) {
    if (!text || text.length < 4) return [];
    const results = [];

    // 1. URL-encoding (%XX / %uXXXX)
    if (/%[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}/i.test(text)) {
      let urlDecoded = text.replace(/%u([0-9a-fA-F]{4})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );
      urlDecoded = urlDecoded.replace(/(?:%[0-9a-fA-F]{2})+/g, (seq) => {
        try {
          return decodeURIComponent(seq);
        } catch {
          return seq;
        }
      });
      if (urlDecoded !== text) {
        results.push(urlDecoded);
      }
    }

    // 2. Hex escapes (\xHH) and contiguous ASCII-hex blocks (0x... or hex tokens >= 16 chars)
    if (/(?:\\x[0-9a-fA-F]{2}){4,}/i.test(text)) {
      const escHexDecoded = text.replace(/(?:\\x([0-9a-fA-F]{2}))+/gi, (full) => {
        const bytes = [];
        const rx = /\\x([0-9a-fA-F]{2})/gi;
        let m;
        while ((m = rx.exec(full)) !== null) {
          bytes.push(parseInt(m[1], 16));
        }
        const buf = Buffer.from(bytes);
        return this._isMostlyPrintableAscii(buf) ? buf.toString('utf8') : full;
      });
      if (escHexDecoded !== text) {
        results.push(escHexDecoded);
      }
    }

    const hexTokenRegex = /\b(?:0x)?([0-9a-fA-F]{16,})\b/g;
    let hexDecodedChanged = false;
    const hexReplaced = text.replace(hexTokenRegex, (full, hexBody) => {
      if (hexBody.length % 2 !== 0) return full;
      const buf = Buffer.from(hexBody, 'hex');
      if (buf.length >= 8 && this._isMostlyPrintableAscii(buf)) {
        hexDecodedChanged = true;
        return buf.toString('utf8');
      }
      return full;
    });
    if (hexDecodedChanged && hexReplaced !== text) {
      results.push(hexReplaced);
    }

    // 3. Base64 tokens (standard + URL-safe), requiring >= 12 encoded chars and printable decoded output
    // Leading `=` (e.g. `note=<b64>`) is an assignment separator, while trailing `=` is padding.
    const b64TokenRegex = /(^|[^A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{12,}={0,2})(?=$|[^A-Za-z0-9+/=_-])/g;
    let b64Changed = false;
    const b64Replaced = text.replace(b64TokenRegex, (full, prefix, token) => {
      const decoded = this._tryDecodeBase64Token(token);
      if (decoded !== null) {
        b64Changed = true;
        return `${prefix}${decoded}`;
      }
      return full;
    });
    if (b64Changed && b64Replaced !== text) {
      results.push(b64Replaced);
    }

    return results;
  }

  /**
   * Decodes a candidate Base64 token strictly if it is valid Base64 and
   * yields predominantly printable ASCII/UTF-8 text (prevents false matches on English words).
   * @private
   */
  _tryDecodeBase64Token(token) {
    if (!token || token.length < 12) return null;
    // Normalize URL-safe Base64 and ensure valid length mod 4
    let std = token.replace(/-/g, '+').replace(/_/g, '/');
    const mod = std.length % 4;
    if (mod === 1) return null;
    if (mod > 0) std = std + '='.repeat(4 - mod);

    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(std)) return null;

    let buf;
    try {
      buf = Buffer.from(std, 'base64');
    } catch {
      return null;
    }

    if (buf.length < 6) return null;

    // Verify canonical Base64 round-trip to reject arbitrary non-base64 strings
    const reencoded = buf.toString('base64');
    if (reencoded.replace(/=+$/, '') !== std.replace(/=+$/, '')) {
      return null;
    }

    if (!this._isMostlyPrintableAscii(buf)) {
      return null;
    }

    return buf.toString('utf8');
  }

  /**
   * Checks whether a decoded buffer consists of >= 85% printable ASCII
   * (0x20..0x7E or \t \r \n) with zero NUL bytes.
   * @private
   */
  _isMostlyPrintableAscii(buf) {
    if (!buf || buf.length === 0) return false;
    let printable = 0;
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      if (b === 0x00) return false;
      if ((b >= 0x20 && b <= 0x7E) || b === 0x09 || b === 0x0A || b === 0x0D) {
        printable++;
      }
    }
    return (printable / buf.length) >= 0.85;
  }
}
