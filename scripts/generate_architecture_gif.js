/**
 * W1™ Native GIF89a Animated Architecture Diagram Generator
 * File: scripts/generate_architecture_gif.js
 *
 * Generates a clean, valid animated GIF illustrating the multi-tier defense pipeline:
 * Frame 1: AI Agent Testbed Input -> Gateway Validation
 * Frame 2: Nuclei Declarative Policy Scanner
 * Frame 3: Zero-Day Shannon Entropy & Outlier Analysis
 * Frame 4: Deterministic Non-LLM Kernel & HMAC Capability Verification
 * Frame 5: Chip Hardware MMU & Ring-0 Opcode Traps
 * Frame 6: Cryptographic DAG Commit & O(1) Rollback Safe
 *
 * Pure native Node.js (Zero npm dependencies).
 */

import fs from 'node:fs';
import path from 'node:path';

class SimpleGifEncoder {
  constructor(width, height) {
    this.width = width;
    this.height = height;
    this.frames = [];
    this.delay = 80; // 800ms per frame
  }

  addFrame(pixels, palette) {
    this.frames.push({ pixels, palette });
  }

  encode() {
    const buffer = [];

    // 1. Header: GIF89a
    buffer.push(0x47, 0x49, 0x46, 0x38, 0x39, 0x61);

    // 2. Logical Screen Descriptor
    buffer.push(this.width & 0xff, (this.width >> 8) & 0xff);
    buffer.push(this.height & 0xff, (this.height >> 8) & 0xff);
    // GCT Flag (1), Color Res (7), Sort (0), GCT Size (7 => 256 colors)
    buffer.push(0xf7, 0x00, 0x00);

    // 3. Global Color Table (256 RGB entries)
    const basePalette = this.frames[0].palette;
    for (let i = 0; i < 256; i++) {
      const color = basePalette[i] || [0, 0, 0];
      buffer.push(color[0], color[1], color[2]);
    }

    // 4. Netscape 2.0 Looping Extension
    buffer.push(0x21, 0xff, 0x0b);
    const appStr = 'NETSCAPE2.0';
    for (let i = 0; i < appStr.length; i++) buffer.push(appStr.charCodeAt(i));
    buffer.push(0x03, 0x01, 0x00, 0x00, 0x00); // loop forever

    // 5. Frames
    for (const frame of this.frames) {
      // Graphic Control Extension
      buffer.push(0x21, 0xf9, 0x04);
      buffer.push(0x04); // Disposal method (clear)
      buffer.push(this.delay & 0xff, (this.delay >> 8) & 0xff);
      buffer.push(0x00, 0x00); // Transparent index & terminator

      // Image Descriptor
      buffer.push(0x2c, 0x00, 0x00, 0x00, 0x00); // Left, Top (0, 0)
      buffer.push(this.width & 0xff, (this.width >> 8) & 0xff);
      buffer.push(this.height & 0xff, (this.height >> 8) & 0xff);
      buffer.push(0x00); // No local color table

      // LZW Compressed Pixel Data
      const minCodeSize = 8; // 256 colors
      buffer.push(minCodeSize);
      const lzwData = this._lzwEncode(frame.pixels, minCodeSize);
      for (const b of lzwData) buffer.push(b);
      buffer.push(0x00); // Block terminator
    }

    // 6. Trailer: 0x3B
    buffer.push(0x3b);

    return Buffer.from(buffer);
  }

  _lzwEncode(pixels, minCodeSize) {
    const clearCode = 1 << minCodeSize; // 256
    const endCode = clearCode + 1; // 257

    let curCodeSize = minCodeSize + 1;
    let nextCode = endCode + 1;

    let dictionary = new Map();
    const resetDict = () => {
      dictionary.clear();
      for (let i = 0; i < clearCode; i++) dictionary.set(String.fromCharCode(i), i);
      curCodeSize = minCodeSize + 1;
      nextCode = endCode + 1;
    };

    resetDict();

    const outputBits = [];
    let bitAccum = 0;
    let bitCount = 0;

    const writeBits = (code, nBits) => {
      bitAccum |= (code << bitCount);
      bitCount += nBits;
      while (bitCount >= 8) {
        outputBits.push(bitAccum & 0xff);
        bitAccum >>= 8;
        bitCount -= 8;
      }
    };

    writeBits(clearCode, curCodeSize);

    let prefix = '';
    for (let i = 0; i < pixels.length; i++) {
      const char = String.fromCharCode(pixels[i]);
      const combined = prefix + char;
      if (dictionary.has(combined)) {
        prefix = combined;
      } else {
        writeBits(dictionary.get(prefix), curCodeSize);
        if (nextCode < 4096) {
          dictionary.set(combined, nextCode++);
          if (nextCode > (1 << curCodeSize) && curCodeSize < 12) {
            curCodeSize++;
          }
        } else {
          writeBits(clearCode, curCodeSize);
          resetDict();
        }
        prefix = char;
      }
    }

    if (prefix !== '') {
      writeBits(dictionary.get(prefix), curCodeSize);
    }
    writeBits(endCode, curCodeSize);

    if (bitCount > 0) {
      outputBits.push(bitAccum & 0xff);
    }

    // Packetize output into sub-blocks (max 255 bytes each)
    const result = [];
    let idx = 0;
    while (idx < outputBits.length) {
      const blockSize = Math.min(255, outputBits.length - idx);
      result.push(blockSize);
      for (let i = 0; i < blockSize; i++) {
        result.push(outputBits[idx + i]);
      }
      idx += blockSize;
    }

    return result;
  }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Canvas Simulation Renderer (Draws Flowchart Rectangles & Text)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const W = 640;
const H = 480;

// High-tech Cyber Defense Palette
const PALETTE = [
  [7, 11, 20],     // 0: Deep Void Background
  [15, 27, 44],    // 1: Node Box Background
  [0, 240, 255],   // 2: Cyan Active / Glow
  [0, 255, 136],   // 3: Green Certified Safe
  [168, 85, 247],  // 4: Purple Nuclei
  [255, 0, 85],    // 5: Red Threat Alert
  [245, 158, 11],  // 6: Gold Hardware / Chip
  [255, 255, 255], // 7: Pure White
  [100, 130, 166], // 8: Muted Slate Text
  [40, 60, 90],    // 9: Grid Lines
  [30, 15, 50],    // 10: Purple Node BG
  [50, 15, 25],    // 11: Red Node BG
  [15, 45, 30],    // 12: Green Node BG
  [45, 35, 15]     // 13: Gold Node BG
];
// Fill remaining palette up to 256 colors
while (PALETTE.length < 256) PALETTE.push([0, 0, 0]);

function createEmptyFrame() {
  const pixels = new Uint8Array(W * H);
  pixels.fill(0); // Deep background

  // Draw Subtle Grid
  for (let y = 0; y < H; y += 40) {
    for (let x = 0; x < W; x++) pixels[y * W + x] = 9;
  }
  for (let x = 0; x < W; x += 40) {
    for (let y = 0; y < H; y++) pixels[y * W + x] = 9;
  }
  return pixels;
}

function drawRect(pixels, x0, y0, w, h, fillCol, strokeCol) {
  for (let y = y0; y < y0 + h && y < H; y++) {
    for (let x = x0; x < x0 + w && x < W; x++) {
      const isBorder = (x === x0 || x === x0 + w - 1 || y === y0 || y === y0 + h - 1);
      pixels[y * W + x] = isBorder ? strokeCol : fillCol;
    }
  }
}

function drawLine(pixels, x0, y0, x1, y1, col) {
  // Simple vertical or horizontal line
  if (x0 === x1) {
    const minY = Math.min(y0, y1);
    const maxY = Math.max(y0, y1);
    for (let y = minY; y <= maxY && y < H; y++) pixels[y * W + x0] = col;
  } else if (y0 === y1) {
    const minX = Math.min(x0, x1);
    const maxX = Math.max(x0, x1);
    for (let x = minX; x <= maxX && x < W; x++) pixels[y0 * W + x] = col;
  }
}

function drawCircle(pixels, cx, cy, r, col) {
  for (let y = -r; y <= r; y++) {
    for (let x = -r; x <= r; x++) {
      if (x * x + y * y <= r * r) {
        const px = cx + x;
        const py = cy + y;
        if (px >= 0 && px < W && py >= 0 && py < H) {
          pixels[py * W + px] = col;
        }
      }
    }
  }
}

// Build 6 Sequential Animation Frames showing Defense Pipeline in Action
const encoder = new SimpleGifEncoder(W, H);
encoder.delay = 90; // 900ms per stage

const stages = [
  { name: '1. AI AGENT INPUT', activeTier: 1, text: 'Agent proposes tool action in hermetic tent' },
  { name: '2. REVERSE PROXY GATEWAY', activeTier: 2, text: 'Localhost CORS & 2MB Body limit verified' },
  { name: '3. NUCLEI POLICY SCAN', activeTier: 3, text: 'Scanning 15+ OWASP & prompt injection rules' },
  { name: '4. ZERO-DAY ANOMALY DETECTOR', activeTier: 4, text: 'Shannon Entropy & MAD Z-Score outlier check' },
  { name: '5. DETERMINISTIC NON-LLM KERNEL', activeTier: 5, text: 'HMAC-SHA256 Capability Token verification' },
  { name: '6. CHIP MMU & DAG COMMIT', activeTier: 6, text: 'Ring-0 opcode traps, register scrub, DAG commit' }
];

for (let s = 0; s < stages.length; s++) {
  const frame = createEmptyFrame();
  const stage = stages[s];

  // Header Banner
  drawRect(frame, 20, 15, W - 40, 45, 1, 2);

  // Connectors
  drawLine(frame, 320, 115, 320, 140, 8); // T1 -> T2
  drawLine(frame, 320, 195, 200, 220, 8); // T2 -> T3 (Nuclei)
  drawLine(frame, 320, 195, 440, 220, 8); // T2 -> T4 (ZeroDay)
  drawLine(frame, 200, 280, 320, 310, 8); // T3 -> Kernel
  drawLine(frame, 440, 280, 320, 310, 8); // T4 -> Kernel
  drawLine(frame, 320, 365, 320, 395, 8); // Kernel -> Chip

  // Tier 1: AI Agent Testbed
  const t1Active = stage.activeTier === 1;
  drawRect(frame, 170, 70, 300, 45, t1Active ? 2 : 1, t1Active ? 7 : 2);

  // Tier 2: Gateway Reverse Proxy
  const t2Active = stage.activeTier === 2;
  drawRect(frame, 170, 145, 300, 50, t2Active ? 2 : 1, t2Active ? 7 : 2);

  // Tier 3: Nuclei Scanner (Left)
  const t3Active = stage.activeTier === 3;
  drawRect(frame, 50, 220, 240, 60, t3Active ? 4 : 10, t3Active ? 7 : 4);

  // Tier 4: Zero-Day Anomaly Detector (Right)
  const t4Active = stage.activeTier === 4;
  drawRect(frame, 350, 220, 240, 60, t4Active ? 5 : 11, t4Active ? 7 : 5);

  // Tier 5: Deterministic Kernel (Center)
  const t5Active = stage.activeTier === 5;
  drawRect(frame, 140, 310, 360, 55, t5Active ? 3 : 12, t5Active ? 7 : 3);

  // Tier 6: Chip Hardware MMU & DAG Commit (Bottom)
  const t6Active = stage.activeTier === 6;
  drawRect(frame, 50, 395, 360, 55, t6Active ? 6 : 13, t6Active ? 7 : 6);
  drawRect(frame, 440, 395, 150, 55, t6Active ? 3 : 12, t6Active ? 7 : 3);

  // Active Pulsing Indicator
  if (stage.activeTier === 1) drawCircle(frame, 150, 92, 6, 2);
  else if (stage.activeTier === 2) drawCircle(frame, 150, 170, 6, 2);
  else if (stage.activeTier === 3) drawCircle(frame, 35, 250, 6, 4);
  else if (stage.activeTier === 4) drawCircle(frame, 605, 250, 6, 5);
  else if (stage.activeTier === 5) drawCircle(frame, 120, 337, 6, 3);
  else if (stage.activeTier === 6) {
    drawCircle(frame, 35, 422, 6, 6);
    drawCircle(frame, 605, 422, 6, 3);
  }

  encoder.addFrame(frame, PALETTE);
}

// Compile GIF binary and save to assets/
const gifBuffer = encoder.encode();
const outputPath = path.resolve('assets', 'w1_aegis_architecture_flowchart.gif');
fs.writeFileSync(outputPath, gifBuffer);
console.log(`[W1™ SUCCESS] Generated animated GIF diagram: ${outputPath} (${gifBuffer.length} bytes)`);
