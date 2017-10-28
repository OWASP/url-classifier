// Copyright (c) 2017, Mike Samuel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// Neither the name of the OWASP nor the names of its contributors may
// be used to endorse or promote products derived from this software
// without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package org.owasp.url;

import java.util.Arrays;

import com.google.common.base.Optional;

/**
 * Support for percent escaping.
 */
final class Percent {
  static Optional<String> decode(String s) {
    Optional<CharSequence> csopt = decode(s, 0, s.length(), false);
    if (csopt.isPresent()) {
      return Optional.of(csopt.get().toString());
    } else {
      return Optional.absent();
    }
  }

  static Optional<CharSequence> decode(
      CharSequence s, int left, int right, boolean formEncoded) {
    StringBuilder decoded = null;
    int writtenCursor = left;  // Position between left and right written to chars

    for (int i = left; i < right; ++i) {
      char c = s.charAt(i);
      if (c == '%') {
        int b0 = pctHex2(s, i, right);
        if (b0 < 0) { return Optional.absent(); }
        int codePoint;
        int numFollowers = 0;
        int minCodepoint;
        switch ((b0 & 0xf0) >>> 4) {
          case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
            numFollowers = 0;
            codePoint = b0;
            minCodepoint = 0;
            break;
          case 12: case 13:
            numFollowers = 1;
            codePoint = b0 & 0x1f;
            minCodepoint = 0x80;
            break;
          case 14:
            numFollowers = 2;
            codePoint = b0 & 0xf;
            minCodepoint = 0x800;
            break;
          case 15:
            numFollowers = 3;
            codePoint = b0 & 0x7;
            // UTF-8 used to go up to 6 code-units but is limited to 4
            // when encoding Unicode scalar values.
            if ((b0 & 0x8) != 0) { return Optional.absent(); }
            minCodepoint = 0x10000;
            break;
          default:
            return Optional.absent();
        }
        int ip = i + 3;
        for (int j = 0; j < numFollowers; ++j) {
          if (ip >= right || '%' != s.charAt(ip)) { return Optional.absent(); }
          int bn = pctHex2(s, ip, right);
          if (bn < 0 || (bn & 0xc0) != 0x80) {
            return Optional.absent();
          }
          codePoint = (codePoint << 6) | (bn & 0x3f);
          ip += 3;
        }

        if (codePoint < minCodepoint  // Non-minimal encoding.
            || codePoint > Character.MAX_CODE_POINT
            // Not a scalar value.
            || (0xd800 <= codePoint && codePoint <= 0xdfff)) {
          return Optional.absent();
        }

        if (decoded == null) {
          decoded = new StringBuilder(right - left);
        }
        decoded.append(s, writtenCursor, i);
        writtenCursor = ip;

        decoded.appendCodePoint(codePoint);
        i = ip - 1;  // Because of ++i in loop header
      } else if (c == '+' && formEncoded) {
        if (decoded == null) {
          decoded = new StringBuilder(right - left);
        }
        decoded.append(s, writtenCursor, i).append(' ');
        writtenCursor = i + 1;
      }
    }
    if (decoded == null) {
      return Optional.of(s.subSequence(left, right));
    }

    return Optional.<CharSequence>of(decoded.append(s, writtenCursor, right));
  }

  static int pctHex2(CharSequence s, int i, int limit) {
    if (i + 2 >= limit) { return -1; }
    char h0 = s.charAt(i + 1);
    char h1 = s.charAt(i + 2);
    int d0 = h0 <= 'f' ? HEX_DIGITS[h0] : -1;
    int d1 = h1 <= 'f' ? HEX_DIGITS[h1] : -1;
    if ((d0 | d1) < 0) { return -1; }
    return (d0 << 4) | d1;
  }

  private static final int[] HEX_DIGITS = new int['f' + 1];
  static {
    Arrays.fill(HEX_DIGITS, -1);
    for (int i = '0'; i <= '9'; ++i) {
      HEX_DIGITS[i] = i - '0';
    }
    for (int i = 'A'; i <= 'F'; ++i) {
      HEX_DIGITS[i] = i - 'A' + 10;
    }
    for (int i = 'a'; i <= 'f'; ++i) {
      HEX_DIGITS[i] = i - 'a' + 10;
    }
  }
}
