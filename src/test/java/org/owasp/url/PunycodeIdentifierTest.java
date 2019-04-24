// Copyright (c) 2019, Trent Miller
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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Testing for mixed scripts only
 * https://unicode.org/cldr/utility/confusables.jsp is a useful resource for generating test strings
 */
@SuppressWarnings({ "javadoc", "static-method" })
public final class PunycodeIdentifierTest {
  private PunycodeIdentifier identifier;

  @Before
  public void before() {
    identifier = PunycodeIdentifierBuilder.DEFAULT;
  }

  @Test
  public void testEmptyString() {
    assertFalse(identifier.isPotentialHomograph(""));
  }

  @Test
  public void testSingleScript() {
    assertFalse(identifier.isPotentialHomograph("google.com"));
  }

  @Test
  public void testCyrillic() {
    assertFalse(identifier.isPotentialHomograph("foo.Ьаг.com")); // Cryllic only homograph of 'bar'
  }

  @Test
  public void testCyrillicTld() {
    assertFalse(identifier.isPotentialHomograph("foo.bar.рф"));
  }

  @Test
  public void testGreek() {
    assertFalse(identifier.isPotentialHomograph("αρ.com")); // Greek only homograph of 'ap'
  }

  @Test
  public void testLatinPlusCyrillic() {
    assertTrue(identifier.isPotentialHomograph("gоogle.com")); // first 'o' is a Cyrillic small letter o, 043E
  }

  @Test
  public void testLatinPlusGreek() {
    assertTrue(identifier.isPotentialHomograph("gοogle.com")); // first 'o' is a Greek small omicron, 03BF
  }

  @Test
  public void testLatinPlusOther() {
    assertFalse(identifier.isPotentialHomograph("googוe.com")); // 'l' is replaced by the Hebrew letter vav, 05D5
  }

  @Test
  public void testLatinPlusTwo() {
    assertTrue(identifier.isPotentialHomograph("gಂgוe.com")); // 'oo' is replaced by single Kannada sign anusvara, 0CB2, and 'l' is replaced by Hebrew vav
  }

  @Test
  public void testHanSimplified() {
    assertFalse(identifier.isPotentialHomograph("买无.com")); // Han simplified characters for 'buy' and  'nothing'
  }

  @Test
  public void testHanTraditional() {
    assertFalse(identifier.isPotentialHomograph("買無.com")); // Han traditional characters for 'buy' and  'nothing'
  }

  @Test
  public void testHanHiraganaKatakana() {
    assertFalse(identifier.isPotentialHomograph("电おオ.com")); // Han character for electricity, Hiragana 304A, and Katakana 30AA
  }

  @Test
  public void testHanBopomofo() {
    assertFalse(identifier.isPotentialHomograph("买无ㄊ.com")); // Bopomofo 310A
  }

  @Test
  public void testHanHangul() {
    assertFalse(identifier.isPotentialHomograph("买无ᄊ.com")); // Hangul 110A
  }

  @Test
  public void testHanBopomofoHangul() {
    assertTrue(identifier.isPotentialHomograph("买无ㄊᄊ.com"));
  }

  @Test
  public void testHanLatinHiraganaKatakana() {
    assertFalse(identifier.isPotentialHomograph("cool-website-电おオ.com"));
  }

  @Test
  public void testHanHiraganaKatakanaPlusOther() {
    assertTrue(identifier.isPotentialHomograph("Ꮟ电おオ.com")); // Cherokee letter si, 13CF
  }
}
