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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.Character.UnicodeScript.*;

/**
 * A builder for {@link PunycodeIdentifier}s.
 */
public final class PunycodeIdentifierBuilder {

  public static final PunycodeIdentifier DEFAULT
      = new PunycodeIdentifierImpl();

  /**
   * Builds a punycode identifier.
   */
  public PunycodeIdentifier build() {
    return new PunycodeIdentifierImpl();
  }
}

/**
 * Checks for homographs via combinations of unicode scripts
 * Approximates the mixed-script detection portion of Mozilla's punycode detection algorithm outlined at https://wiki.mozilla.org/IDN_Display_Algorithm
 * Does not yet incorporate individual character checking as recommended by https://tools.ietf.org/html/rfc5892
 * Reference: https://www.unicode.org/reports/tr39
 */
final class PunycodeIdentifierImpl implements PunycodeIdentifier {
  private final List<Character.UnicodeScript> ignorableScripts = Arrays.asList(COMMON, INHERITED);
  private final List<Character.UnicodeScript> uniqueScripts = Arrays.asList(CYRILLIC, GREEK);
  private final List<List<Character.UnicodeScript>> hanScripts = Arrays.asList(
      Arrays.asList(LATIN, HAN, HIRAGANA, KATAKANA),
      Arrays.asList(LATIN, HAN, BOPOMOFO),
      Arrays.asList(LATIN, HAN, HANGUL)
  );

  @Override
  public boolean isPotentialHomograph(String name) {
    final String[] parts = name.split("\\.");

    if (parts.length > 0) { // evaluate sub domains, domain, and tld independently
      for (String part : parts) {
        if (isPotentialHomographPart(part)) {
          return true;
        }
      }

      return false;
    } else {
      return isPotentialHomographPart(name);
    }
  }

  private boolean isPotentialHomographPart(String part) {
    final List<Character.UnicodeScript> scripts = new ArrayList<>();

    for (int i = 0; i < part.length(); ) {
      int codepoint = part.codePointAt(i);
      final Character.UnicodeScript script = Character.UnicodeScript.of(codepoint);

      if (!ignorableScripts.contains(script) && !scripts.contains(script)) {
        scripts.add(script);

        if (scripts.size() > 1 && isInvalidMix(scripts)) {
          return true;
        }
      }

      i += Character.charCount(codepoint);
    }

    return false;
  }

  private boolean isInvalidMix(List<Character.UnicodeScript> scripts) {
    return mixedGreekOrCyrillic(scripts) || (!isValidLatin(scripts) && !isValidHan(scripts));
  }

  // May not mix Cyrillic or Greek with another script
  private boolean mixedGreekOrCyrillic(List<Character.UnicodeScript> scripts) {
    return scripts.stream().anyMatch(uniqueScripts::contains);
  }

  // Latin script may be near universally combined with one other script
  private boolean isValidLatin(List<Character.UnicodeScript> scripts) {
    return scripts.size() <= 2 && scripts.stream().anyMatch(s -> s == LATIN);
  }

  // Han may be part of several script combinations
  private boolean isValidHan(List<Character.UnicodeScript> scripts) {
    return hanScripts.stream().anyMatch(h -> scripts.size() <= h.size() && h.containsAll(scripts));
  }
}
