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

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

/** Maps scheme names like "http" or "HTTP" to Schemes. */
public final class SchemeLookupTable {
  final ImmutableMap<String, Scheme> additionalSchemes;

  /** */
  public static final SchemeLookupTable BUILTINS_ONLY =
      new SchemeLookupTable(ImmutableList.of());

  /**
   * @param additionalSchemes any schemes beyond the builtins to recognize.
   */
  public SchemeLookupTable(Iterable<? extends Scheme> additionalSchemes) {
    ImmutableMap.Builder<String, Scheme> b = ImmutableMap.builder();
    for (Scheme s : additionalSchemes) {
      for (String schemeName : s.lcaseNames) {
        b.put(schemeName, s);
      }
    }
    this.additionalSchemes = b.build();
  }

  /**
   * Looks up a scheme by name.
   * @return {@link Scheme#UNKNOWN} if schemeName is not recognized.
   */
  public Scheme schemeForName(String schemeName) {
    String lSchemeName = Ascii.toLowerCase(schemeName);
    Scheme s = additionalSchemes.get(lSchemeName);
    if (s == null) {
      s = BuiltinScheme.forName(lSchemeName);
    }
    return s != null ? s : Scheme.UNKNOWN;
  }

}
