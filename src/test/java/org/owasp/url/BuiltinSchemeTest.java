// Copyright (c) 2018, Mike Samuel
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

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import org.junit.Test;

@SuppressWarnings({ "static-method", "javadoc" })
public final class BuiltinSchemeTest {

  @Test
  public void testForName() throws Exception {
    int publicStaticFinal = Modifier.PUBLIC | Modifier.STATIC | Modifier.FINAL;
    int nSchemes = 0;
    for (Field f : BuiltinScheme.class.getDeclaredFields()) {
      if (publicStaticFinal == (f.getModifiers() & publicStaticFinal)
          && Scheme.class.isAssignableFrom(f.getType())) {
        Scheme scheme = (Scheme) f.get(null);
        assertTrue(f.getName(), !scheme.lcaseNames.isEmpty());
        for (String lcaseName : scheme.lcaseNames) {
          assertSame(
              f.getName() + " " + lcaseName,
              scheme,
              BuiltinScheme.forName(lcaseName));
          ++nSchemes;
        }
      }
    }
    assertTrue("" + nSchemes, nSchemes >= 10);
  }
}
