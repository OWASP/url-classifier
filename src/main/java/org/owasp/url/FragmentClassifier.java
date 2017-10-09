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

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * A URLClassifier that considers the fragment: <tt>http://example.com/<b>#fragment</b></tt>.
 *
 * <p>This may be used in a larger {@link UrlClassifier} via
 * {@link UrlClassifierBuilder#fragment}.
 */
public interface FragmentClassifier extends UrlClassifier {

  /** A new blank builder. */
  public static FragmentClassifierBuilder builder() {
    return new FragmentClassifierBuilder();
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static FragmentClassifier or(FragmentClassifier... cs) {
    return or(Arrays.asList(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static FragmentClassifier or(Iterable<? extends FragmentClassifier> cs) {
    return UrlClassifierOr.<FragmentClassifier>abstractOr(
        cs,
        FragmentClassifierOr.FP_FALSE,
        FragmentClassifierOr.FP_NEW);
  }

  /** A classifier that matches all inputs. */
  public static FragmentClassifier any() {
    return AnyFragmentClassifier.INSTANCE;
  }
}

final class AnyFragmentClassifier implements FragmentClassifier {
  static final AnyFragmentClassifier INSTANCE = new AnyFragmentClassifier();

  @Override
  public Classification apply(
      UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
    return Classification.MATCH;
  }
}

final class FragmentClassifierOr
extends UrlClassifierOr<FragmentClassifier> implements FragmentClassifier {

  static final FragmentClassifierOr FP_FALSE =
      new FragmentClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<FragmentClassifier>, FragmentClassifier> FP_NEW =
      new Function<ImmutableList<FragmentClassifier>, FragmentClassifier>() {

        @Override
        public FragmentClassifier apply(ImmutableList<FragmentClassifier> cs) {
          return new FragmentClassifierOr(cs);
        }

      };

  FragmentClassifierOr(ImmutableList<FragmentClassifier> cs) {
    super(cs);
  }

}
