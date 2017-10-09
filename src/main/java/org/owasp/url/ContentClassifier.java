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

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;

/**
 * A URL classifier that checks the content and content-metadata portions
 * of a non-hierarchical URL.
 *
 * @see UrlValue#getDecodedContent()
 */
public interface ContentClassifier extends UrlClassifier {

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static ContentClassifier or(ContentClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static ContentClassifier or(Iterable<? extends ContentClassifier> cs) {
    return UrlClassifierOr.abstractOr(
        cs, ContentClassifierOr.FP_FALSE,
        new Function<ImmutableList<ContentClassifier>, ContentClassifier>() {

          @Override
          public ContentClassifier apply(ImmutableList<ContentClassifier> flat) {
            return new ContentClassifierOr(flat);
          }

        });
  }

  /**
   * A classifier that matches all inputs.
   */
  public static ContentClassifier any() {
    return AnyContentClassifier.INSTANCE;
  }
}

final class AnyContentClassifier implements ContentClassifier {
  static final AnyContentClassifier INSTANCE = new AnyContentClassifier();

  @Override
  public Classification apply(
      UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
    return Classification.MATCH;
  }
}

final class ContentClassifierOr
extends UrlClassifierOr<ContentClassifier> implements ContentClassifier {

  static final ContentClassifierOr FP_FALSE =
      new ContentClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<ContentClassifier>, ContentClassifier> FP_NEW =
      new Function<ImmutableList<ContentClassifier>, ContentClassifier>() {

        @Override
        public ContentClassifier apply(ImmutableList<ContentClassifier> cs) {
          return new ContentClassifierOr(cs);
        }

      };

  ContentClassifierOr(ImmutableList<ContentClassifier> cs) {
    super(cs);
  }
}
