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
 * A classifier over media types like ones found in {@code data:media/type;...}.
 * @see UrlValue#getContentMediaType()
 */
public interface MediaTypeClassifier extends UrlClassifier {

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static MediaTypeClassifier or(MediaTypeClassifier... cs) {
    return or(Arrays.asList(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static MediaTypeClassifier or(
      Iterable<? extends MediaTypeClassifier> cs) {
    return UrlClassifierOr.<MediaTypeClassifier>abstractOr(
        cs,
        MediaTypeClassifierOr.MT_FALSE,
        MediaTypeClassifierOr.MT_NEW);
  }

  /** A classifier that matches all inputs. */
  public static MediaTypeClassifier any() {
    return AnyMediaTypeClassifier.INSTANCE;
  }
}

final class AnyMediaTypeClassifier implements MediaTypeClassifier {
  static final AnyMediaTypeClassifier INSTANCE = new AnyMediaTypeClassifier();

  @Override
  public Classification apply(
      UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
    return Classification.MATCH;
  }
}

final class MediaTypeClassifierOr
extends UrlClassifierOr<MediaTypeClassifier> implements MediaTypeClassifier {

  static final MediaTypeClassifierOr MT_FALSE =
      new MediaTypeClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<MediaTypeClassifier>, MediaTypeClassifier> MT_NEW =
      new Function<ImmutableList<MediaTypeClassifier>, MediaTypeClassifier>() {

        @Override
        public MediaTypeClassifier apply(ImmutableList<MediaTypeClassifier> cs) {
          return new MediaTypeClassifierOr(cs);
        }

      };

  MediaTypeClassifierOr(ImmutableList<MediaTypeClassifier> cs) {
    super(cs);
  }

}
