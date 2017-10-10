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

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

/**
 * Builds a classifier over the fragment content.
 * <p>
 * The built classifier will match no fragments unless one of the match
 * methods is called.  If multiple are called, it will match if any of the
 * supplied predicates or classifiers matches.
 * A predicate, p, is considered matching if {@code p.apply(x)} is true.
 *
 * @see FragmentClassifiers#builder
 */
public final class FragmentClassifierBuilder {
  private UrlClassifier asRelativeUrlPred;
  private Predicate<? super Optional<String>> fragmentPred;

  static final UrlClassifier MATCH_NO_URLS = UrlClassifiers.or();

  FragmentClassifierBuilder() {
    // Use static factory
  }

  /**
   * Builds a classifier based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built classifiers.
   */
  public FragmentClassifier build() {
    Predicate<? super Optional<String>> fragmentClassifier = this.fragmentPred;
    UrlClassifier asRelativeUrlClassifier = this.asRelativeUrlPred;
    if (fragmentClassifier == null) {
      fragmentClassifier = Predicates.alwaysFalse();
    }
    if (asRelativeUrlClassifier == null) {
      asRelativeUrlClassifier = MATCH_NO_URLS;
    }
    return new FragmentClassifierImpl(fragmentClassifier, asRelativeUrlClassifier);
  }

  /**
   * If there is no fragment then p will receive the absent optional.
   * If there is a fragment then p will receive it with the leading "#".
   * RFC 3986 says
   * <blockquote>
   *    two URIs that differ only by the suffix "#" are considered
   *    different regardless of the scheme.
   * </blockquote>
   */
  public FragmentClassifierBuilder match(Predicate<? super Optional<String>> p) {
    if (this.fragmentPred == null) {
      this.fragmentPred = p;
    } else {
      this.fragmentPred = Predicates.or(this.fragmentPred, p);
    }
    return this;
  }

  /**
   * It's not uncommon for single-page applications to embed a path in a query.
   * URLs will match when there is a fragment whose content (sans "#") parses
   * as a relative URL that matches p in the context of
   * http://[special-unkown-host]/
   *
   * <p>By "relative," we mean not absolute per RFC 3986.  An absolute path is
   * still a relative URL by this scheme since it specifies no scheme.
   *
   * <p>This requires that the fragment will be present, so to allow
   * no fragment OR the fragments described above, use FragmentClassifier.or(...).
   */
  public FragmentClassifierBuilder matchAsUrl(UrlClassifier p) {
    this.asRelativeUrlPred = this.asRelativeUrlPred == null
        ? p
        : UrlClassifiers.or(this.asRelativeUrlPred, p);
    return this;
  }
}


final class FragmentClassifierImpl implements FragmentClassifier {
  final Predicate<? super Optional<String>> fragmentClassifier;
  final UrlClassifier asRelativeUrlClassifier;

  FragmentClassifierImpl(
      Predicate<? super Optional<String>> fragmentClassifier,
      UrlClassifier asRelativeUrlClassifier) {
    this.fragmentClassifier = Preconditions.checkNotNull(fragmentClassifier);
    this.asRelativeUrlClassifier = Preconditions.checkNotNull(asRelativeUrlClassifier);
  }

  @Override
  public Classification apply(
      UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
    String fragment = x.getFragment();
    Classification result = Classification.NOT_A_MATCH;
    Optional<String> fragmentOpt = Optional.fromNullable(fragment);
    if (this.fragmentClassifier.apply(fragmentOpt)) {
      result = Classification.MATCH;
    }
    if (fragment != null
        && result == Classification.NOT_A_MATCH
        && !FragmentClassifierBuilder.MATCH_NO_URLS.equals(
            this.asRelativeUrlClassifier)) {
      UrlValue fragmentUrl = UrlValue.from(
          // Explicitly do not use x's path.
          UrlContext.DEFAULT, fragment.substring(1));
      switch (this.asRelativeUrlClassifier.apply(fragmentUrl, r)) {
        case INVALID:
          return Classification.INVALID;
        case MATCH:
          result = Classification.MATCH;
          break;
        case NOT_A_MATCH:
          break;
      }
    }
    return result;
  }

}
