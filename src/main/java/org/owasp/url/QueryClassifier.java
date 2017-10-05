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
 * A URLClassifier that considers the query: <tt>http://example.com/<b>?key=value</b></tt>.
 */
public interface QueryClassifier extends URLClassifier {

  /** A new blank builder. */
  public static QueryClassifierBuilder builder() {
    return new QueryClassifierBuilder();
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static QueryClassifier or(QueryClassifier... cs) {
    return or(ImmutableList.copyOf(cs));
  }

  /**
   * A classifier that passes when applying cs in order results in a match before a
   * classification of INVALID.
   *
   * @param cs the operands.
   * @return The disjunction of cs.
   */
  public static QueryClassifier or(Iterable<? extends QueryClassifier> cs) {
    return URLClassifierOr.<QueryClassifier>abstractOr(
      cs,
      QueryClassifierOr.QP_FALSE,
      QueryClassifierOr.QP_NEW);
  }

  /** A classifier that matches all inputs. */
  public static QueryClassifier any() {
    return AnyQueryClassifier.INSTANCE;
  }
}

final class AnyQueryClassifier implements QueryClassifier {
  static final AnyQueryClassifier INSTANCE = new AnyQueryClassifier();

  @Override
  public Classification apply(
      URLValue x, Diagnostic.Receiver<? super URLValue> r) {
    return Classification.MATCH;
  }
}

final class QueryClassifierOr
extends URLClassifierOr<QueryClassifier> implements QueryClassifier {

  static final QueryClassifierOr QP_FALSE =
      new QueryClassifierOr(ImmutableList.of());

  static final Function<ImmutableList<QueryClassifier>, QueryClassifier> QP_NEW =
      new Function<ImmutableList<QueryClassifier>, QueryClassifier>() {

    @Override
    public QueryClassifier apply(ImmutableList<QueryClassifier> cs) {
      return new QueryClassifierOr(cs);
    }

  };

  QueryClassifierOr(ImmutableList<QueryClassifier> cs) {
    super(cs);
  }
}


