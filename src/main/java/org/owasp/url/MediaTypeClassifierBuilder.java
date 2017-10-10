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
import java.util.Set;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableTable;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;
import com.google.common.net.MediaType;

/**
 * A builder for {@link MediaTypeClassifier}s.
 */
public final class MediaTypeClassifierBuilder {

  MediaTypeClassifierBuilder() {
    // Static factory.
  }

  /** Media type <code>*<!-- -->/*</code> */
  private boolean allowAny;
  private final ImmutableSet.Builder<MediaType> mediaTypes = ImmutableSet.builder();

  /**
   * Builds a classifier based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built classifiers.
   */
  public MediaTypeClassifier build() {
    if (allowAny) {
      return MediaTypeClassifiers.any();
    }

    return new MediaTypeClassifierImpl(mediaTypes.build());
  }


  /**
   * Allows any media type that matches the given type/subtype per
   * <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html">
   * Accept header semantics</a>.
   *
   * @param type like "text"
   * @param subtype like "plain" in "text/plain"
   * @return this.
   */
  public MediaTypeClassifierBuilder type(String type, String subtype) {
    return type(MediaType.create(type, subtype));
  }

  /**
   * Allows any media type that matches the given types per
   * <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html">
   * Accept header semantics</a>.
   *
   * @param mts to allow.  May include wildcard types.
   * @return this
   */
  public MediaTypeClassifierBuilder type(MediaType... mts) {
    return type(Arrays.asList(mts));
  }

  /**
   * Allows any media type that matches the given types per
   * <a href="https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html">
   * Accept header semantics</a>.
   *
   * @param mts to allow.  May include wildcard types.
   * @return this
   */
  public MediaTypeClassifierBuilder type(Iterable<? extends MediaType> mts) {
    for (MediaType mediaType : mts) {
      if (MediaType.ANY_TYPE.equals(mediaType)) {
        allowAny = true;
      } else {
        mediaTypes.add(mediaType);
      }
    }
    return this;
  }

}


final class MediaTypeClassifierImpl implements MediaTypeClassifier {
  private final ImmutableTable<String, String, ImmutableSet<MediaType>> types;

  MediaTypeClassifierImpl(Iterable<? extends MediaType> mts) {
    Table<String, String, Set<MediaType>> typeTable =
        HashBasedTable.<String, String, Set<MediaType>>create();
    for (MediaType mt : mts) {
      String type = mt.type();
      String subtype = mt.subtype();
      Set<MediaType> typeSet = typeTable.get(type, subtype);
      if (typeSet == null) {
        typeSet = Sets.newLinkedHashSet();
        typeTable.put(type, subtype, typeSet);
      }
      typeSet.add(mt);
    }

    ImmutableTable.Builder<String, String, ImmutableSet<MediaType>> b =
        ImmutableTable.builder();
    for (Table.Cell<String, String, Set<MediaType>> cell
         : typeTable.cellSet()) {
      b.put(cell.getRowKey(), cell.getColumnKey(), ImmutableSet.copyOf(cell.getValue()));
    }
    this.types = b.build();
  }

  enum Diagnostics implements Diagnostic {
    MISSING_MEDIA_TYPE,
    WILDCARD,
    WITHIN_NO_RANGES,
  }

  @Override
  public Classification apply(
      UrlValue x, Diagnostic.Receiver<? super UrlValue> r) {
    MediaType t = x.getContentMediaType();
    if (t == null) {
      r.note(Diagnostics.MISSING_MEDIA_TYPE, x);
      return Classification.INVALID;
    }
    String type = t.type();
    String subtype = t.subtype();

    if ("*".equals(type) || "*".equals(subtype)) {
      r.note(Diagnostics.WILDCARD, x);
      return Classification.INVALID;
    }

    if (anyRangeMatches(t, types.get(type, subtype))
        || anyRangeMatches(t, types.get(type, "*"))
        || anyRangeMatches(t, types.get("*", "*"))) {
      return Classification.MATCH;
    }

    r.note(Diagnostics.WITHIN_NO_RANGES, x);
    return Classification.NOT_A_MATCH;
  }

  private static boolean anyRangeMatches(
      MediaType t, ImmutableSet<MediaType> ranges) {
    if (ranges != null) {
      for (MediaType range : ranges) {
        if (t.is(range)) {
          return true;
        }
      }
    }
    return false;
  }

}
