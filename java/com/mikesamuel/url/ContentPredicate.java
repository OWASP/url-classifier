package com.mikesamuel.url;

import java.nio.ByteBuffer;

import com.google.common.collect.ImmutableList;

/** A URL predicate that checks the content portion of a non-hierarchical URL.  */
public interface ContentPredicate {
  Classification applyToTextContent(CharSequence chars);
  Classification applyToBinaryContent(ByteBuffer bytes);

  public static ContentPredicate or(ContentPredicate... ps) {
    return or(ImmutableList.copyOf(ps));
  }
  public static ContentPredicate or(Iterable<? extends ContentPredicate> ps) {

  }
}
