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

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSortedMap;
import com.google.common.collect.Lists;

final class Trie<T extends Comparable<T>, V> {
  final ImmutableSortedMap<T, Trie<T, V>> els;
  final V value;

  Trie(ImmutableSortedMap<T, Trie<T, V>> els, V value) {
    this.els = els;
    this.value = value;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    toStringBuilder(sb);
    return sb.toString();
  }

  private void toStringBuilder(StringBuilder sb) {
    sb.append('(');
    if (els.isEmpty()) {
      sb.append("(/)");
    } else {
      boolean first = true;
      for (Map.Entry<T, Trie<T, V>> e : els.entrySet()) {
        if (first) {
          first = false;
        } else {
          sb.append(" | ");
        }
        sb.append(e.getKey()).append(' ');
        e.getValue().toStringBuilder(sb);
      }
    }
    if (value != null) {
      sb.append(" => " + value);
    }
    sb.append(')');
  }

  static <T extends Comparable<T>, V>
  Trie<T, V> from(List<Map.Entry<List<T>, V>> entries) {
    List<Map.Entry<List<T>, V>> entriesSorted = Lists.newArrayList(entries);
    Collections.sort(
        entriesSorted,
        new Comparator<Map.Entry<List<T>, V>>() {

          @Override
          public int compare(Map.Entry<List<T>, V> a, Map.Entry<List<T>, V> b) {
            List<T> aList = a.getKey();
            int aSize = aList.size();
            List<T> bList = b.getKey();
            int bSize = bList.size();
            int minSize = Math.min(aSize, bSize);
            for (int i = 0; i < minSize; ++i) {
              int delta = aList.get(i).compareTo(bList.get(i));
              if (delta != 0) { return delta; }
            }
            return aSize - bSize;
          }

        });
    return collate(entriesSorted, 0, 0, entriesSorted.size());
  }

  static <T extends Comparable<T>, V>
  Trie<T, V> collate(List<Map.Entry<List<T>, V>> entries, int depth, int left, int right) {
    V value = null;
    ImmutableSortedMap.Builder<T, Trie<T, V>> b = ImmutableSortedMap.naturalOrder();

    int childLeft = left;
    Map.Entry<List<T>, V> leftEntry = null;
    if (left != right) {
      leftEntry = entries.get(childLeft);
      if (leftEntry.getKey().size() == depth) {
        value = leftEntry.getValue();
        ++childLeft;
        leftEntry = childLeft < right
            ? Preconditions.checkNotNull(entries.get(childLeft)) : null;
      }
    }

    if (childLeft < right) {
      T keyAtDepth = Preconditions.checkNotNull(leftEntry).getKey().get(depth);
      for (int i = childLeft + 1; i < right; ++i) {
        Map.Entry<List<T>, V> e = entries.get(i);
        T k = e.getKey().get(depth);
        if (keyAtDepth.compareTo(k) != 0) {
          b.put(keyAtDepth, collate(entries, depth + 1, childLeft, i));
          childLeft = i;
          keyAtDepth = k;
        }
      }
      if (childLeft < right) {
        b.put(keyAtDepth, collate(entries, depth + 1, childLeft, right));
      }
    }

    return new Trie<T, V>(b.build(), value);
  }
}
