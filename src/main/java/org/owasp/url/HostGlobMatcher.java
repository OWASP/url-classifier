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

import java.util.List;
import java.util.Map;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.common.net.InternetDomainName;

/** Collects host globs together for quicker matching. */
final class HostGlobMatcher {

  /** We group globs by the kinds of ambiguity they allow. */
  static final class Group {
    final boolean anySubdomain;  // Starts with **.
    final boolean aSubdomain;  // Starts with *.
    final boolean anyPublicSuffix;  // Ends with a public suffix
    /** A suffix trie over host parts. */
    final Trie<String, Boolean> middleParts;

    Group(
        boolean anySubdomain,
        boolean aSubdomain,
        boolean anyPublicSuffix,
        Trie<String, Boolean> middleParts) {
      this.anySubdomain = anySubdomain;
      this.aSubdomain = aSubdomain;
      this.anyPublicSuffix = anyPublicSuffix;
      this.middleParts = middleParts;
    }
  }

  private final ImmutableList<Group> groups;

  HostGlobMatcher(Iterable<? extends HostGlob> globs) {
    @SuppressWarnings("unchecked")
    Map<List<String>, Boolean>[] byBits = new Map[8];
    for (HostGlob glob : globs) {
      int i = (glob.anyPublicSuffix ? 1 : 0)
          | (glob.anySubdomain ? 2 : 0)
          | (glob.aSubdomain ? 4 : 0);
      if (byBits[i] == null) {
        byBits[i] = Maps.newHashMap();
      }
      byBits[i].put(glob.middleParts.reverse(), true);
    }
    ImmutableList.Builder<Group> b = ImmutableList.builder();
    for (int i = 0; i < byBits.length; ++i) {
      if (byBits[i] == null) { continue; }
      boolean anyPublicSuffix = 0 != (i & 1);
      boolean anySubdomain = 0 != (i & 2);
      boolean aSubdomain = 0 != (i & 4);
      Group g = new Group(
          anySubdomain, aSubdomain, anyPublicSuffix,
          Trie.from(ImmutableList.copyOf(byBits[i].entrySet())));
      b.add(g);
    }
    this.groups = b.build();
  }

  boolean matches(InternetDomainName name) {
    ImmutableList<String> parts = name.parts();
//    System.err.println("parts=" + parts);
    int nParts = parts.size();
    int publicSuffixSize = -1;
    next_group:
    for (Group g : groups) {
//      System.err.println("\tGroup " + g.middleParts + ", anySubdomain=" + g.anySubdomain);
      int right = nParts;
      int left = 0;
      if (g.anyPublicSuffix) {
        if (name.hasPublicSuffix()) {
          if (publicSuffixSize == -1) {
            publicSuffixSize = name.publicSuffix().parts().size();
          }
          right -= publicSuffixSize;
        } else {
          continue next_group;
        }
      }
      if (g.aSubdomain) { ++left; }
      if (left > right) { continue; }
      Trie<String, Boolean> t = g.middleParts;
//      System.err.println("\t\tComparing " + parts.subList(left, right));
      if (g.anySubdomain) {
        boolean sawPartial = false;
        for (int i = right; --i >= left;) {
          sawPartial = sawPartial || Boolean.TRUE.equals(t.value);
          Trie<String, Boolean> child = t.els.get(parts.get(i));
          if (child == null) {
            break;
          }
          t = child;
        }
//        System.err.println("\t\tsawParital=" + sawPartial + ", t=" + t + ", value=" + t.value);
        if (sawPartial) { return true; }
        // Case where we have a complete match handled below.
      } else {
        for (int i = right; --i >= left;) {
          Trie<String, Boolean> child = t.els.get(parts.get(i));
          if (child == null) {
            continue next_group;
          }
          t = child;
        }
      }
      if (Boolean.TRUE.equals(t.value)) { return true; }
    }
    return false;
  }
}