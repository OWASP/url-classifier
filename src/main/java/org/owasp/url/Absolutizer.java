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

import java.util.EnumSet;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import org.owasp.url.Scheme.PartRanges;

/** Converts possibly relative URLs to absolute URLs. */
public final class Absolutizer {

  /**
   * Additional schemes recognized besides those defined in
   * {@link BuiltinScheme}.
   */
  public final SchemeLookupTable schemes;
  /**
   * An absolute, hierarchical URL that serves as the base for relative URLs.
   */
  public final String contextUrl;
  final Scheme contextScheme;
  final PartRanges contextRanges;
  final int contextEos;

  /**
   * @param schemes looks up schemes by name.
   * @param contextUrl An absolute, hierarchical URL that serves as the base
   *   for relative URLs.
   * @throws IllegalArgumentException if the contextUrl is malformed, relative,
   *   or uses an unrecognized scheme.
   */
  public Absolutizer(SchemeLookupTable schemes, String contextUrl) {
    this.schemes = schemes;
    this.contextUrl = contextUrl;

    int eos = endOfScheme(contextUrl);
    Preconditions.checkArgument(eos >= 0, "Missing scheme", contextUrl);
    this.contextEos = eos;
    this.contextScheme =
        schemes.schemeForName(contextUrl.substring(0, eos - 1 /* ':' */));
    Preconditions.checkArgument(
        Scheme.UNKNOWN != this.contextScheme,
        "Context URL has unrecognized scheme", contextUrl);
    this.contextRanges = Preconditions.checkNotNull(
        contextScheme.decompose(schemes, contextUrl, eos, contextUrl.length()),
        "Malformed context URL", contextUrl);
  }


  /**
   * Evaluates a URL reference in the context of an absolute URL.
   *
   * @param refUrlText The URL to absolutize.
   * @return A bundle of information gleaned from the absolutizing process.
   */
  Result absolutize(String refUrlText) {
    int eos = endOfScheme(refUrlText);
    boolean pathSimplificationReachedRootsParent = false;
    EnumSet<UrlValue.UrlSpecCornerCase> cornerCases = EnumSet.noneOf(
        UrlValue.UrlSpecCornerCase.class);

    Scheme scheme;
    PartRanges refUrlRanges, absUrlRanges;
    String absUrlText;
    if (eos >= 0) {
      scheme = schemes.schemeForName(
          refUrlText.substring(0, eos - 1 /* ':' */));
      refUrlRanges = scheme.decompose(
          schemes, refUrlText, eos, refUrlText.length());
      absUrlText = refUrlText;
      absUrlRanges = refUrlRanges;
      if (scheme.isHierarchical && refUrlRanges.pathRight >= 0) {
        StringBuilder sb = new StringBuilder(refUrlText.length());
        sb.append(refUrlText, 0, refUrlRanges.pathRight);
        pathSimplificationReachedRootsParent = removeDotSegmentsInPlace(
            sb, refUrlRanges.pathLeft, cornerCases);
        if (sb.length() != refUrlRanges.pathRight) {
          // Path normalization did some work.
          sb.append(refUrlText, refUrlRanges.pathRight, refUrlText.length());
          absUrlText = sb.toString();
          absUrlRanges = scheme.decompose(
              schemes, absUrlText, eos, absUrlText.length());
        }
      }
    } else {
      scheme = contextScheme;
      PartRanges crs = this.contextRanges;
      PartRanges rrs = refUrlRanges = scheme.decompose(
          schemes, refUrlText, 0, refUrlText.length());
//      System.err.println("ors=" + ors);
      // We have an example of a well-structured absolute URL with the
      // right scheme in contextURL.
      // Compute a set of substitutions into contextURL specified as
      // (left, right, content) tuples.
      // Then substitute them.

      // Collect enough information to create a ranges object
      // so we can recompose the URL.
      PartRanges.Builder abs = new PartRanges.Builder();

      // Collect parts on this buffer.
      StringBuilder partBuf = new StringBuilder(
          refUrlText.length() + contextUrl.length());

      // True if we have used a part from the given URL instead of
      // the context URL which indicates that we should defer to the
      // given URL for subseuqent parts.
      boolean usedGivenUrlPart = false;

      if (rrs.authorityLeft >= 0) {
        usedGivenUrlPart = true;
        int absAuthLeft = partBuf.length();
        partBuf.append(
            refUrlText, rrs.authorityLeft, rrs.authorityRight);
        abs.withAuthority(absAuthLeft, partBuf.length());
      } else if (crs.authorityLeft >= 0) {
        int absAuthLeft = partBuf.length();
        partBuf.append(
            contextUrl, crs.authorityLeft, crs.authorityRight);
        abs.withAuthority(absAuthLeft, partBuf.length());
      }
//      System.err.println("ors.pathLeft=" + ors.pathLeft);
//      System.err.println("ors.pathRight=" + ors.pathRight);
//      System.err.println("crs.pathLeft=" + crs.pathLeft);
//      System.err.println("crs.pathRight=" + crs.pathRight);
//      System.err.println("usedGivenUrlPart=" + usedGivenUrlPart);
      int absPathLeft = -1;
      if (rrs.pathLeft < rrs.pathRight || usedGivenUrlPart) {
        absPathLeft = partBuf.length();
        if (rrs.pathLeft >= 0) {
          if (rrs.pathLeft < rrs.pathRight
              && refUrlText.charAt(rrs.pathLeft) == '/') {
            // Absolute path.
            partBuf.append(refUrlText, rrs.pathLeft, rrs.pathRight);
          } else if (!usedGivenUrlPart) {
            // Relative path.
            // Append the context path.
            if (crs.pathLeft < crs.pathRight) {
              partBuf.append(contextUrl, crs.pathLeft, crs.pathRight);
              // Truncate at last '/'.
              // Absolutizing "foo" relative to "/bar/baz" is "/bar/foo"
              // but "foo" relative to "/bar/baz/" is "/bar/baz/foo".
              boolean truncated = false;
              for (int i = partBuf.length(); --i >= absPathLeft;) {
                if (partBuf.charAt(i) == '/') {
                  partBuf.setLength(i + 1);
                  truncated = true;
                  break;
                }
              }
              if (!truncated) {
                partBuf.setLength(absPathLeft);
              }
            } else if (crs.authorityLeft >= 0) {
              // https://tools.ietf.org/html/rfc3986#section-5.2.3 "Merge Paths" says
              // > If the base URI has a defined authority component and an empty
              // > path, then return a string consisting of "/" concatenated with the
              // > reference's path.
              partBuf.append('/');
            }
            // Append new path
            partBuf.append(refUrlText, rrs.pathLeft, rrs.pathRight);
          }
        }
        usedGivenUrlPart = true;
      } else if (crs.pathLeft >= 0) {
        absPathLeft = partBuf.length();
        partBuf.append(contextUrl, crs.pathLeft, crs.pathRight);
      }
      // Fixup . and ..
//      System.err.println("absPathLeft=" + absPathLeft + ", partBuf=" + partBuf);
      if (absPathLeft >= 0) {
        if (fixupEncodedDots(partBuf, absPathLeft)) {
          cornerCases.add(UrlValue.UrlSpecCornerCase.ENCODED_DOT_PATH_SEGMENST);
        }
        pathSimplificationReachedRootsParent = removeDotSegmentsInPlace(
            partBuf, absPathLeft, cornerCases);
        abs.withPath(absPathLeft, partBuf.length());
      }
//      System.err.println("absPathRight=" + absPathRight + ", partBuf=" + partBuf);

      if (rrs.contentLeft < rrs.contentRight
          || rrs.contentMetadataLeft < rrs.contentMetadataRight
          || usedGivenUrlPart) {
        usedGivenUrlPart = true;
        if (rrs.contentMetadataLeft >= 0) {
          int absContentMetadataLeft = partBuf.length();
          partBuf.append(
              refUrlText,
              rrs.contentMetadataLeft, rrs.contentMetadataRight);
          abs.withContentMetadata(absContentMetadataLeft, partBuf.length());
        }
        if (rrs.contentLeft >= 0) {
          int absContentLeft = partBuf.length();
          partBuf.append(refUrlText, rrs.contentLeft, rrs.contentRight);
          abs.withContent(absContentLeft, partBuf.length());
        }
      } else if (
          (crs.contentLeft >= 0 || crs.contentMetadataLeft >= 0)
          && !usedGivenUrlPart) {
        if (crs.contentMetadataLeft >= 0) {
          int absContentMetadataLeft = partBuf.length();
          partBuf.append(
              contextUrl, crs.contentMetadataLeft, crs.contentMetadataRight);
          abs.withContentMetadata(absContentMetadataLeft, partBuf.length());
        }
        if (crs.contentLeft >= 0) {
          int absContentLeft = partBuf.length();
          partBuf.append(contextUrl, crs.contentLeft, crs.contentRight);
          abs.withContent(absContentLeft, partBuf.length());
        }
      }

      if (rrs.queryLeft >= 0) {
        usedGivenUrlPart = true;
        int absQueryLeft = partBuf.length();
        partBuf.append(refUrlText, rrs.queryLeft, rrs.queryRight);
        abs.withQuery(absQueryLeft, partBuf.length());
      } else if (!usedGivenUrlPart && crs.queryLeft >= 0) {
        int absQueryLeft = partBuf.length();
        partBuf.append(contextUrl, crs.queryLeft, crs.queryRight);
        abs.withQuery(absQueryLeft, partBuf.length());
      }

      if (rrs.fragmentLeft >= 0) {
        int absFragmentLeft = partBuf.length();
        partBuf.append(refUrlText, rrs.fragmentLeft, rrs.fragmentRight);
        abs.withFragment(absFragmentLeft, partBuf.length());
      }
      // Do not inherit fragment from context URL.

      // Seed the buffer with the scheme.
      StringBuilder recomposed = new StringBuilder(partBuf.capacity());
      recomposed.append(contextUrl, 0, contextEos);
      PartRanges ranges = abs.build();
      contextScheme.recompose(partBuf, ranges, recomposed);
      absUrlText = recomposed.toString();
//    System.err.println("RECOMPOSED\n\tranges=" + ranges + "\n\tsource=" + partBuf + "\n\tresult=" + absUrlText);
      absUrlRanges = scheme.decompose(
          schemes, absUrlText, contextEos, absUrlText.length());
    }

    if (contextRanges.authorityLeft < 0 && refUrlRanges.authorityLeft < 0
        && absUrlRanges.pathRight - absUrlRanges.pathLeft >= 2
        && '/' == absUrlText.charAt(absUrlRanges.pathLeft)
        && '/' == absUrlText.charAt(absUrlRanges.pathLeft + 1)) {
      cornerCases.add(UrlValue.UrlSpecCornerCase.PATH_AUTHORITY_AMBIGUITY);
    }

    return new Result(
        scheme, refUrlText, refUrlRanges, absUrlText, absUrlRanges,
        pathSimplificationReachedRootsParent, cornerCases);
  }



  /**
   * The result of absolutizing a URL along with structural information
   * found about the input and the output.
   */
  static final class Result {
    /** */
    public final Scheme scheme;
    /** */
    public final String originalUrlText;
    /** */
    public final PartRanges originalUrlRanges;
    /** */
    public final String absUrlText;
    /** */
    public final PartRanges absUrlRanges;
    /** */
    public final boolean pathSimplificationReachedRootsParent;

    public final ImmutableSet<UrlValue.UrlSpecCornerCase> cornerCases;

    /** */
    public Result(
        Scheme scheme, String originalUrlText,
        PartRanges originalUrlRanges, String absUrlText, PartRanges absUrlRanges,
        boolean pathSimplificationReachedRootsParent,
        EnumSet<UrlValue.UrlSpecCornerCase> cornerCases) {
      this.scheme = scheme;
      this.originalUrlText = originalUrlText;
      this.originalUrlRanges = originalUrlRanges;
      this.absUrlText = absUrlText;
      this.absUrlRanges = absUrlRanges;
      this.pathSimplificationReachedRootsParent = pathSimplificationReachedRootsParent;
      this.cornerCases = Sets.immutableEnumSet(cornerCases);
    }
  }


  static int endOfScheme(String urlText) {
    int n = urlText.length();
    for (int i = 0; i < n; ++i) {
      char c = urlText.charAt(i);
      if (c == ':' && i != 0) {
        return i + 1;
      } else if (c == '/' || c == '?' || c == '#') {
        return -1;
      }
    }
    return -1;
  }

  private static final boolean DEBUG_RDS = false;
  /**
   * @return true iff a "prefix/" or "/prefix/" before path[:left]
   *     would have been removed because of ".." handling were it present.
   */
  static boolean removeDotSegmentsInPlace(StringBuilder path, int left,
      EnumSet<UrlValue.UrlSpecCornerCase> cornerCases) {
    // The code below has excerpts from the spec interspersed.
    // The "input buffer" and "output buffer" referred to in the spec
    // are both just regions of path.
    // The loop deals with the exclusive cases by continuing instead
    // of proceeding to the bottom.
    boolean isAbsolute = left < path.length() && path.charAt(left) == '/';
    boolean dotDotNavigatesPastRoot = false;

    // RFC 3986 Section 5.2.4
    // 1.  The input buffer is initialized with the now-appended path
    //     components and the output buffer is initialized to the empty
    //     string.
    int inputBufferStart = left;
    final int inputBufferEnd = path.length();
    final int outputBufferStart = left;
    int outputBufferEnd = left;

    // 2.  While the input buffer is not empty, loop as follows:
    while (inputBufferStart < inputBufferEnd) {
      if (DEBUG_RDS) {
        System.err.println(
            "\t[" + path.substring(outputBufferStart, outputBufferEnd) + "]" +
                path.substring(outputBufferEnd, inputBufferStart) + "[" +
                path.substring(inputBufferStart, inputBufferEnd) + "]");
      }

      char c0 = path.charAt(inputBufferStart);
      //     A.  If the input buffer begins with a prefix of "../" or "./",
      //         then remove that prefix from the input buffer; otherwise,
      if (c0 == '.') {
        char c1;
        if (inputBufferStart + 1 < inputBufferEnd) {
          if ('/' == (c1 = path.charAt(inputBufferStart + 1))) {
            inputBufferStart += 2;
            continue;
          }
          if ('.' == c1 && inputBufferStart + 2 < inputBufferEnd
              && '/' == path.charAt(inputBufferStart + 2)) {
            inputBufferStart += 3;
            dotDotNavigatesPastRoot = true;
            continue;
          }
        }
      }

      //     B.  if the input buffer begins with a prefix of "/./" or "/.",
      //         where "." is a complete path segment, then replace that
      //         prefix with "/" in the input buffer; otherwise,
      if (c0 == '/' && inputBufferStart + 1 < inputBufferEnd
          && '.' == path.charAt(inputBufferStart + 1)) {
        if (inputBufferStart + 2 == inputBufferEnd) {
          inputBufferStart += 1;
          path.setCharAt(inputBufferStart, '/');
          continue;
        } else if ('/' == path.charAt(inputBufferStart + 2)) {
          inputBufferStart += 2;
          continue;
        }
      }

      //     C.  if the input buffer begins with a prefix of "/../" or "/..",
      //         where ".." is a complete path segment, then replace that
      //         prefix with "/" in the input buffer and remove the last
      //         segment and its preceding "/" (if any) from the output
      //         buffer; otherwise,
      if (c0 == '/' && inputBufferStart + 2 < inputBufferEnd
          && '.' == path.charAt(inputBufferStart + 1)
          && '.' == path.charAt(inputBufferStart + 2)) {
        boolean foundDotDot = false;
        if (inputBufferStart + 3 == inputBufferEnd) {
          inputBufferStart += 2;
          path.setCharAt(inputBufferStart, '/');
          foundDotDot = true;
        } else if ('/' == path.charAt(inputBufferStart + 3)) {
          inputBufferStart += 3;
          foundDotDot = true;
        }
        if (foundDotDot) {
          switch (outputBufferEnd - outputBufferStart) {
            // !!Extra not found in spec!!
            case 0:
              dotDotNavigatesPastRoot = true;
              break;
            case 1:
              if ('/' == path.charAt(outputBufferStart)) {
                dotDotNavigatesPastRoot = true;
              }
              break;
          }
          while (outputBufferEnd > outputBufferStart) {
            --outputBufferEnd;
            if (path.charAt(outputBufferEnd) == '/') { break; }
          }
          if (outputBufferEnd == outputBufferStart && !isAbsolute) {
            // !!!This differs from spec!!!
            // Do not convert relative URLs into absolute ones via parent
            // navigation.
            inputBufferStart += 1;
            cornerCases.add(
                UrlValue.UrlSpecCornerCase.RELATIVE_URL_MERGED_TO_ABSOLUTE);
          }
          continue;
        }
      }

      //     D.  if the input buffer consists only of "." or "..", then remove
      //         that from the input buffer; otherwise,
      if (c0 == '.') {
        if (inputBufferStart + 1 == inputBufferEnd) {
          inputBufferStart += 1;
          continue;
        } else if (inputBufferStart + 2 == inputBufferEnd
                   && '.' == path.charAt(inputBufferStart + 1)) {
          inputBufferStart += 2;
          dotDotNavigatesPastRoot = true;
          continue;
        }
      }

      //     E.  move the first path segment in the input buffer to the end of
      //         the output buffer, including the initial "/" character (if
      //         any) and any subsequent characters up to, but not including,
      //         the next "/" character or the end of the input buffer.
      do {
        path.setCharAt(outputBufferEnd++, path.charAt(inputBufferStart++));
      } while (inputBufferStart < inputBufferEnd
               && path.charAt(inputBufferStart) != '/');
    }

    // 3.  Finally, the output buffer is returned as the result of
    //     remove_dot_segments.
    path.setLength(outputBufferEnd);

    return dotDotNavigatesPastRoot;
  }

  static final boolean RECODE_ENCODED_SPECIAL_PATH_SEGMENTS = false;
  static boolean fixupEncodedDots(StringBuilder partBuf, int pathLeft) {
    boolean needCompactLeft = false;
    boolean foundEncodedDotSegment = false;
    // We could, recode "%2e" to "." and similarly for double dots.
    // Enable the flag above to experiment with this.

    // We walk left to right and when we find a path segment that decodes to
    // "." or "..", but contains an encoded dot, we replace it in place.
    // We then compact left.
    // This works because both "." and ".." are strictly shorter than
    // the encoded form.
    int writeCursor = pathLeft;

    for (int i = pathLeft, n = partBuf.length(); i < n; ++i) {
      if (encodedDotAt(partBuf, i)) {
        // Look for a . or endoded dot to the left.
        int leftBound = i - 1 < pathLeft
            ? i
            : partBuf.charAt(i - 1) == '.'
            ? i - 1
            : i - 3 >= pathLeft && encodedDotAt(partBuf, i - 3)
            ? i - 3
            : i;
        int rightBound = leftBound != i || i + 3 == n
            ? i + 3
            : '.' == partBuf.charAt(i + 3)
            ? i + 4
            : encodedDotAt(partBuf, i + 3) ? i + 6 : i + 3;

        // We now know that partBuf[leftBound:rightBound] decodes to
        // "." or ".." with at least one dot encoded.
        if ((leftBound == pathLeft || partBuf.charAt(leftBound - 1) == '/')
            && (rightBound == n || partBuf.charAt(rightBound) == '/')) {
          foundEncodedDotSegment = true;
          if (RECODE_ENCODED_SPECIAL_PATH_SEGMENTS) {
            needCompactLeft = true;
            partBuf.setCharAt(writeCursor, '.');
            ++writeCursor;
            if (leftBound == i && rightBound != i + 3) {
              partBuf.setCharAt(writeCursor, '.');
              ++writeCursor;
            }
          }

          i = rightBound - 1;  // Don't bother considering this again.
          continue;
        }
      }

      // Compact left
      if (needCompactLeft) {
        partBuf.setCharAt(writeCursor, partBuf.charAt(i));
        ++writeCursor;
      }
    }
    if (needCompactLeft) {
      partBuf.setLength(writeCursor);  // Finish compacting left
    }

    return foundEncodedDotSegment;
  }

  private static boolean encodedDotAt(StringBuilder partBuf, int i) {
    return i + 2 < partBuf.length()
        && '%' == partBuf.charAt(i)
        && '2' == partBuf.charAt(i + 1)
        && 'e' == (partBuf.charAt(i + 2) | 32);
  }

}
