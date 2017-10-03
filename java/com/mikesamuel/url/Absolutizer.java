package com.mikesamuel.url;

import com.google.common.base.Preconditions;
import com.mikesamuel.url.Scheme.PartRanges;

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


  /** Evaluates a relative URL in the context of an absolute URL. */
  public Result absolutize(String originalUrlText) {
    int eos = endOfScheme(originalUrlText);

    Scheme scheme;
    PartRanges originalUrlRanges, absUrlRanges;
    String absUrlText;
    if (eos >= 0) {
      scheme = schemes.schemeForName(
          originalUrlText.substring(0, eos - 1 /* ':' */));
      originalUrlRanges = scheme.decompose(
          schemes, originalUrlText, eos, originalUrlText.length());
      absUrlText = originalUrlText;
      absUrlRanges = originalUrlRanges;
      if (scheme.isHierarchical && originalUrlRanges.pathRight >= 0) {
        StringBuilder sb = new StringBuilder(absUrlText.length());
        sb.append(originalUrlText, 0, originalUrlRanges.pathRight);
        removeDotSegmentsInPlace(sb, originalUrlRanges.pathLeft);
        if (sb.length() != originalUrlRanges.pathRight) {
          // Path normalization did some work.
          sb.append(originalUrlText, originalUrlRanges.pathRight, originalUrlText.length());
          absUrlText = sb.toString();
          absUrlRanges = scheme.decompose(
              schemes, absUrlText, eos, absUrlText.length());
        }
      }
    } else {
      scheme = contextScheme;
      PartRanges crs = this.contextRanges;
      PartRanges ors = originalUrlRanges = scheme.decompose(
          schemes, originalUrlText, 0, originalUrlText.length());
//      System.err.println("ors=" + ors);
      // We have an example of a well-structured absolute URL with the
      // right scheme in contextURL.
      // Compute a set of substitutions into contextURL specified as
      // (left, right, content) tuples.
      // Then substitute them.

      // Collect enough information to create a ranges object
      // so we can recompose the URL.
      int absAuthLeft = -1, absAuthRight = -1;
      int absPathLeft = -1, absPathRight = -1;
      int absQueryLeft = -1, absQueryRight = -1;
      int absFragmentLeft = -1, absFragmentRight = -1;
      int absContentMetadataLeft = -1, absContentMetadataRight = -1;
      int absContentLeft = -1, absContentRight = -1;

      // Collect parts on this buffer.
      StringBuilder partBuf = new StringBuilder(
          originalUrlText.length() + contextUrl.length());

      // True if we have used a part from the given URL instead of
      // the context URL which indicates that we should defer to the
      // given URL for subseuqent parts.
      boolean usedGivenUrlPart = false;

      if (ors.authorityLeft >= 0) {
        usedGivenUrlPart = true;
        absAuthLeft = partBuf.length();
        partBuf.append(
            originalUrlText, ors.authorityLeft, ors.authorityRight);
        absAuthRight = partBuf.length();
      } else if (crs.authorityLeft >= 0) {
        absAuthLeft = partBuf.length();
        partBuf.append(
            contextUrl, crs.authorityLeft, crs.authorityRight);
        absAuthRight = partBuf.length();
      }
//      System.err.println("ors.pathLeft=" + ors.pathLeft);
//      System.err.println("ors.pathRight=" + ors.pathRight);
//      System.err.println("crs.pathLeft=" + crs.pathLeft);
//      System.err.println("crs.pathRight=" + crs.pathRight);
//      System.err.println("usedGivenUrlPart=" + usedGivenUrlPart);
      if (ors.pathLeft < ors.pathRight || usedGivenUrlPart) {
        absPathLeft = partBuf.length();
        if (ors.pathLeft >= 0) {
          if (ors.pathLeft < ors.pathRight
              && originalUrlText.charAt(ors.pathLeft) == '/') {
            // Absolute path.
            partBuf.append(originalUrlText, ors.pathLeft, ors.pathRight);
          } else if (!usedGivenUrlPart) {
            // Relative path.
            // Append the context path.
            if (crs.pathLeft >= 0) {
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
            }
            // Append new path
            partBuf.append(originalUrlText, ors.pathLeft, ors.pathRight);
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
        removeDotSegmentsInPlace(partBuf, absPathLeft);
        absPathRight = partBuf.length();
      }
//      System.err.println("absPathRight=" + absPathRight + ", partBuf=" + partBuf);

      if (ors.contentLeft < ors.contentRight
          || ors.contentMetadataLeft < ors.contentMetadataRight
          || usedGivenUrlPart) {
        usedGivenUrlPart = true;
        if (ors.contentMetadataLeft >= 0) {
          absContentMetadataLeft = partBuf.length();
          partBuf.append(
              originalUrlText,
              ors.contentMetadataLeft, ors.contentMetadataRight);
          absContentMetadataRight = partBuf.length();
        }
        if (ors.contentLeft >= 0) {
          absContentLeft = partBuf.length();
          partBuf.append(originalUrlText, ors.contentLeft, ors.contentRight);
          absContentRight = partBuf.length();
        }
      } else if (
          (crs.contentLeft >= 0 || crs.contentMetadataLeft >= 0)
          && !usedGivenUrlPart) {
        if (crs.contentMetadataLeft >= 0) {
          absContentMetadataLeft = partBuf.length();
          partBuf.append(
              contextUrl, crs.contentMetadataLeft, crs.contentMetadataRight);
          absContentMetadataRight = partBuf.length();
        }
        if (crs.contentLeft >= 0) {
          absContentLeft = partBuf.length();
          partBuf.append(contextUrl, crs.contentLeft, crs.contentRight);
          absContentRight = partBuf.length();
        }
      }

      if (ors.queryLeft >= 0) {
        usedGivenUrlPart = true;
        absQueryLeft = partBuf.length();
        partBuf.append(originalUrlText, ors.queryLeft, ors.queryRight);
        absQueryRight = partBuf.length();
      } else if (!usedGivenUrlPart && crs.queryLeft >= 0) {
        absQueryLeft = partBuf.length();
        partBuf.append(contextUrl, crs.queryLeft, crs.queryRight);
        absQueryRight = partBuf.length();
      }

      if (ors.fragmentLeft >= 0) {
        absFragmentLeft = partBuf.length();
        partBuf.append(originalUrlText, ors.fragmentLeft, ors.fragmentRight);
        absFragmentRight = partBuf.length();
      }
      // Do not inherit fragment from context URL.

      // Seed the buffer with the scheme.
      StringBuilder recomposed = new StringBuilder(partBuf.capacity());
      recomposed.append(contextUrl, 0, contextEos);
      PartRanges ranges = new PartRanges(
          absAuthLeft, absAuthRight,
          absPathLeft, absPathRight,
          absQueryLeft, absQueryRight,
          absFragmentLeft, absFragmentRight,
          absContentLeft, absContentRight,
          absContentMetadataLeft, absContentMetadataRight
          );
      contextScheme.recompose(partBuf, ranges, recomposed);
      absUrlText = recomposed.toString();
//    System.err.println("RECOMPOSED\n\tranges=" + ranges + "\n\tsource=" + partBuf + "\n\tresult=" + absUrlText);
      absUrlRanges = scheme.decompose(
          schemes, absUrlText, contextEos, absUrlText.length());
    }

    return new Result(
        scheme, originalUrlText, originalUrlRanges, absUrlText, absUrlRanges);
  }



  /**
   * The result of absolutizing a URL along with structural information
   * found about the input and the output.
   */
  public static final class Result {
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
    public Result(
        Scheme scheme, String originalUrlText,
        PartRanges originalUrlRanges, String absUrlText, PartRanges absUrlRanges) {
      super();
      this.scheme = scheme;
      this.originalUrlText = originalUrlText;
      this.originalUrlRanges = originalUrlRanges;
      this.absUrlText = absUrlText;
      this.absUrlRanges = absUrlRanges;
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
  static void removeDotSegmentsInPlace(StringBuilder path, int left) {
    // The code below has excerpts from the spec interspersed.
    // The "input buffer" and "output buffer" referred to in the spec
    // are both just regions of path.
    // The loop deals with the exclusive cases by continuing instead
    // of proceeding to the bottom.
    boolean isAbsolute = left < path.length() && path.charAt(left) == '/';

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
          while (outputBufferEnd > outputBufferStart) {
            --outputBufferEnd;
            if (path.charAt(outputBufferEnd) == '/') { break; }
          }
          if (outputBufferEnd == outputBufferStart && !isAbsolute) {
            // !!!This differs from spec!!!
            // Do not convert relative URLs into absolute ones via parent
            // navigation.
            inputBufferStart += 1;
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
  }
}
