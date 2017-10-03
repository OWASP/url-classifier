package com.mikesamuel.url;

import java.util.Arrays;
import java.util.EnumSet;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;

/**
 * Encapsulates knowledge about how to recognize a scheme in a URL and
 * how to decompose the URL into parts that can be further checked.
 */
public class Scheme {
  /** The lower-case names by which the Scheme is known. */
  public final ImmutableSet<String> lcaseNames;
  /**
   * True if the URL is hierarchical.
   * https://tools.ietf.org/html/rfc3986#section-1.2.3
   * <blockquote>
   * The URI syntax is organized hierarchically, with components listed in
   * order of decreasing significance from left to right.  For some URI
   * schemes, the visible hierarchy is limited to the scheme itself:
   * everything after the scheme component delimiter (":") is considered
   * opaque to URI processing.  Other URI schemes make the hierarchy
   * explicit and visible to generic parsing algorithms.
   * </blockquote>
   */
  public final boolean isHierarchical;
  /** True iff the scheme allows for an authority component. */
  public final boolean naturallyHasAuthority;
  /** True iff the scheme allows for a path component. */
  public final boolean naturallyHasPath;
  /** True iff the scheme allows for a query component. */
  public final boolean naturallyHasQuery;
  /** True iff the scheme embeds content. */
  public final boolean naturallyEmbedsContent;
  /**
   * True iff the scheme has a default port associated with it which is used
   * when the authority does not explicitly mention one.
   */
  public final int defaultPortOrNegOne;

  /** An unknown scheme that may be used for hierarchical URLs. */
  public static final Scheme UNKNOWN = new Scheme(
      ImmutableSet.of(),
      true, -1, SchemePart.AUTHORITY, SchemePart.PATH, SchemePart.QUERY) {
    @Override
    public String toString() {
      return "::UNKNOWN::";
    }
  };

  /**
   */
  public Scheme(
      ImmutableSet<String> lcaseNames,
      boolean isHierarchical, int defaultPortOrNegOne,
      SchemePart... parts) {
    EnumSet<SchemePart> partSet = EnumSet.noneOf(SchemePart.class);
    partSet.addAll(Arrays.asList(parts));
    this.lcaseNames = lcaseNames;
    this.isHierarchical = isHierarchical;
    this.defaultPortOrNegOne = defaultPortOrNegOne;
    this.naturallyEmbedsContent = partSet.contains(SchemePart.CONTENT);
    this.naturallyHasAuthority = partSet.contains(SchemePart.AUTHORITY);
    this.naturallyHasPath = partSet.contains(SchemePart.PATH);
    this.naturallyHasQuery = partSet.contains(SchemePart.QUERY);
  }

  /** Character ranges of parts of a URL.  Ranges are left-inclusive, right-exclusive. */
  public static final class PartRanges {
    /** Left (inclusive) of authority in the scheme specific part or -1. */
    public final int authorityLeft;
    /** Right (exclusive) of authority in the scheme specific part or -1. */
    public final int authorityRight;
    /** Left (inclusive) of path in the scheme specific part or -1. */
    public final int pathLeft;
    /** Right (exclusive) of path in the scheme specific part or -1. */
    public final int pathRight;
    /** Left (inclusive) of query in the scheme specific part or -1. */
    public final int queryLeft;
    /** Right (exclusive) of query in the scheme specific part or -1. */
    public final int queryRight;
    /** Left (inclusive) of fragment in the scheme specific part or -1. */
    public final int fragmentLeft;
    /** Right (exclusive) of fragment in the scheme specific part or -1. */
    public final int fragmentRight;
    /** Left (inclusive) of content in the scheme specific part or -1. */
    public final int contentLeft;
    /** Right (exclusive) of content in the scheme specific part or -1. */
    public final int contentRight;
    /** Left (inclusive) of content metadata in the scheme specific part or -1. */
    public final int contentMetadataLeft;
    /** Right (exclusive) of content metadata in the scheme specific part or -1. */
    public final int contentMetadataRight;

    /** */
    public PartRanges(
        int authorityLeft, int authorityRight,
        int pathLeft, int pathRight,
        int queryLeft, int queryRight,
        int fragmentLeft, int fragmentRight,
        int contentLeft, int contentRight,
        int contentMetadataLeft, int contentMetadataRight) {
      this.authorityLeft = authorityLeft;
      this.authorityRight = authorityRight;
      this.pathLeft = pathLeft;
      this.pathRight = pathRight;
      this.queryLeft = queryLeft;
      this.queryRight = queryRight;
      this.fragmentLeft = fragmentLeft;
      this.fragmentRight = fragmentRight;
      this.contentLeft = contentLeft;
      this.contentRight = contentRight;
      this.contentMetadataLeft = contentMetadataLeft;
      this.contentMetadataRight = contentMetadataRight;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append("(PartRanges");
      if (authorityLeft != -1) {
        sb.append(" authority:[")
            .append(authorityLeft).append('-')
            .append(authorityRight).append(')');
      }
      if (pathLeft != -1) {
        sb.append(" path:[")
            .append(pathLeft).append('-')
            .append(pathRight).append(')');
      }
      if (queryLeft != -1) {
        sb.append(" query:[")
            .append(queryLeft).append('-')
            .append(queryRight).append(')');
      }
      if (fragmentLeft != -1) {
        sb.append(" fragment:[")
            .append(fragmentLeft).append('-')
            .append(fragmentRight).append(')');
      }
      if (contentLeft != -1) {
        sb.append(" content:[")
            .append(contentLeft).append('-')
            .append(contentRight).append(')');
      }
      if (contentMetadataLeft != -1) {
        sb.append(" contentMetadata:[")
            .append(contentMetadataLeft).append('-')
            .append(contentMetadataRight).append(')');
      }
      return sb.append(')').toString();
    }
  }


  /**
   * Identifies ranges of structures within the URL.
   * @param schemes may be used to further decompose when a URLs embeds
   *     other URLs in its scheme specific part.
   */
  public PartRanges decompose(
      SchemeLookupTable schemes,
      String schemeSpecificPart, int left, int right) {
    int authorityLeft = -1, authorityRight = -1;
    int pathLeft = -1, pathRight = -1;
    int queryLeft = -1, queryRight = -1;
    int fragmentLeft = -1, fragmentRight = -1;
    int contentLeft = -1, contentRight = -1;
    int contentMetadataLeft = -1, contentMetadataRight = -1;

    if (isHierarchical) {
      int cursor = left;
      if (cursor + 2 < right
          && schemeSpecificPart.charAt(cursor) == '/'
          && schemeSpecificPart.charAt(cursor + 1) == '/') {
        cursor += 2;
        authorityLeft = cursor;

        for (; cursor < right; ++cursor) {
          char ch = schemeSpecificPart.charAt(cursor);
          if (ch == '/' || ch == '?' || ch == '#') {
            break;
          }
        }
        authorityRight = cursor;
      }

      pathLeft = cursor;
      for (; cursor < right; ++cursor) {
        char ch = schemeSpecificPart.charAt(cursor);
        if (ch == '?' || ch == '#') {
          break;
        }
      }
      pathRight = cursor;

      if (cursor < right && schemeSpecificPart.charAt(cursor) == '?') {
        queryLeft = cursor;
        for (; cursor < right; ++cursor) {
          char ch = schemeSpecificPart.charAt(cursor);
          if (ch == '#') {
            break;
          }
        }
        queryRight = cursor;
      }

      if (cursor < right) {
        Preconditions.checkState(schemeSpecificPart.charAt(cursor) == '#');
        fragmentLeft = cursor;
        fragmentRight = cursor = right;
      }
    } else {
      int hash = -1;
      for (int i = left; i < right; ++i) {
        if (schemeSpecificPart.charAt(i) == '#') {
          hash = i;
          break;
        }
      }
      contentLeft = left;
      contentRight = hash >= 0 ? hash : right;
      if (hash >= 0) {
        fragmentLeft = hash;
        fragmentRight = right;
      }
    }
    return new PartRanges(
        authorityLeft, authorityRight,
        pathLeft, pathRight,
        queryLeft, queryRight,
        fragmentLeft, fragmentRight,
        contentLeft, contentRight,
        contentMetadataLeft, contentMetadataRight);
  }

  /** Appends a scheme specific part onto out using the ranges into source. */
  public void recompose(CharSequence source, PartRanges ranges, StringBuilder out) {
    Preconditions.checkArgument(
        ranges.contentLeft < 0 && ranges.contentMetadataLeft < 0);
    boolean wroteAuth = false;
    int al = ranges.authorityLeft;
    int ar = ranges.authorityRight;
//    System.err.println("al=" + al + ", ar=" + ar + ", this.naturallyHasAuthority=" + this.naturallyHasAuthority);
    if (al >= 0 || this.naturallyHasAuthority) {
      out.append("//");
      if (al >= 0) {
        out.append(source, al, ar);
      }
      wroteAuth = true;
    }

    int pl = ranges.pathLeft;
    int pr = ranges.pathRight;
    //    System.err.println("wroteAuth=" + wroteAuth);
    //    System.err.println("source=" + source);
    //    System.err.println("pl=" + pr);
    //    System.err.println("pr=" + pl);
    if (pl >= 0 && pl != pr) {
      if (wroteAuth && source.charAt(pl) != '/') {
        // Make sure a relative path part doesn't merge into the
        // authority.
        out.append('/');
      } else if (!wroteAuth && pl + 1 < pr && '/' == source.charAt(pl)) {
        // If the path starts with "//" make sure it is not ambiguous with
        // an authority.
        out.append("//");
        wroteAuth = true;
      }
      out.append(source, pl, pr);
    }
    //    System.err.println("out=" + out);

    int ql = ranges.queryLeft;
    int qr = ranges.queryRight;
    recomposeQuery(source, ql, qr, out);

    int fl = ranges.fragmentLeft;
    int fr = ranges.fragmentRight;
    recomposeFragment(source, fl, fr, out);
  }

  static void recomposeQuery(
      CharSequence source, int queryLeft, int queryRight, StringBuilder out) {
    if (queryLeft >= 0) {
      if (queryLeft < queryRight && '?' != source.charAt(queryLeft)) {
        out.append('?');
      }
      out.append(source, queryLeft, queryRight);
    }
  }

  static void recomposeFragment(
      CharSequence source, int fragmentLeft, int fragmentRight,
      StringBuilder out) {
    if (fragmentLeft >= 0) {
      if (fragmentLeft < fragmentRight && '#' != source.charAt(fragmentLeft)) {
        out.append('#');
      }
      out.append(source, fragmentLeft, fragmentRight);
    }
  }

  /** Decodes the content if any.  May be either a CharSequence or a byte[]. */
  @SuppressWarnings("static-method")
  public Optional<?> decodeContent(String schemeSpecificPart, PartRanges ranges) {
    return defaultDecodeContent(schemeSpecificPart, ranges);
  }

  static final Optional<CharSequence> defaultDecodeContent(
      String schemeSpecificPart, PartRanges ranges) {
    if (ranges.contentLeft < 0) { return Optional.absent(); }
    return PctDecode.of(
        schemeSpecificPart, ranges.contentLeft, ranges.contentRight, false);
  }

  /** A part of a scheme */
  public static enum SchemePart {
    /** */
    AUTHORITY,
    /** */
    PATH,
    /** */
    QUERY,
    /** */
    CONTENT,
  }

  @Override
  public String toString() {
    return lcaseNames.iterator().next();
  }
}
