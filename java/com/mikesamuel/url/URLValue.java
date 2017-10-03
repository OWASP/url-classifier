package com.mikesamuel.url;

import com.google.common.base.Preconditions;

/**
 * Bundles a URL with sufficient context to allow part-wise analysis.
 */
public final class URLValue {

  /** The context in which the URL is interpreted. */
  public final URLContext context;
  /** The original URL text. */
  public final String originalUrlText;
  /**
   * True if the authority component of the URL was not explicitly specified
   * in the original URL text and the authority is the placeholder authority.
   */
  public final boolean inheritsPlaceholderAuthority;

  /**
   * True iff simplifying the path interpreted ".." relative to "/" or "".
   * <p>
   * For example,
   * Interpreting "/../bar" relative to "http://example.com/foo/"
   * leads to simplying "http://example.com/foo/../bar" to
   * "http://example.com/bar".
   * But the "/.." is applied to "/foo" so root's parent is not reached.
   * <p>
   * On the other hand,
   * Interpreting "/../../bar" relative to "http://example.com/foo/"
   * leads to simplifying "http://example.com/foo/../../bar" to
   * "http://example.com/bar".
   * In this case, the first "/.." is applied to "/foo" and the second
   * is applied to "/" so the root's parent is reached.
   */
  public final boolean pathSimplificationReachedRootsParent;

  /** The full text of the URL after resolving against the context's base URL. */
  public final String urlText;

  private final int endOfScheme;
  /** The scheme of the URL or {@link Scheme#UNKNOWN} if not known. */
  public final Scheme scheme;

  /**
   * @param context a context used to flesh out relative URLs.
   * @return a URL value with the given original text and whose
   *     urlText is an absolute URL.
   */
  public static URLValue of(URLContext context, String originalUrlText) {
    return new URLValue(
        Preconditions.checkNotNull(context),
        Preconditions.checkNotNull(originalUrlText));
  }

  /** Uses the default context. */
  public static URLValue of(String originalUrlText) {
    return new URLValue(URLContext.DEFAULT, originalUrlText);
  }


  private URLValue(URLContext context, String originalUrlText) {
    this.context = context;
    this.originalUrlText = originalUrlText;

    int eos = Absolutizer.endOfScheme(originalUrlText);
    if (eos >= 0) {
      this.urlText = originalUrlText;
      this.endOfScheme = eos;
      this.scheme = context.absolutizer.schemes.schemeForName(
          urlText.substring(0, eos - 1 /* ':' */));
      this.inheritsPlaceholderAuthority = false;
      // Don't bother computing part ranges for a URL
      // that may fail the scheme filter.
      this.pathSimplificationReachedRootsParent = false;  // TODO: is this legit
    } else {
      Absolutizer.Result abs = context.absolutizer.absolutize(originalUrlText);
      this.scheme  = abs.scheme;
      this.urlText = abs.absUrlText;
      this.ranges = abs.absUrlRanges;
      this.pathSimplificationReachedRootsParent = abs.pathSimplificationReachedRootsParent;
      this.computedRanges = true;
      this.endOfScheme = Absolutizer.endOfScheme(this.urlText);
      final int phLen = URLContext.PLACEHOLDER_AUTHORITY.length();
      this.inheritsPlaceholderAuthority = this.ranges != null
          && abs.originalUrlRanges.authorityLeft < 0
          && this.ranges.authorityLeft >= 0
          && this.ranges.authorityRight - this.ranges.authorityLeft == phLen
          && URLContext.PLACEHOLDER_AUTHORITY.regionMatches(
              0, this.urlText, abs.absUrlRanges.authorityLeft, phLen);
    }
  }

  private boolean computedRanges;
  private Scheme.PartRanges ranges;
  /** The position of part boundaries within {@link #urlText}. */
  public Scheme.PartRanges getRanges() {
    if (!computedRanges) {
      ranges = scheme.decompose(
          context.absolutizer.schemes, urlText, endOfScheme, urlText.length());
    }
    return ranges;
  }

  private String authority;
  /** The authority or null if none is available. */
  public String getAuthority() {
    if (authority == null) {
      Scheme.PartRanges r = getRanges();
      if (r != null && r.authorityLeft >= 0) {
        authority = urlText.substring(r.authorityLeft, r.authorityRight);
      }
    }
    return authority;
  }

  private String path;
  /** The path or null if none is available. */
  public String getPath() {
    if (path == null) {
      Scheme.PartRanges r = getRanges();
      if (r != null && r.pathLeft >= 0) {
        path = urlText.substring(r.pathLeft, r.pathRight);
      }
    }
    return path;
  }

  private String query;
  /**
   * The query string or null if none is available.
   * This includes any leading '{@code ?}'.
   */
  public String getQuery() {
    if (query == null) {
      Scheme.PartRanges r = getRanges();
      if (r != null && r.queryLeft >= 0) {
        query = urlText.substring(r.queryLeft, r.queryRight);
      }
    }
    return query;
  }

  private String fragment;
  /**
   * The fragment or null if none is available.
   * This includes any leading '{@code #}'.
   */
  public String getFragment() {
    if (fragment == null) {
      Scheme.PartRanges r = getRanges();
      if (r != null && r.fragmentLeft >= 0) {
        fragment = urlText.substring(r.fragmentLeft, r.fragmentRight);
      }
    }
    return fragment;
  }


  @Override
  public boolean equals(Object o) {
    if (!(o instanceof URLValue)) {
      return false;
    }
    URLValue that = (URLValue) o;
    return this.originalUrlText.equals(that.originalUrlText)
        && this.context.equals(that.context);
  }

  @Override
  public int hashCode() {
    return originalUrlText.hashCode() + 31 * context.hashCode();
  }
}
