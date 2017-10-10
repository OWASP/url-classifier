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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.LinkedListMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import com.google.common.net.InternetDomainName;
import com.google.common.net.MediaType;

/**
 * A URL reference that can be examined piecewise.
 */
public final class UrlValue {

  /**
   * An oddity in the URL spec (STD 66/RFC 3986) that would
   * probably not be there if it could be redrafted without concern
   * for backwards compatibility or spec complexity.
   * <p>
   * If we rely on other URL consumers interpreting the
   * {@link UrlValue#originalUrlText original URL text} according to spec,
   * (instead of using {@link UrlValue#urlText} which is tweaked to avoid
   * corner cases) then those consumers might behave in different/unintended
   * ways.
   * <p>
   * Additionally, different URL consumers come to different conclusions
   * about what the spec says in some cases.
   */
  public enum UrlSpecCornerCase {
    /**
     * When the special path components ({@code .} and {@code ..}) are
     * percent-encoded, different URL consumers behave in different ways.
     * <p>
     * The spec requires that encoded dots not be considered part of the
     * special path components.
     * <p>
     * Still, {@code %2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd} is a hazard.
     *
     * @see <a href="https://bugzilla.mozilla.org/show_bug.cgi?id=1042347">Mozilla bug 1042347</a>
     */
    ENCODED_DOT_PATH_SEGMENST,
    /**
     * {@code file://bar} has authority "bar" but can be the result of
     * resolving a path-relative URL {@code .//bar} against a context URL
     * with no authority, {@code file:/}.
     * <p>
     * @see <a href="https://tools.ietf.org/html/rfc8089#appendix-E.3.1">
     *     RFC 8089: E.3.1. &lt;file&gt; URI with Authority
     * </a>
     */
    PATH_AUTHORITY_AMBIGUITY,
    /**
     * The <a href="https://tools.ietf.org/html/rfc3986#section-5.2.4"><i>remove_dot_segments</i></a>
     * spec method simplifies "{@code .}" and "{@code ..}" path segments out of a merged path.
     * Merging two relative paths can lead to an absolute path.
     * For example, "{@code ../bar}" relative to "{@code file:foo/}" invokes
     * {@code remove_dot_segments("foo/../baz')} which yields {@code "/bar"}.
     */
    RELATIVE_URL_MERGED_TO_ABSOLUTE,
    /**
     * Per {@link UrlContext.MicrosoftPathStrategy}, some backslashes were flipped to
     * forward slashes.
     */
    FLIPPED_SLASHES,
  }

  /** The context in which the URL is interpreted. */
  public final UrlContext context;
  /** The original URL text.  May be relative. */
  public final String originalUrlText;

  /**
   * True if the authority component of the URL was not explicitly specified
   * in the original URL text and the authority is the placeholder authority.
   *
   * @see UrlContext#PLACEHOLDER_AUTHORITY
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

  /** The full text of the URL after resolving against the base URL. */
  public final String urlText;

  /** The scheme of the URL or {@link Scheme#UNKNOWN} if not known. */
  public final Scheme scheme;
  /**
   * The position of part boundaries within {@link #urlText} or null.
   * It is null when the scheme specific part does not follow the
   * additional rules for that scheme.
   *
   * <p>For example, the ranges are null for "{@code data:text/plain}"
   * because the "{@code data:}" scheme requires a comma between the
   * media-type ("{@code text/plain}") and the content but there is none.
   */
  public final Scheme.PartRanges ranges;
  /**
   * Corner cases that might cause {@link #originalUrlText} to be
   * interpreted differently by different URL consumers.
   *
   * @see UrlClassifierBuilder#tolerate
   */
  public final ImmutableSet<UrlSpecCornerCase> cornerCases;

  /**
   * @param context a context used to flesh out relative URLs.
   * @return a URL value with the given original text and whose
   *     urlText is an absolute URL.
   */
  public static UrlValue from(UrlContext context, String originalUrlText) {
    String urlText = originalUrlText;
    switch (context.urlSource) {
      case HUMAN_READABLE_INPUT:
        if (urlText.indexOf(':') < 0) {
          String prefix = null;
          String suffix = null;
          String hostPortion = null;
          int at = urlText.indexOf('@');
          if (at >= 0) {
            prefix = "mailto:";
            suffix = "";
            hostPortion = urlText.substring(at + 1);
          } else {
            int slash = urlText.indexOf('/');
            prefix = "http://";
            hostPortion = slash >= 0 ? urlText.substring(0, slash) : urlText;
            suffix = slash < 0 ? "/" : "";
          }
          if (hostPortion != null) {
            InternetDomainName dname;
            try {
              dname = InternetDomainName.from(hostPortion);
            } catch (@SuppressWarnings("unused")
                     IllegalArgumentException ex) {
              dname = null;
            }
            if (dname != null && dname.hasPublicSuffix()) {
              urlText = prefix + urlText + suffix;
            }
          }
        }
        break;
      case MACHINE_READABLE_INPUT:
        break;
    }
    return new UrlValue(
        Preconditions.checkNotNull(context),
        Preconditions.checkNotNull(urlText));
  }

  /** Uses the default context. */
  public static UrlValue from(String originalUrlText) {
    return from(UrlContext.DEFAULT, originalUrlText);
  }


  private UrlValue(UrlContext context, String originalUrlText) {
    this.context = context;
    this.originalUrlText = originalUrlText;

    String refUrlText = originalUrlText;
    boolean flippedSlashes = false;
    switch (context.microsoftPathStrategy) {
      case BACK_TO_FORWARD:
        int eos = Absolutizer.endOfScheme(refUrlText);
        @SuppressWarnings("hiding")
        Scheme scheme = null;
        if (eos >= 0) {
          scheme = context.absolutizer.schemes.schemeForName(
              refUrlText.substring(0, eos - 1 /* ':' */));
        }
        if (scheme == null || scheme.isHierarchical) {
          refUrlText = refUrlText.replace('\\', '/');
          flippedSlashes = !refUrlText.equals(originalUrlText);
        }
        break;
      case STANDARDS_COMPLIANT:
        break;
    }

    Absolutizer.Result abs = context.absolutizer.absolutize(refUrlText);
    this.scheme  = abs.scheme;
    this.urlText = abs.absUrlText;
    this.ranges = abs.absUrlRanges;
    this.pathSimplificationReachedRootsParent = abs.pathSimplificationReachedRootsParent;
    final int phLen = UrlContext.PLACEHOLDER_AUTHORITY.length();
    this.inheritsPlaceholderAuthority = this.ranges != null
        && abs.originalUrlRanges.authorityLeft < 0
        && this.ranges.authorityLeft >= 0
        && this.ranges.authorityRight - this.ranges.authorityLeft == phLen
        && UrlContext.PLACEHOLDER_AUTHORITY.regionMatches(
            0, this.urlText, abs.absUrlRanges.authorityLeft, phLen);
    ImmutableSet<UrlSpecCornerCase> allCornerCases = abs.cornerCases;
    if (flippedSlashes) {
      EnumSet<UrlSpecCornerCase> ccs = EnumSet.noneOf(UrlSpecCornerCase.class);
      ccs.addAll(allCornerCases);
      ccs.add(UrlSpecCornerCase.FLIPPED_SLASHES);
      allCornerCases = Sets.immutableEnumSet(ccs);
    }
    this.cornerCases = allCornerCases;
  }

  private Optional<String> rawAuthority;
  /** The authority or null if none is available. */
  public String getRawAuthority() {
    if (rawAuthority == null) {
      rawAuthority = Optional.absent();
      if (ranges != null && ranges.authorityLeft >= 0) {
        rawAuthority = Optional.of(
            urlText.substring(ranges.authorityLeft, ranges.authorityRight));
      }
    }
    return rawAuthority.orNull();
  }

  private Optional<Authority> authority;
  /** The decoded authority or null if none is available. */
  public Authority getAuthority(Diagnostic.Receiver<? super UrlValue> r) {
    if (authority == null) {
      authority = Optional.absent();
      if (getRawAuthority() != null) {
        Authority auth = Authority.decode(this, r);
        authority = Optional.fromNullable(auth);
        return auth;
      }
    }
    if (r != Diagnostic.Receiver.NULL
        && rawAuthority.isPresent() && !authority.isPresent()) {
      // Replay error messages.
      Authority.decode(this, r);
    }
    return authority.orNull();
  }

  private Optional<String> rawPath;
  /** The path or null if none is available. */
  public String getRawPath() {
    if (rawPath == null) {
      rawPath = Optional.absent();
      if (ranges != null && ranges.pathLeft >= 0) {
        rawPath = Optional.of(
            urlText.substring(ranges.pathLeft, ranges.pathRight));
      }
    }
    return rawPath.orNull();
  }

  private String query;
  /**
   * The query string or null if none is available.
   * This includes any leading '{@code ?}'.
   */
  public String getQuery() {
    if (query == null) {
      if (ranges != null && ranges.queryLeft >= 0) {
        query = urlText.substring(ranges.queryLeft, ranges.queryRight);
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
      if (ranges != null && ranges.fragmentLeft >= 0) {
        fragment = urlText.substring(ranges.fragmentLeft, ranges.fragmentRight);
      }
    }
    return fragment;
  }

  private String contentMetadata;
  /**
   * The contentMetadata or null if none is available.
   * This includes any leading '{@code #}'.
   */
  public String getContentMetadata() {
    if (contentMetadata == null) {
      if (ranges != null && ranges.contentMetadataLeft >= 0) {
        contentMetadata = urlText.substring(
            ranges.contentMetadataLeft, ranges.contentMetadataRight);
      }
    }
    return contentMetadata;
  }

  private Optional<MediaType> mediaTypeOpt;
  /**
   * The media type for the associated content if specified in
   * the content metadata, or null if not available.
   */
  public MediaType getContentMediaType() {
    if (mediaTypeOpt == null) {
      mediaTypeOpt = Optional.absent();
      if (scheme == BuiltinScheme.DATA) {
        String metadata = getContentMetadata();
        if (metadata != null) {
          mediaTypeOpt = DataSchemeMediaTypeUtil.parseMediaTypeFromDataMetadata(
              metadata);
        }
      }
    }
    return mediaTypeOpt.orNull();
  }

  private Optional<String> rawContent;
  /**
   * The raw content string or null if not available.
   */
  public String getRawContent() {
    if (rawContent == null) {
      rawContent = Optional.absent();
      if (ranges.contentLeft >= 0) {
        rawContent = Optional.of(urlText.substring(
            ranges.contentLeft, ranges.contentRight));
      }
    }
    return rawContent.orNull();
  }

  private Optional<Object> decodedContent;
  /**
   * The decoded content.
   *
   * @return A CharSequence if the content is textual,
   *      a ByteBuffer if binary, or
   *      null if not available.
   */
  public Object getDecodedContent() {
    if (decodedContent == null) {
      decodedContent = Optional.absent();
      if (ranges.contentLeft >= 0) {
        decodedContent = Optional.<Object>fromNullable(
            scheme.decodeContent(urlText, ranges));
      }
    }
    return decodedContent.orNull();
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof UrlValue)) {
      return false;
    }
    UrlValue that = (UrlValue) o;
    return this.originalUrlText.equals(that.originalUrlText)
        && this.context.equals(that.context);
  }

  @Override
  public int hashCode() {
    return originalUrlText.hashCode() + 31 * context.hashCode();
  }

  @Override
  public String toString() {
    return urlText;
  }
}


final class DataSchemeMediaTypeUtil {
  /**
   * RFC 2397 defines mediatype thus
   * """
   *         mediatype  := [ type "/" subtype ] *( ";" parameter )
   *         ...
   *         parameter  := attribute "=" value
   *     where ... "type", "subtype", "attribute" and "value" are
   *     the corresponding tokens from [RFC2045], represented using
   *     URL escaped encoding of [RFC2396] as necessary.
   * """
   * so we need to percent decode after identifying the "/" and ";"
   * boundaries.
   * <p>
   * In addition, parameter values may be quoted-strings per RFC 822
   * which allows \-escaping.
   * It is unclear whether quotes can be %-escaped.
   * <p>
   * A strict reading of this means that a ',' or ';' in a quoted
   * string is part of the parameter value.
   */
  private static final Pattern MEDIA_TYPE_PATTERN = Pattern.compile(
      ""
      + "^"
      + "([^/;\"]+)"  // type in group 1
      + "/"
      + "([^/;\"]+)"   // type in group 2
      + "("   // parameters in group 3
      +   "(?:[;]"  // each parameter is preceded by a semicolon
      +     "(?!=base64(?:;|\\z))"  // base64 is not a media type parameter.
      +     "(?:"
      +       "[^;\"%]"  // one character in a parameter key or value
      +       "|(?:\"|%22)(?:[^\\\\\"%]|\\\\.|%5c.|%(?!=22|5c))*(?:\"|%22)"  // quoted-string
      +       "|%(?!=22|5c)"  // encoded non-meta character
      +     ")*"  // end key=value loop
      +   ")*"  // end parameter loop
      + ")",  // end group 3
      Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

  static Optional<MediaType> parseMediaTypeFromDataMetadata(
      String contentMetadata) {
    Matcher m = MEDIA_TYPE_PATTERN.matcher(contentMetadata);
    if (!m.find()) {
      return Optional.absent();
    }
    String type = Percent.decode(m.group(1)).orNull();
    String subtype = Percent.decode(m.group(2)).orNull();
    if (type == null || subtype == null) {
      return Optional.absent();
    }
    MediaType mt;
    try {
      mt = MediaType.create(type, subtype);
    } catch (@SuppressWarnings("unused") IllegalArgumentException ex) {
      return Optional.absent();
    }

    String parameters = m.group(3);
    if (parameters != null) {
      Multimap<String, String> parameterValues = LinkedListMultimap.create();
      for (String parameter : parameters.split(";")) {
        if (parameter.isEmpty()) { continue; }
        int eq = parameter.indexOf('=');
        if (eq < 0) {
          return Optional.absent();
        }
        String key = Percent.decode(parameter.substring(0, eq)).orNull();
        String value = Percent.decode(parameter.substring(eq + 1)).orNull();
        if (key == null || value == null) {
          return Optional.absent();
        }
        value = maybeDecodeRfc822QuotedString(value);
        parameterValues.put(key, value);
      }
      try {
        mt = mt.withParameters(parameterValues);
      } catch (@SuppressWarnings("unused") IllegalArgumentException ex) {
        return Optional.absent();
      }
    }

    return Optional.of(mt);
  }

  private static String maybeDecodeRfc822QuotedString(String tokenOrQuotedString) {
    int n = tokenOrQuotedString.length();
    if (n >= 2 && '"' == tokenOrQuotedString.charAt(0)
        && '"' == tokenOrQuotedString.charAt(n - 1)) {
      StringBuilder sb = new StringBuilder(n - 2);
      for (int i = 1; i < n - 1; ++i) {
        char c = tokenOrQuotedString.charAt(i);
        if (c == '\\' && i + 1 < n) {
          sb.append(tokenOrQuotedString.charAt(i + 1));
          ++i;
        } else {
          sb.append(c);
        }
      }
      return sb.toString();
    }
    return tokenOrQuotedString;
  }

}