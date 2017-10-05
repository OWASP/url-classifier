package org.owasp.url;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

import com.google.common.base.Ascii;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import org.owasp.url.Scheme.SchemePart;

/**
 * Schemes available by default.
 *
 * @see SchemeLookupTable
 */
public final class BuiltinScheme {
  private BuiltinScheme() {
    // static API
  }

  /** https://wiki.whatwg.org/wiki/URL_schemes#about:_URLs */
  public static final Scheme ABOUT = new OpaqueSchemeWithQuery("about");

  /** See https://www.w3.org/TR/FileAPI/#DefinitionOfScheme */
  public static final Scheme BLOB = new Scheme(
      ImmutableSet.of("blob"), false, -1, SchemePart.AUTHORITY, SchemePart.CONTENT) {
    @Override
    public PartRanges decompose(
        SchemeLookupTable schemes,
        String schemeSpecificPart, int left, int right) {
      PartRanges.Builder b = new PartRanges.Builder();

      int lastSlash = -1;
      int fragmentLeft = -1;
      for (int i = right; --i >= left;) {
        char c = schemeSpecificPart.charAt(i);
        if (c == '#') {
          lastSlash = -1;
          fragmentLeft = i;
          b.withFragment(fragmentLeft, right);
        } else if (c == '/' && lastSlash == -1) {
          lastSlash = i;
        }
      }
      if (lastSlash >= 0) {
        int originLeft = left;
        int originRight = lastSlash + 1;
        b.withContent(originRight, fragmentLeft >= 0 ? fragmentLeft : right);
        // Expect the origin to be a URL with an authority and path
        // like http://quth/path/
        for (int i = originLeft; i < originRight; ++i) {
          char c = schemeSpecificPart.charAt(i);
          if (c == ':') {
            String schemeName = schemeSpecificPart.substring(originLeft, i);
            Scheme originScheme = schemes.schemeForName(schemeName);
            if (originScheme == Scheme.UNKNOWN) { return null; }
            PartRanges originRanges = originScheme.decompose(
                schemes, schemeSpecificPart, i + 1, originRight);
            if (originRanges == null) { return null; }
            // https://html.spec.whatwg.org/multipage/origin.html#concept-origin defines "origin"
            b.withAuthority(originRanges.authorityLeft, originRanges.authorityRight);
            // A tuple origin consists of:
            //
            //   A scheme (a scheme).
            //   A host (a host).
            //   A port (a port).
            //   A domain (null or a domain). Null unless stated otherwise
            // TODO: package up the origin scheme as well.
            // TODO: disallow userinfo in the origin
            break;
          } else if (c == '/' || c == '?' || c == '#') {
            // Malformed or non-absolute origin.
            return null;
          }
        }
      } else {
        return null;
      }
      return b.build();
    }

    @Override
    public void recompose(CharSequence source, PartRanges ranges, StringBuilder out) {
      // This should only be reached if people use blog URLs as context URLs.
      // Don't do that.
      // To support this, we would need the origin's scheme available in parts.
      throw new UnsupportedOperationException();
    }
  };
  /** See http://tools.ietf.org/html/2397 */
  public static final Scheme DATA = new Scheme(
      ImmutableSet.of("data"), false, -1, SchemePart.CONTENT) {
    @Override
    public PartRanges decompose(
        SchemeLookupTable schemes,
        String schemeSpecificPart, int left, int right) {
      PartRanges pr = super.decompose(
          schemes, schemeSpecificPart, left, right);
      if (pr.contentLeft >= 0) {
        int contentRight = pr.contentRight;
        for (int i = pr.contentLeft; i < contentRight; ++i) {
          char c = schemeSpecificPart.charAt(i);
          if (c == ',') {
            return new PartRanges.Builder(pr)
                .withContent(i + 1, contentRight)
                .withContentMetadata(pr.contentLeft, i)
                .build();
          }
        }
      }
      return null;
    }

    @Override
    public void recompose(CharSequence source, PartRanges ranges, StringBuilder out) {
      Preconditions.checkArgument(
          (ranges.authorityLeft & ranges.pathLeft & ranges.queryLeft) < 0);
      int ml = ranges.contentMetadataLeft;
      int mr = ranges.contentMetadataRight;
      if (ranges.contentMetadataLeft < 0) {
        out.append(source, ml, mr);
      }
      out.append(',');

      int cl = ranges.contentLeft;
      int cr = ranges.contentRight;
      if (cl >= 0) {
        out.append(source, cl, cr);
      }

      int fl = ranges.fragmentLeft;
      int fr = ranges.fragmentRight;
      recomposeFragment(source, fl, fr, out);
    }

    @Override
    public Optional<?> decodeContent(
        String schemeSpecificPart, PartRanges ranges) {
      Optional<CharSequence> decoded =
          defaultDecodeContent(schemeSpecificPart, ranges);
      if (decoded.isPresent()) {
        if (ranges.contentMetadataLeft >= 0) {
          for (int i = ranges.contentMetadataLeft;
              i < ranges.contentMetadataRight; ++i) {
            char c = schemeSpecificPart.charAt(i);
            if (c == ';' && i + 7 <= ranges.contentMetadataRight
                && "base64".regionMatches(
                    true, 0, schemeSpecificPart, i + 1, 6)
                && (i + 7 == ranges.contentLeft
                    || schemeSpecificPart.charAt(i + 7) == ';')) {
              byte[] bytes;
              try {
                bytes = Base64.getDecoder().decode(decoded.get().toString());
              } catch (@SuppressWarnings("unused")
                       IllegalArgumentException ex) {
                return Optional.absent();
              }
              // TODO: if the media type has a charset should we decode
              // the bytes back to a string using that charset?
              return Optional.of(
                  ByteBuffer.wrap(bytes).asReadOnlyBuffer());
            }
          }
        }
      }
      return decoded;
    }
  };
  /** https://tools.ietf.org/html/rfc8089 */
  public static final Scheme FILE = new Scheme(
      ImmutableSet.of("file"), true, -1, SchemePart.PATH, SchemePart.QUERY);
  /** https://tools.ietf.org/html/rfc7230 */
  public static final Scheme HTTP = new Scheme(
      ImmutableSet.of("http"), true, 80,
      SchemePart.AUTHORITY, SchemePart.PATH, SchemePart.QUERY);
  /** https://tools.ietf.org/html/rfc7230 */
  public static final Scheme HTTPS = new Scheme(
      ImmutableSet.of("https"), true, 443,
      SchemePart.AUTHORITY, SchemePart.PATH, SchemePart.QUERY);
  /** https://wiki.whatwg.org/wiki/URL_schemes#javascript:_URLs */
  public static final Scheme JAVASCRIPT = new Scheme(
      ImmutableSet.of("javascript"), false, -1,
      SchemePart.CONTENT);
  /** https://tools.ietf.org/html/rfc6068 */
  public static final Scheme MAILTO = new OpaqueSchemeWithQuery("mailto");
  /** https://www.ietf.org/rfc/rfc3966.txt */
  public static final Scheme TEL = new Scheme(
      ImmutableSet.of("tel"), false, -1,
      SchemePart.CONTENT);

  private static final ImmutableMap<String, Scheme> BUILTIN_SCHEMES;
  static {
    ImmutableMap.Builder<String, Scheme> b = ImmutableMap.builder();
    for (Scheme s : new Scheme[] {
        ABOUT, BLOB, DATA, FILE, HTTP, HTTPS, JAVASCRIPT, MAILTO, TEL,
    }) {
      for (String name : s.lcaseNames) {
        b.put(name, s);
      }
    }
    BUILTIN_SCHEMES = b.build();
  }

  /** Null if the name isn't recognized as that of a builtin scheme. */
  static Scheme forName(String name) {
    String lname = Ascii.toLowerCase(name);
    return BUILTIN_SCHEMES.get(lname);
  }
}


final class OpaqueSchemeWithQuery extends Scheme {
  OpaqueSchemeWithQuery(String name, String... names) {
    super(
        ImmutableSet.<String>builder()
            .add(name)
            .addAll(Arrays.asList(names))
            .build(),
        false, -1, SchemePart.CONTENT, SchemePart.QUERY);
  }

  @Override
  public PartRanges decompose(
      SchemeLookupTable schemes,
      String schemeSpecificPart, int left, int right) {
    PartRanges.Builder b = new PartRanges.Builder();

    int cursor = left;
    int contentLeft = cursor;
    for (;cursor < right; ++cursor) {
      char c = schemeSpecificPart.charAt(cursor);
      if (c == '?' || c == '#') {
        break;
      }
    }
    b.withContent(contentLeft, cursor);

    if (cursor < right
        && '?' == schemeSpecificPart.charAt(cursor)) {
      int queryLeft = cursor;
      for (; cursor < right; ++cursor) {
        char c = schemeSpecificPart.charAt(cursor);
        if (c == '#') {
          break;
        }
      }
      b.withQuery(queryLeft, cursor);
    }

    if (cursor < right
        && '#' == schemeSpecificPart.charAt(cursor)) {
      b.withFragment(cursor, right);
      cursor = right;
    }
    Preconditions.checkState(cursor == right);

    return b.build();
  }

  @Override
  public void recompose(CharSequence source, PartRanges ranges, StringBuilder out) {
    Preconditions.checkArgument(
        ranges.authorityLeft < 0 && ranges.pathLeft < 0);
    int cl = ranges.contentLeft;
    int cr = ranges.contentRight;
    if (cl >= 0) {
      out.append(source, cl, cr);
    }

    int ql = ranges.queryLeft;
    int qr = ranges.queryRight;
    recomposeQuery(source, ql, qr, out);

    int fl = ranges.fragmentLeft;
    int fr = ranges.fragmentRight;
    recomposeFragment(source, fl, fr, out);
  }

  @Override
  public Optional<?> decodeContent(
      String schemeSpecificPart, PartRanges ranges) {
    // about: does not allow percent-encoding in the content part.
    return ranges.contentLeft >= 0
        ? Optional.of(schemeSpecificPart.substring(
            ranges.contentLeft, ranges.contentRight))
        : Optional.absent();
  }
}
