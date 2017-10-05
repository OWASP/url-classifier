package com.mikesamuel.url;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.regex.Pattern;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

/**
 * Specifying multiple sub-classifiers of the same kind ORs those
 * together.
 * Classifiers of one kind AND with classifiers of another kind except
 * where stated below.
 * For example,
 * <pre>
 *    .matchesSchemes(HTTP, HTTPS)
 *    .matchesSchemes(FILE)
 *    .matchesHosts("example.com")
 *    .matchesPathGlobs("/foo/**")
 *    .matchesPathGlobs("/*.js")
 * </pre>
 * corresponds to pseudocode like
 * <pre>
 * ((url.scheme in (HTTP, HTTPS))
 *    or (url.scheme is FILE))
 * and (not url.scheme.naturallyHasAuthority
 *      or url.authority == "example.com")
 * and (not url.scheme.naturallyHasPath
 *      or glob("/foo/**").matches(url.path)
 *      or glob("/*.js").matches(url.path))
 * </pre>
 *
 * <p>If a URL's scheme does not naturally have an authority,
 * then it MUST not have an authority and any authority classifier
 * is ignored.
 * For example, `file:` URLs and `data:` URLs do not naturally
 * have an authority.  `file:` by the nature of the scheme, and
 * `data:` because it is not a hierarchical scheme.
 *
 * <p>If a URL's scheme naturally has an authority then it MUST have an
 * authority and any authority classifier must also pass.
 * For example: `http:///` will never pass any classifier.
 * <a href="https://w3c.github.io/FileAPI/#DefinitionOfScheme">Blobs</a>
 * naturally have an authority.
 *
 * <p>If a URL's scheme does not naturally have a path or query component
 * then path and query classifiers will not be applied.
 * All hierarchical URLs naturally have both, so a `file:` URL MUST match
 * any query classifiers.
 *
 * <p>All URLs are treated as URI References, so fragments are allowed
 * regardless of scheme.
 *
 * <p>If a URL's scheme does not naturally have embedded content then
 * any content classifier is ignored.  For example, `http:` and other
 * hierarchical URLs do not have embedded content.
 *
 * <p>If a URL's scheme does naturally have embedded content, then it
 * MUST have embedded content and any content classifier must match
 * that content.  For example: `data:text/plain;base64` will not match
 * any classifier but `data:text/plain,` will match if the content
 * classifier matches the empty string.  Schemes that naturally have
 * embedded content include `about:`, `blob:`, `data:`, and
 * `javascript:`.
 */
public final class URLClassifierBuilder {
  URLClassifierBuilder() {
    // Use static factory
  }

  /**
   * Builds a classifier based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built classifiers.
   */
  public URLClassifier build() {
    EnumSet<URLClassifierImpl.GlobalFlag> flags =
        EnumSet.noneOf(URLClassifierImpl.GlobalFlag.class);
    if (this.allowPathsThatReachRootsParent) {
      flags.add(URLClassifierImpl.GlobalFlag.ALLOW_PATHS_THAT_REACH_ROOT_PARENT);
    }
    if (this.matchesNULs) {
      flags.add(URLClassifierImpl.GlobalFlag.ALLOW_NULS);
    }
    ImmutableSet<URLValue.URLSpecCornerCase> toleratedCornerCaseSet =
        Sets.immutableEnumSet(this.toleratedCornerCases);
    ImmutableSet<Scheme> allowedSchemeSet = allowedSchemes.build();
    MediaTypeClassifier mtc = mediaTypeClassifier != null
        ? mediaTypeClassifier
        : MediaTypeClassifier.or();
    AuthorityClassifier ac = authorityClassifier != null
        ? authorityClassifier
        : AuthorityClassifier.any();
    ImmutableSet<String> positivePathGlobSet = positivePathGlobs.build();
    ImmutableSet<String> negativePathGlobSet = negativePathGlobs.build();
    Pattern positivePathPattern = positivePathGlobSet.isEmpty()
        ? null
        : pathGlobsToPattern(positivePathGlobSet);
    Pattern negativePathPattern = negativePathGlobSet.isEmpty()
        ? null
        : pathGlobsToPattern(negativePathGlobSet);
    QueryClassifier qc = queryClassifier != null
        ? queryClassifier
        : QueryClassifier.any();
    FragmentClassifier fc = fragmentClassifier != null
        ? fragmentClassifier
        : FragmentClassifier.any();
    ContentClassifier cc = contentClassifier != null
        ? contentClassifier
        : ContentClassifier.any();

    return new URLClassifierImpl(
        flags,
        toleratedCornerCaseSet,
        allowedSchemeSet,
        mtc,
        ac,
        positivePathPattern,
        negativePathPattern,
        qc,
        fc,
        cc
        );
  }

  private static Pattern pathGlobsToPattern(Iterable<? extends String> globs) {
    StringBuilder sb = new StringBuilder();
    sb.append("^(?:");
    boolean wroteOne = false;
    for (String glob : globs) {
      if (wroteOne) {
        sb.append('|');
      }
      wroteOne = true;

      // Split the glob so that all "*" and "**" segments appear at the front
      // of tokens and any trailing /? appears by itself.
      int written = 0;
      int n = glob.length();
      for (int i = 0; i <= n; ++i) {
        String sub = null;
        int nMatched = 0;
        if (i == n) {
          sub = "";  // Forces write of last region
          nMatched = 1;
        } else if ("/**/".regionMatches(0, glob, i, 4)) {
          nMatched = 4;
          // /**/ should match /
          sub = "/(?:.*/)?";
        } else if ("/**".regionMatches(0, glob, i, 3) && i + 3 == n) {
          nMatched = 3;
          sub = "/.*\\z";
        } else if ("**".regionMatches(0, glob, i, 2)) {
          nMatched = 2;
          sub = ".*";
        } else if (glob.charAt(i) == '*') {
          nMatched = 1;
          sub = "[^/]*";
        } else if (i + 2 == n && "/?".regionMatches(0, glob, i, 2)) {
          nMatched = 2;
          sub = "/?";
        }
        if (sub != null) {
          if (i != written) {
            String globPart = glob.substring(written, i);
            Optional<String> decodedPart = Percent.decode(globPart);
            if (decodedPart.isPresent()) {
              sb.append(Pattern.quote(decodedPart.get()));
            } else {
              // We check when adding a glob that it decodes properly
              // so this should not occur.
              throw new AssertionError(globPart);
            }
          }
          sb.append(sub);
          written = i + nMatched;
          i = written - 1;
        }
      }
    }
    if (!wroteOne) {
      // We are joining using | but if there's no operands we
      // should fail to match per the usual semantics of
      // zero-arity OR.
      sb.append("(?!)");
    }
    sb.append(")\\z");
//    System.err.println(Arrays.asList(globs) + " => " + sb);
    return Pattern.compile(sb.toString());
  }

  //// Flags that affect multiple sub-classifiers.
  private boolean matchesNULs = false;
  private boolean allowPathsThatReachRootsParent = false;
  private final EnumSet<URLValue.URLSpecCornerCase> toleratedCornerCases =
      EnumSet.noneOf(URLValue.URLSpecCornerCase.class);

  /**
   * URLs with NULs are a common problem case.
   * By default they are not matched.
   * blob and data URLs that need to embed NULs in content typically
   * base64 encode and NULs in decoded will not cause a mismatch.
   * If allowing NULs is definitely required enable this.
   */
  public URLClassifierBuilder matchesNULs(boolean allow) {
    this.matchesNULs = allow;
    return this;
  }

  /**
   * If not enabled (the default), apply(x) will return INVALID when
   * x.{@link URLValue#pathSimplificationReachedRootsParent pathSimplificationReachedRootsParent}.
   * <p>
   * It is safe to enable this if you plan on substituting x.urlText
   * for x.originalUrlText in your output, but not if you plan on
   * using x.originalUrlText.
   */
  public URLClassifierBuilder toleratePathsThatReachRootsParent(boolean enable) {
    this.allowPathsThatReachRootsParent = enable;
    return this;
  }

  /**
   * Don't reject as {@link Classification#INVALID} URLs whose interpretation involves
   * the given corner cases.
   */
  public URLClassifierBuilder tolerate(URLValue.URLSpecCornerCase... cornerCases) {
    return tolerate(Arrays.asList(cornerCases));
  }

  /**
   * Don't reject as {@link Classification#INVALID} URLs whose interpretation involves
   * the given corner cases.
   */
  public URLClassifierBuilder tolerate(
      Iterable<? extends URLValue.URLSpecCornerCase> cornerCases) {
    for (URLValue.URLSpecCornerCase cornerCase : cornerCases) {
      this.toleratedCornerCases.add(cornerCase);
    }
    return this;
  }


  private final ImmutableSet.Builder<Scheme> allowedSchemes = ImmutableSet.builder();
  private MediaTypeClassifier mediaTypeClassifier;

  //// Sub-classifiers of kind scheme     MATCH_ME://...
  /**
   * @see #matchesSchemes(Iterable)
   */
  public URLClassifierBuilder matchesSchemes(Scheme... schemes) {
    return matchesSchemes(Arrays.asList(schemes));
  }
  /**
   * Allows URLs with the given schemes assuming any per-component classifiers
   * also pass.
   */
  public URLClassifierBuilder matchesSchemes(Iterable<? extends Scheme> schemes) {
    this.allowedSchemes.addAll(schemes);
    return this;
  }
  /**
   * Matches data schemes
   * We can match data with an additional constraint on the mime-type.
   * We special-case data because content-types are not attached to
   * URLs with other schemes and its rare to want to match a data: URL
   * without caring about the type of data.
   */
  public URLClassifierBuilder matchesData(MediaTypeClassifier c) {
    this.allowedSchemes.add(BuiltinScheme.DATA);
    this.mediaTypeClassifier = this.mediaTypeClassifier == null
        ? c
        : MediaTypeClassifier.or(this.mediaTypeClassifier, c);
    return this;
  }

  //// Sub-classifiers of kind authority  http://MATCH_ME/...
  private AuthorityClassifier authorityClassifier;
  /**
   * Specifies that any matching URLs must naturally have no authority
   * or have one that matches the given authority classifier.
   */
  public URLClassifierBuilder matchesAuthority(AuthorityClassifier ac) {
    this.authorityClassifier = this.authorityClassifier == null
        ? ac
        : AuthorityClassifier.or(this.authorityClassifier, ac);
    return this;
  }

  //// Sub-classifiers of kind path       http://example.com/MATCH_ME?...
  private final ImmutableSet.Builder<String> positivePathGlobs = ImmutableSet.builder();
  private final ImmutableSet.Builder<String> negativePathGlobs = ImmutableSet.builder();
  /**
   * In the glob, `**` matches one or more path components and * matches
   * a single path component at most.  Matching is done after processing the
   * special path components ".." and ".".
   * If a glob ends in "/?" then a slash is optionally allowed at the end.
   * For example,
   * <ul>
   *   <li>"**<!--->/*.html" matches all paths that end with ".html"
   *   <li>"**.html" matches the same.
   *   <li>"*.html" matches all single-component paths that end with ".html"
   *   <li>"foo/**<!--->/bar" matches all paths that start with a foo component,
   *     followed by zero or more other components and ending with bar.
   *   <li>"foo/" matches "foo/" but not "foo" while "foo/?" matches both.
   *   <li>"foo**" is not a valid glob.
   * </ul>
   * The following code-points may be %-encoded in a path glob to allow them
   * to be treated literally as part of a path component: ('/', '*', '?', '%').
   */
  public URLClassifierBuilder matchesPathGlobs(String... pathGlobs) {
    return matchesPathGlobs(ImmutableList.copyOf(pathGlobs));
  }
  /** @see #matchesPathGlobs(String...) */
  public URLClassifierBuilder matchesPathGlobs(
      Iterable<? extends String> pathGlobs) {
    for (String pathGlob : pathGlobs) {
      Optional<String> decPathGlob = Percent.decode(pathGlob);
      Preconditions.checkArgument(
          decPathGlob.isPresent(), "Invalid %-encoding in path glob", pathGlob);
      positivePathGlobs.add(pathGlob);
    }
    return this;
  }
  /**
   * Like {@link #matchesPathGlobs(String...)} but the path must not match.
   */
  public URLClassifierBuilder notMatchesPathGlobs(String... pathGlobs) {
    return notMatchesPathGlobs(ImmutableList.copyOf(pathGlobs));
  }
  /** @see #notMatchesPathGlobs(String...) */
  public URLClassifierBuilder notMatchesPathGlobs(
      Iterable<? extends String> pathGlobs) {
    for (String pathGlob : pathGlobs) {
      Optional<String> decPathGlob = Percent.decode(pathGlob);
      Preconditions.checkArgument(
          decPathGlob.isPresent(), "Invalid %-encoding in path glob", pathGlob);
      negativePathGlobs.add(pathGlob);
    }
    return this;
  }

  private QueryClassifier queryClassifier;
  //// Sub-classifiers of kind query      http://example.com/?MATCH_ME#...
  /**
   * Specifies a query classifier that, in order for the URL to match,
   * must match the URL's query if the URL's scheme naturally has a query.
   */
  public URLClassifierBuilder matchesQuery(QueryClassifier qc) {
    this.queryClassifier = this.queryClassifier == null
        ? qc
        : QueryClassifier.or(this.queryClassifier, qc);
    return this;
  }
  /**
   * Reverses the classifier where not(INVALID) == INVALID.
   */
  public URLClassifierBuilder notMatchesQuery(QueryClassifier qc) {
    return matchesQuery(new NotQueryClassifier(qc));
  }
  static final class NotQueryClassifier implements QueryClassifier {
    final QueryClassifier qc;

    NotQueryClassifier(QueryClassifier qc) {
      this.qc = qc;
    }

    @Override
    public Classification apply(
        URLValue x, Diagnostic.Receiver<? super URLValue> r) {
      return qc.apply(x, Diagnostic.Receiver.NULL_RECEIVER).invert();
    }
  }

  //// Sub-classifiers of kind fragment   http://example.com/#MATCH_ME
  private FragmentClassifier fragmentClassifier;
  /**
   * Specifies a fragment classifier that, in order for the URL to match,
   * must match the URL's fragment.
   */
  public URLClassifierBuilder matchesFragment(
      FragmentClassifier fc) {
    this.fragmentClassifier = this.fragmentClassifier == null
        ? fc
        : FragmentClassifier.or(this.fragmentClassifier, fc);
    return this;
  }
  /**
   * Reverses the classifier where not(INVALID) == INVALID.
   */
  public URLClassifierBuilder notMatchesFragment(
      FragmentClassifier fc) {
    return matchesFragment(new NotFragmentClassifier(fc));
  }
  static final class NotFragmentClassifier implements FragmentClassifier {
    final FragmentClassifier fc;

    NotFragmentClassifier(FragmentClassifier fc) {
      this.fc = fc;
    }

    @Override
    public Classification apply(
        URLValue x, Diagnostic.Receiver<? super URLValue> r) {
      return fc.apply(x, Diagnostic.Receiver.NULL_RECEIVER).invert();
    }
  }

  //// Sub-classifiers of kind content    javascript:MATCH_ME
  ////                                    data:foo/bar,MATCH_ME
  private ContentClassifier contentClassifier;
  /**
   * Matches when the scheme-specific part matches the classifier.
   * This is applied after any content metadata is stripped and after decoding.
   * For example,
   * data: URLs have the mime-type and any base64 specifier stripped, and if the
   * base64 is specified, the content is base64 decoded;
   * blob: URLs have the origin stripped.
   */
  public URLClassifierBuilder matchesContent(ContentClassifier c) {
    this.contentClassifier = this.contentClassifier == null
        ? c
        : ContentClassifier.or(this.contentClassifier, c);
    return this;
  }
}

final class URLClassifierImpl implements URLClassifier {
  final boolean matchesNULs;
  final boolean allowPathsThatReachRootsParent;
  final ImmutableSet<URLValue.URLSpecCornerCase> toleratedCornerCaseSet;
  final ImmutableSet<Scheme> allowedSchemeSet;
  final MediaTypeClassifier mediaTypeClassifier;
  final AuthorityClassifier authorityClassifier;
  final Pattern positivePathPattern;
  final Pattern negativePathPattern;
  final QueryClassifier queryClassifier;
  final FragmentClassifier fragmentClassifier;
  final ContentClassifier contentClassifier;

  public URLClassifierImpl(
      EnumSet<GlobalFlag> flags,
      ImmutableSet<URLValue.URLSpecCornerCase> toleratedCornerCaseSet,
      ImmutableSet<Scheme> allowedSchemeSet,
      MediaTypeClassifier mediaTypeClassifier,
      AuthorityClassifier authorityClassifier,
      Pattern positivePathPattern,
      Pattern negativePathPattern,
      QueryClassifier queryClassifier,
      FragmentClassifier fragmentClassifier,
      ContentClassifier contentClassifier) {
    this.matchesNULs = flags.contains(GlobalFlag.ALLOW_NULS);
    this.allowPathsThatReachRootsParent = flags.contains(
        GlobalFlag.ALLOW_PATHS_THAT_REACH_ROOT_PARENT);
    this.toleratedCornerCaseSet = toleratedCornerCaseSet;
    this.allowedSchemeSet = allowedSchemeSet;
    this.mediaTypeClassifier = mediaTypeClassifier;
    this.authorityClassifier = authorityClassifier;
    this.positivePathPattern = positivePathPattern;
    this.negativePathPattern = negativePathPattern;
    this.queryClassifier = queryClassifier;
    this.fragmentClassifier = fragmentClassifier;
    this.contentClassifier = contentClassifier;
  }

  enum GlobalFlag {
    ALLOW_NULS,
    ALLOW_PATHS_THAT_REACH_ROOT_PARENT,
  }

  enum Diagnostics implements Diagnostic {
    UNTOLERATED_CORNER_CASE,
    NULS,
    AUTHORITY_DID_NOT_MATCH,
    MALFORMED_PATH,
    PATH_SIMPLIFICATION_REACHED_ROOTS_PARENT,
    PATH_MATCHED_NEGATIVE_PATH_GLOBS,
    PATH_DID_NOT_MATCH_PATH_GLOBS,
    QUERY_DID_NOT_MATCH,
    MEDIA_TYPE_DID_NOT_MATCH,
    CONTENT_DID_NOT_MATCH,
    FRAGMENT_DID_NOT_MATCH
  }

  @Override
  public Classification apply(
      URLValue x, Diagnostic.Receiver<? super URLValue> r) {
    Diagnostic.CollectingReceiver<? super URLValue> cr =
        Diagnostic.collecting(r);

    if (!this.toleratedCornerCaseSet.containsAll(x.cornerCases)) {
      r.note(Diagnostics.UNTOLERATED_CORNER_CASE, x);
      return Classification.INVALID;
    }
    if (!matchesNULs && x.originalUrlText.indexOf('\0') >= 0) {
      r.note(Diagnostics.NULS, x);
      return Classification.INVALID;
    }

    Scheme s = x.scheme;
    if (!allowedSchemeSet.contains(s)) {
      return Classification.NOT_A_MATCH;
    }
    if (s.naturallyHasAuthority || x.ranges.authorityLeft >= 0) {
      Classification c = authorityClassifier.apply(x, cr);
      if (c != Classification.MATCH) {
        cr.flush();
        r.note(Diagnostics.AUTHORITY_DID_NOT_MATCH, x);
        return c;
      }
    }
    String path = x.getRawPath();
    if (path != null) {
      Optional<String> decPathOpt = Percent.decode(path);
      if (!decPathOpt.isPresent()) {
        r.note(Diagnostics.MALFORMED_PATH, x);
        return Classification.INVALID;
      }
      if (!allowPathsThatReachRootsParent
          && x.pathSimplificationReachedRootsParent) {
        r.note(Diagnostics.PATH_SIMPLIFICATION_REACHED_ROOTS_PARENT, x);
        return Classification.NOT_A_MATCH;
      }
      String decPath = decPathOpt.get();
      if (negativePathPattern != null
          && negativePathPattern.matcher(decPath).matches()) {
        r.note(Diagnostics.PATH_MATCHED_NEGATIVE_PATH_GLOBS, x);
        return Classification.NOT_A_MATCH;
      }
      if (positivePathPattern != null
          && !positivePathPattern.matcher(decPath).matches()) {
        r.note(Diagnostics.PATH_DID_NOT_MATCH_PATH_GLOBS, x);
        return Classification.NOT_A_MATCH;
      }
    }
    if (s.naturallyHasQuery || x.ranges.queryLeft >= 0) {
      cr.reset();
      Classification c = queryClassifier.apply(x, cr);
      if (c != Classification.MATCH) {
        cr.flush();
        r.note(Diagnostics.QUERY_DID_NOT_MATCH, x);
        return c;
      }
    }
    if (mediaTypeClassifier != null && x.getContentMediaType() != null) {
      cr.reset();
      Classification c = mediaTypeClassifier.apply(x, cr);
      if (c != Classification.MATCH) {
        cr.flush();
        r.note(Diagnostics.MEDIA_TYPE_DID_NOT_MATCH, x);
        return c;
      }
    }
    if (s.naturallyEmbedsContent || x.ranges.contentLeft >= 0) {
      cr.reset();
      Classification c = contentClassifier.apply(x, cr);
      if (c != Classification.MATCH) {
        cr.flush();
        r.note(Diagnostics.CONTENT_DID_NOT_MATCH, x);
        return c;
      }
    }

    cr.reset();
    Classification c = fragmentClassifier.apply(x, r);
    if (c != Classification.MATCH) {
      cr.flush();
      r.note(Diagnostics.FRAGMENT_DID_NOT_MATCH, x);
    }
    return c;
  }
}
