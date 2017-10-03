package com.mikesamuel.url;

import java.util.Arrays;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;

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
  private URLClassifierBuilder() {
    // Use static factory
  }

  /** A new blank builder. */
  public static URLClassifierBuilder builder() {
    return new URLClassifierBuilder();
  }

  /**
   * Builds a classifier based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built classifiers.
   */
  public URLClassifier build() {
    return null;  // TODO
    // return new URLClassifierImpl(...);
  }

  //// Flags that affect multiple sub-classifiers.
  private boolean matchesNULs = false;
  // TODO: Move this to the URLContext
  private boolean matchMicrosoftPathBugForBug = false;
  private boolean allowPathsThatReachRootsParent = false;

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
  public URLClassifierBuilder allowPathsThatReachRootsParent(boolean enable) {
    this.allowPathsThatReachRootsParent = enable;
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
    this.mediaTypeClassifier = this.mediaTypeClassifier == null
        ? c
        : MediaTypeClassifier.or(this.mediaTypeClassifier, c);
    return this;
  }

  //// Sub-classifiers of kind authority  http://MATCH_ME/...
  public URLClassifierBuilder matchesHosts(String... hostnames) {
    // TODO
    return this;
  }
  public URLClassifierBuilder matchesHosts(Iterable<? extends String> hostnames) {
    // TODO
    return this;
  }
  public URLClassifierBuilder matchesAuthority(AuthorityClassifier authMatcher) {
    // TODO
    return this;
  }

  //// Sub-classifiers of kind path       http://example.com/MATCH_ME?...
  /**
   * In the glob, `**` matches one or more path components and * matches
   * a single path component at most.  Matching is done after processing the
   * special path components ".." and ".".
   * If a glob ends in "/?" then a slash is optionally allowed at the end.
   * For example,
   * <ul>
   *   <li>"**<!--->/*.html" matches all paths that end with ".html"
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
  public URLClassifierBuilder matchesPathGlobs(
      Iterable<? extends String> pathGlobs) {
    // TODO
    return this;
  }
  /**
   * Does not match any of the path globs where not(INVALID) == INVALID.
   */
  public URLClassifierBuilder notMatchesPathGlobs(String... pathGlobs) {
    return notMatchesPathGlobs(ImmutableList.copyOf(pathGlobs));
  }
  public URLClassifierBuilder notMatchesPathGlobs(
      Iterable<? extends String> pathGlobs) {
    return this;  // TODO
  }

  //// Sub-classifiers of kind query      http://example.com/?MATCH_ME#...
  public URLClassifierBuilder matchesQuery(QueryClassifier queryClassifier) {
    return this;  // TODO
  }
  /**
   * Reverses the classifier where not(INVALID) == INVALID.
   */
  public URLClassifierBuilder notMatchesQuery(QueryClassifier queryClassifier) {
    return this;  // TODO
  }

  //// Sub-classifiers of kind fragment   http://example.com/#MATCH_ME
  public URLClassifierBuilder matchesFragment(
      FragmentClassifier fragmentClassifier) {
    return this;  // TODO
  }
  /**
   * Reverses the classifier where not(INVALID) == INVALID.
   */
  public URLClassifierBuilder notMatchesFragment(
      FragmentClassifier fragmentClassifier) {
    return this;  // TODO
  }

  //// Sub-classifiers of kind content    javascript:MATCH_ME
  ////                                   data:foo/bar,MATCH_ME
  /**
   * Matches when the scheme-specific part matches the classifier.
   * This is applied after any content metadata is stripped and after decoding.
   * For example,
   * data: URLs have the mime-type and any base64 specifier stripped, and if the
   * base64 is specified, the content is base64 decoded;
   * blob: URLs have the origin stripped.
   */
  public URLClassifierBuilder matchesContent(ContentClassifier p) {
    return this;  // TODO
  }
}
