package com.mikesamuel.url;

import com.google.common.collect.ImmutableList;

/**
 * Specifying multiple sub-predicates of the same kind ORs those
 * together.
 * Predicates of one kind AND with predicates of another kind except
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
 * then it MUST not have an authority and any authority predicate
 * is ignored.
 * For example, `file:` URLs and `data:` URLs do not naturally
 * have an authority.  `file:` by the nature of the scheme, and
 * `data:` because it is not a hierarchical scheme.
 *
 * <p>If a URL's scheme naturally has an authority then it MUST have an
 * authority and any authority predicate must also pass.
 * For example: `http:///` will never pass any predicate.
 * <a href="https://w3c.github.io/FileAPI/#DefinitionOfScheme">Blobs</a>
 * naturally have an authority.
 *
 * <p>If a URL's scheme does not naturally have a path or query component
 * then path and query predicates will not be applied.
 * All hierarchical URLs naturally have both, so a `file:` URL MUST match
 * any query predicates.
 *
 * <p>All URLs are treated as URI References, so fragments are allowed
 * regardless of scheme.
 *
 * <p>If a URL's scheme does not naturally have embedded content then
 * any content predicate is ignored.  For example, `http:` and other
 * hierarchical URLs do not have embedded content.
 *
 * <p>If a URL's scheme does naturally have embedded content, then it
 * MUST have embedded content and any content predicate must match
 * that content.  For example: `data:text/plain;base64` will not match
 * any predicate but `data:text/plain,` will match if the content
 * predicate matches the empty string.  Schemes that naturally have
 * embedded content include `about:`, `blob:`, `data:`, and
 * `javascript:`.
 */
public final class URLPredicateBuilder {
  private URLPredicateBuilder() {
    // Use static factory
  }

  /** A new blank builder. */
  public static URLPredicateBuilder builder() {
    return new URLPredicateBuilder();
  }

  /**
   * Builds a predicate based on previous allow/match decisions.
   * This may be reused after a call to build and subsequent calls to
   * allow/match methods will not affect previously built predicates.
   */
  public URLPredicate build() {
    return new URLPredicateImpl(...);
  }

  //// Flags that affect multiple sub-predicates.
  private boolean matchesNULs = false;
  // TODO: Move this to the URLContext
  private boolean matchMicrosoftPathBugForBug = false;

  /**
   * URLs with NULs are a common problem case.
   * By default they are not matched.
   * blob and data URLs that need to embed NULs in content typically
   * base64 encode and NULs in decoded will not cause a mismatch.
   * If allowing NULs is definitely required enable this.
   */
  public URLPredicateBuilder matchesNULs(boolean allow) {
    this.matchesNULs = allow;
    return this;
  }

  /**
   * Microsoft uses back-slash ('\\') to separate file components and many
   * Microsoft systems helpfully treat ('\\') as equivalent to the normal
   * URL path component separator ('/').
   * Enable this flag if you want to emulate this behavior.
   * By default, you don't.
   */
  public URLPredicateBuilder matchMicrosoftPathBugForBug(boolean enable) {
    this.matchMicrosoftPathBugForBug = enable;
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
  public URLPredicateBuilder allowPathsThatReachRootsParent(boolean enable) {
    this.allowPathsThatReachRootsParent = allowPathsThatReachRootsParent;
  }



  //// Sub-predicates of kind scheme     MATCH_ME://...
  public URLPredicateBuilder matchesSchemes(Scheme... schemes);
  public URLPredicateBuilder matchesSchemes(Iterable<? extends Scheme> schemes);
  /**
   * We can match data with an additional constraint on the mime-type.
   * We special-case data because content-types are not attached to
   * URLs with other schemes and its rare to want to match a data: URL
   * without caring about the type of data.
   */
  public URLPredicateBuilder matchesData(MimeTypePredicate types);

  //// Sub-predicates of kind authority  http://MATCH_ME/...
  public URLPredicateBuilder matchesHosts(String... hostnames);
  public URLPredicateBuilder matchesHosts(Iterable<? extends String> hostnames);
  public URLPredicateBuilder matchesAuthority(AuthorityPredicate authMatcher);

  //// Sub-predicates of kind path       http://example.com/MATCH_ME?...
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
  public URLPredicateBuilder matchesPathGlobs(String... pathGlobs) {
    return matchesPathGlobs(ImmutableList.copyOf(pathGlobs));
  }
  public URLPredicateBuilder matchesPathGlobs(
      Iterable<? extends String> pathGlobs) {

  }
  /**
   * Does not match any of the path globs where not(INVALID) == INVALID.
   */
  public URLPredicateBuilder notMatchesPathGlobs(String... pathGlobs) {
    return notMatchesPathGlobs(ImmutableList.copyOf(pathGlobs));
  }
  public URLPredicateBuilder notMatchesPathGlobs(
      Iterable<? extends String> pathGlobs) {

  }
  /**
   * By default, path components like ("%2e", "%2e%2e") that, post decoding
   * are ambiguous with the special path components (".", "..") will not be
   * matched.  If these must be matched, then enable this but ensure that the
   * server that processes these deals with these path components correctly.
   * Default is TREAT_AS_INVALID
   */
  public URLPredicateBuilder matchesEncodedDots(EncodedDotStrategy strategy);
  public enum EncodedDotStrategy {
    TREAT_AS_INVALID,
    DO_NOT_MATCH,
    MATCH_AS_PATH,
    MATCH_AS_DECODED,
  }

  //// Sub-predicates of kind query      http://example.com/?MATCH_ME#...
  public URLPredicateBuilder matchesQuery(QueryPredicate queryPredicate);
  /**
   * Reverses the predicate where not(INVALID) == INVALID.
   */
  public URLPredicateBuilder notMatchesQuery(QueryPredicate queryPredicate);

  //// Sub-predicates of kind fragment   http://example.com/#MATCH_ME
  public URLPredicateBuilder matchesFragment(
      FragmentPredicate fragmentPredicate);
  /**
   * Reverses the predicate where not(INVALID) == INVALID.
   */
  public URLPredicateBuilder notMatchesFragment(
      FragmentPredicate fragmentPredicate);

  //// Sub-predicates of kind content    javascript:MATCH_ME
  ////                                   data:foo/bar,MATCH_ME
  /**
   * Matches when the scheme-specific part matches the predicate.
   * This is applied after any content metadata is stripped and after decoding.
   * For example,
   * data: URLs have the mime-type and any base64 specifier stripped, and if the
   * base64 is specified, the content is base64 decoded;
   * blob: URLs have the origin stripped.
   */
  public URLPredicateBuilder matchesContent(ContentPredicate p) {

  }
}
