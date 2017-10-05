/**
 * A declarative syntax for
 * {@linkplain org.owasp.url.URLClassifier classifiers} (tri-state predicates)
 * over {@linkplain org.owasp.url.URLValue URL}s.
 *
 * <p>
 * {@link org.owasp.url.URLClassifierBuilder} allows building
 * {@link org.owasp.url.URLClassifier}s that map
 * {@link org.owasp.url.URLValue}s to {@link org.owasp.url.Classification}.
 *
 * <p>
 * Sometimes it's useful to know why a URL did not match a classifier in which
 * case {@link org.owasp.url.Diagnostic} may come in handy.
 *
 * <p>
 * The other interfaces and classes are <tt>*ClassifierBuilder</tt>s that can be
 * used with {@link org.owasp.url.URLClassifierBuilder} to vet parts of a
 * URL or are mostly of interest when writing one's own classifier.
 */
package org.owasp.url;