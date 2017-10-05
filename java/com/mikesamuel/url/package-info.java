/**
 * A declarative syntax for
 * {@linkplain com.mikesamuel.url.URLClassifier classifiers} (tri-state predicates)
 * over {@linkplain com.mikesamuel.url.URLValue URL}s.
 *
 * <p>
 * {@link com.mikesamuel.url.URLClassifierBuilder} allows building
 * {@link com.mikesamuel.url.URLClassifier}s that map
 * {@link com.mikesamuel.url.URLValue}s to {@link com.mikesamuel.url.Classification}.
 *
 * <p>
 * Sometimes it's useful to know why a URL did not match a classifier in which
 * case {@link com.mikesamuel.url.Diagnostic} may come in handy.
 *
 * <p>
 * The other interfaces and classes are <tt>*ClassifierBuilder</tt>s that can be
 * used with {@link com.mikesamuel.url.URLClassifierBuilder} to vet parts of a
 * URL or are mostly of interest when writing one's own classifier.
 */
package com.mikesamuel.url;