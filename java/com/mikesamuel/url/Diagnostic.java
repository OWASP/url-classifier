package com.mikesamuel.url;

import java.util.List;

import com.google.common.collect.Lists;

/**
 * A message typically used to explain why a URLClassifier didn't match its input.
 */
public interface Diagnostic {

  /**
   * A receiver of diagnostic messages; may hook into a logger.
   * <p>
   * Implementations may assume that only one thread is using a receiver
   * at a time.
   *
   * @param <T> The type of the context value passed to {@link Receiver#note}.
   */
  public interface Receiver<T> {

    /**
     * Is called when a classification operation fails in a noteworthy way.
     *
     * @param d A diagnostic message.
     * @param context a value associated with the failure.
     */
    public void note(Diagnostic d, T context);

    /**
     * A receiver that does nothing when notified.
     */
    public static final Receiver<Object> NULL = NullReceiver.INSTANCE;
  }


  /**
   * A receiver that collects diagnostics while waiting to see whether a larger
   * operation fails.
   */
  public static abstract class CollectingReceiver<T> implements Receiver<T> {
    CollectingReceiver() {}

    /**
     * Clears the queue of notifications.
     */
    public abstract void clear();

    /**
     * Replays collected notifications to the underlying receiver in order.
     */
    public abstract void replay();

    /** Replay then clear. */
    public abstract void flush();
  }


  /**
   * A receiver that collects diagnostics while waiting to see whether a larger
   * operation fails.
   *
   * @param r the underlying receiver to notify when flushing.
   * @param <T> The type of the context value passed to {@link Receiver#note}.
   * @return a receiver that will collect diagnostics until replayed onto r.
   */
  @SuppressWarnings("unchecked")
  public static <T> CollectingReceiver<T> collecting(Receiver<T> r) {
    if (r == NullReceiver.INSTANCE) {
      // This cast is unsound, but safe since all NullReceiver operations
      // are null-ops.
      // Returning null receiver allows code that wants to avoid
      // spending time figuring out exactly which diagnostic to show to
      // first test whether anyone is on the other end of the receiver
      // by checking whether it is the null receiver.
      return (CollectingReceiver<T>) NullReceiver.INSTANCE;
    }
    return new CollectingReceiverImpl<>(r);
  }
}


final class NullReceiver extends Diagnostic.CollectingReceiver<Object> {

  static final NullReceiver INSTANCE = new NullReceiver();

  private NullReceiver() {
    // Singleton
  }

  @Override
  public String toString() {
    return "(NullReceiver)";
  }

  @Override
  public void note(Diagnostic d, Object context) {
    // This block left intentionally blank.
  }

  @Override
  public void clear() {
    // This block left intentionally blank.
  }

  @Override
  public void replay() {
    // This block left intentionally blank.
  }

  @Override
  public void flush() {
    // This block left intentionally blank.
  }
}


final class CollectingReceiverImpl<T> extends Diagnostic.CollectingReceiver<T> {

  private final Diagnostic.Receiver<T> underlying;
  private List<Object> diagnosticsAndContexts;

  CollectingReceiverImpl(Diagnostic.Receiver<T> underlying) {
    this.underlying = underlying;
  }

  @Override
  public String toString() {
    return "(CollectingReceiver " + underlying + ")";
  }

  @Override
  public void note(Diagnostic d, T context) {
    if (diagnosticsAndContexts == null) {
      diagnosticsAndContexts = Lists.newArrayList();
    }
    diagnosticsAndContexts.add(d);
    diagnosticsAndContexts.add(context);
  }

  @Override
  public void clear() {
    if (diagnosticsAndContexts != null) {
      diagnosticsAndContexts.clear();
    }
  }

  @Override
  public void replay() {
    if (this.diagnosticsAndContexts != null) {
      for (int i = 0, n = this.diagnosticsAndContexts.size(); i < n; i += 2) {
        Diagnostic d = (Diagnostic) this.diagnosticsAndContexts.get(i);
        @SuppressWarnings("unchecked")  // Sound modulo thread-unsafety
        T context = (T) this.diagnosticsAndContexts.get(i + 1);
        this.underlying.note(d, context);
      }
    }
  }

  @Override
  public void flush() {
    if (this.diagnosticsAndContexts != null) {
      if (underlying instanceof CollectingReceiverImpl) {
        CollectingReceiverImpl<T> cri = (CollectingReceiverImpl<T>) underlying;
        if (cri.diagnosticsAndContexts == null || cri.diagnosticsAndContexts.isEmpty()) {
          List<Object> swap = cri.diagnosticsAndContexts;
          cri.diagnosticsAndContexts = this.diagnosticsAndContexts;
          this.diagnosticsAndContexts = swap;
        } else {
          cri.diagnosticsAndContexts.addAll(this.diagnosticsAndContexts);
          this.diagnosticsAndContexts.clear();
        }
      } else {
        replay();
        this.diagnosticsAndContexts.clear();
      }
    }
  }
}
