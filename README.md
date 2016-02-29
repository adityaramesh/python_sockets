# Overview

Experiments involving sockets in Python.

# Notes

## Summary

- Use `signalfd` to respond to signals.
- Carefully consider which signals we should detect and respond to.
- If your program does not have real-time constraints, consider using `TCP_SOCK`. On the other hand,
  if your program does have real-time constraints, use `TCP_NODELAY`.
- When sending sporradic notifications to a set of clients, register the outgoing connections with
  `EPOLLONESHOT`. This avoids busy-waiting on the sending thread when sockets are available for
  writing, but we have no data to send.
- When occasional event notifications need to be send between a server and client that are
  continuously communicating using over a main channel, consider using the out-of-band feature of TCP
  instead of opening another socket for this purpose. Linux's `send` explicitly supports this. 
- To send messages from a worker thread to an epoll-loop thread, use eventfd.

## Efficiency

- If only one dedicated connection needs to be open, then using a dedicated thread with blocking IO
  does not consume many cycles. Using htop shows that the server program only uses 1--2% CPU.

- If many dedicated connections need to be open, then one approach is to use two threads for the
  server. One thread listens for incoming connections and appends them to a shared list, while
  another loops over the list of available connections, draining any that have available data and
  removing any that have closed.
- This approach consumes 100% CPU, even if we sleep for a short amount of time at each iteration of
  the loops run by both workers.
- We can avoid this problem by sleeping for a much longer amount of time (e.g. 500 ms), but this
  greatly increases the response time.

- If it is not crucial for each message to get sent as soon as it is produced, then specifying
  TCP_CORK with `setsockopt` is recommended. This allows the OS to buffer outgoing messages instead
  of sending them as soon as they are produced.
- For real-time applications like SSH clients, the TCP_NODELAY option, which causes the OS to send
  the message as soon as it is produced, is recommended. This does the opposite of TCP_CORK.
- See [this tutorial][epoll_tutorial] for more information.

## Exception Handling

- One must be careful to avoid calling cleanup functions twice if signal handlers are registered.
  This is because KeyboardInterrupt, InterruptedError, and SystemExit may be raised at the same time
  a signal is triggered. In this case, the exceptions should be suppressed, since the signal handler
  should take care of the cleanup on its own.

## Signal Handling

- [This article][about_signals] is a great source of information about the salient points in dealing
  with signals. The notes below are in large part based on information from the article.

- Ways in which a process can receive signals:
  - From another process in userspace (e.g. ``kill``).
  - Sent from program to itself (e.g. ``raise``, ``abort``).
  - Child process exits and sends SIGCHLD to the parent. Warning: this can interrupt system calls,
    but in Python things have been revised so that system calls that return EINTR are automatically
    retried, unless the signal handler throws an exception.
  - Parent process dies or hangup is detected on the controlling terminal, resulting in SIGHUP.
  - User interrupts program from keyboard (one possible signal is SIGINT).
  - Incorrect program behavior (SIGILL, SIGFPE, SIGSEGV).
  - Program accesses memory that is mapped by ``mmap``, but is not available.
  - When a profiler is used (SIGPROF) will occasionally be sent. Warning: this can also interrupt
    system calls.
  - When an IO function (e.g. ``write``) fails because nobody is on the other end to receive the
    data. This causes SIGPIPE to be sent. Warning: in such a case, the system call may exit with an
    error **and** SIGPIPE may be sent.

- Three approaches to deal with signals:
  - (1) Use ``signal``. This function is deprecated, because the handler is reset each time it is
    called. Restoring the handler safely is difficult to do, because we must ensure a race in which
    ``signal`` is called again before we are able to reset the handler does not occur.
  - (2) Use ``sigaction``. The default behavior is to not reset the handler each time it is called.
    In addition, the signal that triggered the handler is blocked until the handler finishes
    execution (unless SA_NODEFER is specified). Other signals can also be blocked using the
    `sa_mask` argument.
  - (3) Use ``signalfd``, possibly along with ``select`` or ``poll``. This allows one to handle
    signals in a synchronous way, as part of the normal control flow of the same thread that is
    running the rest of the program. This allows us to respond to the signal without being subject
    to the severe restrictions imposed on what can be done in a signal handler registered using
    ``signal`` or ``sigaction``.

- One must be careful when using either of these approaches if signals being coalesced can cause
  undesirable behavior. In this case, one must use the "self-pipe trick", as described in [this
  article][signalfd_problems].
- Option (3) is probably the best option to use for a server thread, since subtle race conditions
  may be introduced if the signal handler is not used in a careful manner (see the link for more
  information).

- Which signals should we respond to? In this project, we only respond to signals that indicidate
  that we should shutdown. These signals are the following: SIGHUP, SIGINT, SIGQUIT, SIGABRT, and
  SIGTERM.

- Options for dealing with signals in a ``select`` loop without introducing races that could cause
  the program to effectively ignore the signal and hang.
  - (1) Continue looping as long as a certain termination condition is not set. Block the signals
    that we wish to handle so that they can only be triggered during the system call to ``select``.
    In the signal handler, set the termination condition to true. The type of the flag used should
    have guaranteed atomic read and write access (i.e. `is_lock_free<T>` should be true).
  - (2) Similar to the above, but use ``signalfd`` instead of ``sigaction``. Using ``signalfd``
    implies that we have blocked all of the signals to which we wish to respond. All system calls we
    encounter must be non-blocking, since they will never get interrupted by the signals we have
    blocked.
  - (3) Use an infinite loop and a signal handler. In the handler, clean up all of the resources and
    call ``exit``. This option is not very good, because the restrictions on what one can do in a
    signal handler will likely prevent us from being able to free the resources.

[epoll_tutorial]: http://scotdoyle.com/python-epoll-howto.html
[about_signals]: https://www.linuxprogrammingblog.com/all-about-linux-signals?page=show
[signalfd_problems]: https://ldpreload.com/blog/signalfd-is-useless
