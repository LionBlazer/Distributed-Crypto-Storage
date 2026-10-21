//! Synchronous client I/O over readiness and an explicit cross-thread wakeup.
//! Every registered socket operation uses Mio, including Windows rearming.
use mio::{Events, Interest, Poll, Token, Waker, net::TcpStream};
use std::{
    io::{self, IoSlice, IoSliceMut, Read, Write},
    net,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

const SOCKET: Token = Token(0);
const WAKE: Token = Token(1);
const CANCELLED: u8 = 1;
const EXPIRED: u8 = 2;

pub(crate) struct Interrupt {
    reason: AtomicU8,
    waker: Waker,
}
impl Interrupt {
    fn stop(&self, reason: u8) {
        let _ = self
            .reason
            .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire);
        let _ = self.waker.wake();
    }
    pub(crate) fn cancel(&self) {
        self.stop(CANCELLED);
    }
    pub(crate) fn expire(&self) {
        self.stop(EXPIRED);
    }
    fn check(&self) -> io::Result<()> {
        match self.reason.load(Ordering::Acquire) {
            0 => Ok(()),
            EXPIRED => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Connection deadline expired",
            )),
            // Interrupted is retried by rustls and std read_exact/write_all.
            _ => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "RPC operation cancelled",
            )),
        }
    }
}

pub(crate) struct Socket {
    stream: TcpStream,
    poll: Poll,
    events: Events,
    interrupt: Arc<Interrupt>,
    timeout: Mutex<Duration>,
}
impl Socket {
    pub(crate) fn new(socket: net::TcpStream) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        let mut stream = TcpStream::from_std(socket);
        let poll = Poll::new()?;
        poll.registry().register(
            &mut stream,
            SOCKET,
            Interest::READABLE.add(Interest::WRITABLE),
        )?;
        let interrupt = Arc::new(Interrupt {
            reason: AtomicU8::new(0),
            waker: Waker::new(poll.registry(), WAKE)?,
        });
        Ok(Self {
            stream,
            poll,
            events: Events::with_capacity(2),
            interrupt,
            timeout: Mutex::new(crate::IO_TIMEOUT),
        })
    }
    pub(crate) fn interrupt(&self) -> Arc<Interrupt> {
        self.interrupt.clone()
    }
    pub(crate) fn check(&self) -> io::Result<()> {
        self.interrupt.check()
    }
    pub(crate) fn set_io_timeout(&self, timeout: Duration) -> io::Result<()> {
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Zero I/O timeout",
            ));
        }
        *self
            .timeout
            .lock()
            .map_err(|_| io::Error::other("Client I/O policy poisoned"))? = timeout;
        Ok(())
    }
    pub(crate) fn into_owned(mut self) -> io::Result<net::TcpStream> {
        if Arc::strong_count(&self.interrupt) != 1 {
            return Err(io::Error::other("Connection interrupt is still shared"));
        }
        self.check()?;
        self.poll.registry().deregister(&mut self.stream)?;
        let socket: net::TcpStream = self.stream.into();
        socket.set_nonblocking(false)?;
        Ok(socket)
    }
    fn perform<T>(
        &mut self,
        interest: Interest,
        mut operation: impl FnMut(&mut TcpStream) -> io::Result<T>,
    ) -> io::Result<T> {
        // Copy configuration before I/O; no mutex spans readiness or TLS work.
        let timeout = *self
            .timeout
            .lock()
            .map_err(|_| io::Error::other("Client I/O policy poisoned"))?;
        let expires = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "I/O timeout overflow"))?;
        loop {
            self.check()?;
            if Instant::now() >= expires {
                return Err(io::Error::from(io::ErrorKind::TimedOut));
            }
            match operation(&mut self.stream) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    self.check()?;
                    return result;
                }
            }
            self.poll
                .registry()
                .reregister(&mut self.stream, SOCKET, interest)?;
            loop {
                self.check()?;
                let remaining = expires
                    .checked_duration_since(Instant::now())
                    .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
                match self.poll.poll(&mut self.events, Some(remaining)) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                }
                self.check()?;
                break;
            }
        }
    }
}
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.perform(Interest::READABLE, |stream| stream.read(bytes))
    }
    fn read_vectored(&mut self, bytes: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.perform(Interest::READABLE, |stream| stream.read_vectored(bytes))
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.perform(Interest::WRITABLE, |stream| stream.write(bytes))
    }
    fn write_vectored(&mut self, bytes: &[IoSlice<'_>]) -> io::Result<usize> {
        self.perform(Interest::WRITABLE, |stream| stream.write_vectored(bytes))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.perform(Interest::WRITABLE, Write::flush)
    }
}
