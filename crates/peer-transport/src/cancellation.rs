//! Cancellation owns only local RPC sockets, never peer processes or protocol state.
use std::{
    io,
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Default)]
pub struct RequestControl(Arc<Mutex<Option<Cancellation>>>);

/// One caller-owned operation. Dropping it ends the scope for future RPCs.
/// A later operation gets an independent token; an old cancel cannot affect it.
pub struct RequestScope {
    control: RequestControl,
    cancellation: Cancellation,
}
impl RequestControl {
    pub fn begin(&self) -> io::Result<RequestScope> {
        let mut active = self
            .0
            .lock()
            .map_err(|_| io::Error::other("Request control poisoned"))?;
        if active.is_some() {
            return Err(io::Error::other("An operation is already active"));
        }
        let cancellation = Cancellation::default();
        *active = Some(cancellation.clone());
        Ok(RequestScope {
            control: self.clone(),
            cancellation,
        })
    }
    pub fn current(&self) -> Option<Cancellation> {
        self.0.lock().ok().and_then(|active| active.clone())
    }
    pub fn cancel(&self) -> bool {
        if let Some(active) = self.current() {
            active.cancel();
            true
        } else {
            false
        }
    }
}
impl RequestScope {
    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
}
impl Drop for RequestScope {
    fn drop(&mut self) {
        if let Ok(mut active) = self.control.0.lock()
            && active
                .as_ref()
                .is_some_and(|token| Arc::ptr_eq(&token.0, &self.cancellation.0))
        {
            *active = None;
        }
    }
}

#[derive(Default)]
struct State {
    cancelled: AtomicBool,
    sockets: Mutex<Vec<Arc<TcpStream>>>,
}
#[derive(Clone, Default)]
pub struct Cancellation(Arc<State>);
impl Cancellation {
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }
    pub fn check(&self) -> io::Result<()> {
        if self.is_cancelled() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "RPC operation cancelled",
            ))
        } else {
            Ok(())
        }
    }
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        if let Ok(sockets) = self.0.sockets.lock() {
            for socket in sockets.iter() {
                let _ = socket.shutdown(Shutdown::Both);
            }
        }
    }
    pub(crate) fn register(&self, socket: &TcpStream) -> io::Result<Registration> {
        let mut sockets = self
            .0
            .sockets
            .lock()
            .map_err(|_| io::Error::other("Socket registry poisoned"))?;
        self.check()?;
        let socket = Arc::new(socket.try_clone()?);
        sockets.push(socket.clone());
        Ok(Registration {
            cancellation: self.clone(),
            socket,
        })
    }
}
pub(crate) struct Registration {
    cancellation: Cancellation,
    socket: Arc<TcpStream>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut sockets) = self.cancellation.0.sockets.lock() {
            sockets.retain(|socket| !Arc::ptr_eq(socket, &self.socket));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, net::TcpListener, sync::mpsc, time::Duration};
    #[test]
    fn cancellation_interrupts_blocked_socket_io_and_rejects_later_registrations() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_server, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let cancellation = Cancellation::default();
        let registered = cancellation.register(&socket).unwrap();
        let (sent, received) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let mut byte = [0];
            sent.send(socket.read_exact(&mut byte).is_err()).unwrap();
        });
        cancellation.cancel();
        assert!(received.recv_timeout(Duration::from_secs(1)).unwrap());
        thread.join().unwrap();
        assert!(cancellation.register(&_server).is_err());
        drop(registered);
        assert!(cancellation.0.sockets.lock().unwrap().is_empty());
    }
    #[test]
    fn old_cancellation_cannot_stop_a_new_operation() {
        let control = RequestControl::default();
        let first = control.begin().unwrap();
        let old = first.cancellation();
        assert!(control.begin().is_err());
        assert!(control.cancel());
        assert!(old.is_cancelled());
        drop(first);
        let second = control.begin().unwrap();
        old.cancel();
        assert!(!second.cancellation().is_cancelled());
        drop(second);
        assert!(!control.cancel());
    }
}
