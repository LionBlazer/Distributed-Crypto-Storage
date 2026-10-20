//! One operation-owned socket cancellation/deadline scope and joined watcher.
//! It never owns private state or supplies verification/finality authority.
use super::*;
use peer_runtime::{RemotePeer, RequestScope, finality::ProgressFinalityClient};
use std::{
    sync::{Arc, Condvar, Mutex},
    thread::{self, JoinHandle},
    time::Instant,
};
pub(super) struct Operation {
    pub clients: Vec<ProgressFinalityClient>,
    pub remote: RemotePeer,
    scope: RequestScope,
    expires: Instant,
    stop: Arc<(Mutex<bool>, Condvar)>,
    watcher: Option<JoinHandle<()>>,
}
impl Operation {
    pub fn new(
        config: &Config,
        binding: &Binding,
        control: &RequestControl,
        budget: Duration,
    ) -> io::Result<Self> {
        let scope = control.begin()?;
        let expires = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| io::Error::other("Progress owner deadline overflow"))?;
        let clients = config
            .peers
            .iter()
            .map(|e| ProgressFinalityClient::new(config.connector.clone(), e.clone(), binding))
            .collect::<Vec<_>>();
        let remote = RemotePeer::new(config.fhe.clone(), config.connector.clone())
            .with_control(control.clone());
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let watched = stop.clone();
        let cancel = scope.cancellation();
        let sockets = clients.clone();
        let watcher = thread::Builder::new()
            .name("progress-owner-deadline".into())
            .spawn(move || {
                let (flag, wake) = &*watched;
                loop {
                    if cancel.is_cancelled() || Instant::now() >= expires {
                        cancel.cancel();
                        for client in &sockets {
                            client.cancel();
                        }
                        break;
                    }
                    let Ok(guard) = flag.lock() else {
                        cancel.cancel();
                        for client in &sockets {
                            client.cancel();
                        }
                        break;
                    };
                    if *guard {
                        break;
                    }
                    let wait = expires
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(20));
                    match wake.wait_timeout(guard, wait) {
                        Ok((guard, _)) if *guard => break,
                        Ok(_) => {}
                        Err(_) => {
                            cancel.cancel();
                            for client in &sockets {
                                client.cancel();
                            }
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            clients,
            remote,
            scope,
            expires,
            stop,
            watcher: Some(watcher),
        })
    }
    pub fn check(&self) -> core::result::Result<(), io::ErrorKind> {
        if Instant::now() >= self.expires {
            return Err(io::ErrorKind::TimedOut);
        }
        if self.scope.cancellation().is_cancelled() {
            return Err(io::ErrorKind::Interrupted);
        }
        Ok(())
    }
    pub fn stop_network(&self) {
        for client in &self.clients {
            client.cancel();
        }
    }
    pub fn finish(mut self) -> io::Result<()> {
        self.join()
    }
    fn join(&mut self) -> io::Result<()> {
        self.stop_network();
        let (flag, wake) = &*self.stop;
        if let Ok(mut stopped) = flag.lock() {
            *stopped = true;
            wake.notify_all();
        } else {
            self.scope.cancellation().cancel();
        }
        if let Some(watcher) = self.watcher.take() {
            watcher
                .join()
                .map_err(|_| io::Error::other("Progress deadline watcher panicked"))?;
        }
        Ok(())
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        let _ = self.join();
    }
}
