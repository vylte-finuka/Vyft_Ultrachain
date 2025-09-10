use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{mpsc, SetError};
use tokio::sync::OnceCell;

static NEXT_CHAIN_ID: AtomicUsize = AtomicUsize::new(1);

pub struct AsyncOnceCell<T> {
    cell: OnceCell<T>,
    shutdown_rx: mpsc::Sender<()>,
    chain_id: usize,
}

impl<T> AsyncOnceCell<T> {
    pub fn new() -> Self {
        let (shutdown_rx, _) = mpsc::channel(1);
        Self {
            cell: OnceCell::new(),
            shutdown_rx,
            chain_id: NEXT_CHAIN_ID.fetch_add(1, Ordering::SeqCst),
        }
    }

    pub async fn get_or_init<F, Fut>(&self, init: F) -> &T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        self.cell.get_or_init(init).await
    }

    pub fn get(&self) -> Option<&T> {
        self.cell.get()
    }

    pub fn set(&self, value: T) -> Result<(), SetError<T>> {
        self.cell.set(value)
    }

    pub fn state(&self) -> Option<&T> {
        self.cell.get()
    }

    pub fn get_mut(&mut self) -> Option<&mut T> {
        self.cell.get_mut()
    }

    pub fn set_mut(&mut self, value: T) -> Result<(), SetError<T>> {
        self.cell.set(value)
    }

    pub fn take(&mut self) -> Option<T> {
        self.cell.take()
    }

    pub fn subscribe_to_shutdown_channel(&self) -> mpsc::Sender<()> {
        self.shutdown_rx.clone()
    }

    pub fn get_chain_identifier(&self) -> usize {
        self.chain_id
    }
}