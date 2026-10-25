#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Millis(pub u64);

#[derive(Debug)]
pub struct StorageError;

pub trait UserPresence {
    fn consume_presence(&mut self, now: Millis) -> bool;
}

pub trait CounterStore {
    fn increment(&mut self) -> Result<u32, StorageError>;
}
