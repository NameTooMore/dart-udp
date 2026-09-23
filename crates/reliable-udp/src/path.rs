use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathBinding {
    peer: SocketAddr,
}

impl PathBinding {
    pub const fn new(peer: SocketAddr) -> Self {
        Self { peer }
    }

    pub const fn peer(self) -> SocketAddr {
        self.peer
    }
}

impl From<SocketAddr> for PathBinding {
    fn from(peer: SocketAddr) -> Self {
        Self::new(peer)
    }
}
