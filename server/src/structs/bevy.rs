use std::{collections::HashMap, sync::Arc};

use bevy_ecs::prelude::*;
use dashmap::DashMap;
use futures::future::join_all;
use parking_lot::Mutex;
use wtransport::SendStream;

use crate::SessionCrypto;

pub struct PlayerConnection {
    pub stream: SendStream,
    pub crypto: SessionCrypto,
}

impl PlayerConnection {
    pub fn new(stream: SendStream, crypto: SessionCrypto) -> Self {
        Self { stream, crypto }
    }

    pub async fn send_encrypted(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ciphertext = self.crypto.encrypt(plaintext).unwrap();
        self.stream.write_all(&ciphertext).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct World {
    pub bevy_world: bevy_ecs::world::World,
    pub config: crate::config::config::Config,
}
pub type MWorld = Arc<Mutex<World>>;

pub type IDToConnection = DashMap<u8, Arc<Mutex<PlayerConnection>>>;

impl World {
    pub async fn send_to(id: u8, plaintext: &[u8], connections: &IDToConnection) {
        if let Some(conn_ref) = connections.get(&id) {
            let mut conn = conn_ref.lock();
            if let Err(e) = conn.send_encrypted(plaintext).await {
                tracing::warn!("Failed to send packet to player {}: {}", id, e);
            }
        }
    }

    pub async fn broadcast(plaintext: &[u8], connections: &IDToConnection) {
        let futures = connections.iter().map(|entry| {
            let conn = entry.value().clone();
            let data = plaintext.to_vec();

            async move {
                let mut lock = conn.lock();
                let _ = lock.send_encrypted(&data).await;
            }
        });

        join_all(futures).await;
    }

    pub async fn broadcast_with_exceptions(
        exceptions: &[u8],
        plaintext: &[u8],
        connections: &IDToConnection,
    ) {
        let futures = connections
            .iter()
            .filter(|entry| !exceptions.contains(entry.key()))
            .map(|entry| {
                let conn = entry.value().clone();
                let data = plaintext.to_vec();

                async move {
                    let mut lock = conn.lock();
                    let _ = lock.send_encrypted(&data).await;
                }
            });

        join_all(futures).await;
    }
}

#[derive(Debug, Resource)]
pub struct PlayerMap {
    pub map: HashMap<u8, Entity>,
}

impl Default for PlayerMap {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}
