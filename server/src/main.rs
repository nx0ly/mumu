use std::{
    sync::{atomic::AtomicU8, Arc},
    time::Duration,
};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use bevy_ecs::prelude::*;
use dashmap::DashMap;
use parking_lot::Mutex;
use shared::structs::server::{Move, Player};
use shared::to_server::SpawnMessage;
use shared::PacketType;
use tokio::sync::mpsc as god;
use wtransport::*;

use hkdf::Hkdf;
use pqc_kyber::{self, KYBER_PUBLICKEYBYTES, KYBER_SSBYTES};

use nanorand::{Rng, WyRand};

use crate::{
    config::config::load_config,
    errors::{GameError, InternalGameMessages},
    structs::bevy::{PlayerMap, World},
};

mod config;
mod errors;
mod structs;
mod systems;

use borsh_derive::{BorshDeserialize, BorshSerialize};

#[derive(BorshSerialize, BorshDeserialize)]
struct ClientHello {
    x25519_pk: [u8; 32],
    kyber_pk: Vec<u8>, // kyber768 public key
}

#[derive(BorshSerialize, BorshDeserialize)]
struct ServerHello {
    x25519_pk: [u8; 32],
    kyber_ct: Vec<u8>, // kyber768 ciphertext (1088 bytes)
}

struct SessionCrypto {
    cipher: ChaCha20Poly1305,
    recv_nonce: u64,
    send_nonce: u64,
}

impl SessionCrypto {
    fn new(key: [u8; 32]) -> Self {
        let key = Key::from_slice(&key);
        Self {
            cipher: ChaCha20Poly1305::new(key),
            recv_nonce: 0,
            send_nonce: 0,
        }
    }

    // format: [0,0,0,0 | counter_be_bytes]
    fn make_nonce(counter: u64) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[4..].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&bytes)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let nonce = Self::make_nonce(self.recv_nonce);
        self.recv_nonce = self.recv_nonce.wrapping_add(1);
        self.cipher.decrypt(&nonce, ciphertext)
    }

    // encrypt outgoing with automatic increment
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let nonce = Self::make_nonce(self.send_nonce);
        self.send_nonce = self.send_nonce.wrapping_add(1);
        self.cipher.encrypt(&nonce, plaintext)
    }
}

// performs a hybrid post-quantum key exchance (25519 & kyber768)
// derives a session key using hkdf-sha256
async fn perform_handshake(
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> anyhow::Result<SessionCrypto> {
    // make x25519 keypair
    let server_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_public = PublicKey::from(&server_secret);

    let mut buf = vec![0u8; 4096]; // Kyber768 PK is 1184 bytes + X25519 is 32 bytes + borsh overhead (thanks friend)

    let len = recv
        .read(&mut buf)
        .await?
        .ok_or_else(|| anyhow::anyhow!("stream closed during handshake"))?;

    let client_hello: ClientHello = borsh::from_slice(&buf[..len])?;

    // x25519 ecdh
    let client_x25519_pk = PublicKey::from(client_hello.x25519_pk);
    let x25519_shared_secret = server_secret.diffie_hellman(&client_x25519_pk);

    // verify size
    if client_hello.kyber_pk.len() != KYBER_PUBLICKEYBYTES {
        return Err(anyhow::anyhow!(
            "invalid kyber public key size: expected {}, got {}",
            KYBER_PUBLICKEYBYTES,
            client_hello.kyber_pk.len()
        ));
    }

    // do kyber768 encapsulation
    let (kyber_ciphertext, kyber_shared_secret) =
        pqc_kyber::encapsulate(&client_hello.kyber_pk, &mut OsRng).unwrap();

    // derive the session key using hkde-sha256
    // combine both secrets
    let mut combined_secret = Vec::with_capacity(32 + KYBER_SSBYTES);
    combined_secret.extend_from_slice(x25519_shared_secret.as_bytes());
    combined_secret.extend_from_slice(&kyber_shared_secret);

    let hkdf = Hkdf::<Sha256>::new(None, &combined_secret);

    let mut session_key = [0u8; 32];
    hkdf.expand(b"mumu", &mut session_key)
        .map_err(|_| anyhow::anyhow!("hkdf expansion failed"))?;

    let server_hello = ServerHello {
        x25519_pk: *server_public.as_bytes(),
        kyber_ct: kyber_ciphertext[..].to_vec(),
    };

    let response_bytes = borsh::to_vec(&server_hello)?;
    send.write_all(&response_bytes).await?;

    tracing::info!("jaja working im such a GOD");

    Ok(SessionCrypto::new(session_key))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = load_config().expect("failed to load config");

    let world = Arc::new(Mutex::new(World {
        bevy_world: bevy_ecs::world::World::new(),
        config,
    }));

    let id_to_stream: Arc<DashMap<u8, SendStream>> = Arc::new(DashMap::new());
    let id_to_player: Arc<DashMap<u8, Player>> = Arc::new(DashMap::new());

    let mut schedule = Schedule::default();

    let (input_tx, mut input_rx) = god::channel::<(u8, InternalGameMessages)>(1024);

    let net_streams = id_to_stream.clone();
    let net_players = id_to_player.clone();
    let net_input_tx = input_tx.clone();

    let identity = Identity::load_pemfiles("cert.pem", "key.pem")
        .await
        .expect("failed to load TLS certificate");

    let server_config = ServerConfig::builder()
        .with_bind_default(6767)
        .with_identity(identity)
        .build();

    let server = Endpoint::server(server_config)?;
    tracing::info!("port 6767");

    let player_count = AtomicU8::new(0);

    // Spawn networking task
    tokio::spawn(async move {
        loop {
            let session_req = match server.accept().await.await {
                Ok(req) => req,
                Err(e) => {
                    tracing::error!("failed to accept session: {}", e);
                    continue;
                }
            };

            let player_id = player_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            let conn_streams = net_streams.clone();
            let conn_players = net_players.clone();
            let tx = net_input_tx.clone();

            tokio::spawn(async move {
                let _session = PlayerSession {
                    id: player_id,
                    streams: conn_streams.clone(),
                    players: conn_players.clone(),
                    tx: tx.clone(),
                };

                let mut rng = WyRand::new();

                let connection = match session_req.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::error!("failed to accept connection: {}", e);
                        return;
                    }
                };

                let (mut send_stream, mut recv_stream) = match connection.accept_bi().await {
                    Ok(streams) => streams,
                    Err(e) => {
                        tracing::error!("failed to open bidirectional stream: {}", e);
                        return;
                    }
                };

                // handshake msgs (clienthello/serverhello)
                let mut crypto = match perform_handshake(&mut send_stream, &mut recv_stream).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("handshake failed for player {}: {}", player_id, e);
                        connection.close(VarInt::from_u32(1), b"handshake Failed");
                        return;
                    }
                };

                tracing::info!("player {} connected - session encrypted", player_id);
                conn_streams.insert(player_id, send_stream);

                // ok now everything else is encrypted with chacha20poly1305
                let mut buf = [0u8; 2048];

                loop {
                    let ciphertext_len = match recv_stream.read(&mut buf).await {
                        Ok(None) => break,
                        Ok(Some(len)) => len,
                        Err(e) => {
                            tracing::error!("stream read error: {}", e);
                            return;
                        }
                    };

                    let plaintext = match crypto.decrypt(&buf[..ciphertext_len]) {
                        Ok(data) => data,
                        Err(_) => {
                            tracing::warn!(
                                "decryption failed for player {} - possible replay attack",
                                player_id
                            );
                            connection.close(VarInt::from_u32(2), b"why ass");
                            return;
                        }
                    };

                    if plaintext.is_empty() {
                        continue;
                    }

                    let opcode = match plaintext.first() {
                        Some(op) => *op,
                        None => {
                            connection.close(VarInt::from_u32(67), b"why ass");
                            return;
                        }
                    };

                    match PacketType::from_u8(opcode) {
                        Some(PacketType::Spawn) => {
                            let data = match decode::<SpawnMessage>(&plaintext[1..]) {
                                Ok(data) => data,
                                Err(_) => {
                                    connection.close(VarInt::from_u32(67), b"why ass");
                                    return;
                                }
                            };

                            let r = rng.generate::<u64>();
                            let x = (r & 0xFFFF_FFFF) as f32 / u32::MAX as f32;
                            let y = (r >> 32) as f32 / u32::MAX as f32;

                            if tx
                                .send((
                                    player_id,
                                    InternalGameMessages::AddPlayer(Player {
                                        name: data.name,
                                        x,
                                        y,
                                        id: player_id,
                                        move_dir: None,
                                        vx: 0.,
                                        vy: 0.,
                                        attacked: false,
                                        weapon_index: Some(0),
                                    }),
                                ))
                                .await
                                .is_err()
                            {
                                tracing::error!("failed to send spawn message to ECS");
                            }
                        }
                        Some(PacketType::Move) => {
                            if tx
                                .send((
                                    player_id,
                                    InternalGameMessages::MovePlayer(Move { dir: 3.1 }),
                                ))
                                .await
                                .is_err()
                            {
                                tracing::error!("failed to send move message to ECS");
                            }
                        }
                        None => {
                            tracing::warn!("unknown packet type: {}", opcode);
                        }
                    }
                }

                tracing::info!("player {} gone", player_id);
            });
        }
    });

    schedule.add_systems(systems::movement_system);
    // maybe reduce interval idk
    let mut interval = tokio::time::interval(Duration::from_millis(67));

    loop {
        interval.tick().await;

        let mut world = world.lock();

        while let Ok((id, msg)) = input_rx.try_recv() {
            match msg {
                InternalGameMessages::AddPlayer(p) => {
                    let entity = world.bevy_world.spawn(p).id();
                    let mut player_map = world
                        .bevy_world
                        .get_resource_or_insert_with(PlayerMap::default);
                    player_map.map.insert(id, entity);
                }
                InternalGameMessages::MovePlayer(move_dir) => {
                    if let Some(player_map) = world.bevy_world.get_resource::<PlayerMap>() {
                        if let Some(&entity) = player_map.map.get(&id) {
                            if let Some(mut player) = world.bevy_world.get_mut::<Player>(entity) {
                                player.move_dir = Some(move_dir.dir);
                            }
                        }
                    }
                }
                InternalGameMessages::Disconnect => {
                    if let Some(player_map) = world.bevy_world.get_resource::<PlayerMap>() {
                        if let Some(&entity) = player_map.map.get(&id) {
                            if let Some(player) = world.bevy_world.get::<Player>(entity) {
                                tracing::info!("player {} ({}) gone", player.name, id);
                            }
                            world.bevy_world.despawn(entity);
                        }
                    }
                }
            }
        }

        schedule.run(&mut world.bevy_world);
        drop(world);
    }
}

fn decode<T>(buf: &[u8]) -> Result<T, GameError>
where
    T: borsh::BorshDeserialize,
{
    borsh::from_slice::<T>(buf)
        .map_err(|_| GameError::Client(errors::ClientProducedError::FaultyMessage))
}

struct PlayerSession {
    id: u8,
    streams: Arc<DashMap<u8, SendStream>>,
    players: Arc<DashMap<u8, Player>>,
    tx: god::Sender<(u8, InternalGameMessages)>,
}

impl Drop for PlayerSession {
    fn drop(&mut self) {
        self.streams.remove(&self.id);
        self.players.remove(&self.id);
        let _ = self
            .tx
            .try_send((self.id, InternalGameMessages::Disconnect));
    }
}
