use bevy_ecs::prelude::*;
use shared::structs::server::Player;

// increase map based on player count.
// map will be infinite, however there will be a boundary where
// you will slow down and get damage (~30 dps)

pub fn map_system(mut query: Query<(&mut Player)>) {}
