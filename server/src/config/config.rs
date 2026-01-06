use config::File;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub map: MapConfig,
}

#[derive(Debug, Deserialize)]
pub struct MapConfig {
    pub initial: u16,
    pub increment_per_player: u16,
    pub dead_zone_dpt: u8,
}

pub fn load_config() -> Result<Config, config::ConfigError> {
    let config = config::Config::builder()
        .add_source(File::with_name("src/config/config.toml"))
        .build()?;
    config.try_deserialize()
}
