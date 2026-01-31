use ipnet::IpNet;

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: String,
    pub origin: String,
    pub purgers: Vec<IpNet>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let listen = std::env::var("CODYCACHE_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let origin = std::env::var("CODYCACHE_ORIGIN").map_err(|_| "CODYCACHE_ORIGIN is required".to_string())?;
        let purgers_raw = std::env::var("CODYCACHE_PURGERS").unwrap_or_else(|_| "127.0.0.1/32,::1/128".to_string());
        let purgers = purgers_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<IpNet>().map_err(|e| format!("invalid CIDR/IP in CODYCACHE_PURGERS: {s}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { listen, origin, purgers })
    }
}
