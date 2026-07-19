mod load;
pub mod model;

pub use load::{load, validate, ConfigError};
pub use model::{Listener, ListenerKind, ServerConfig};
