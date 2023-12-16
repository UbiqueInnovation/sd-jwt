use crate::Error;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone)]
pub struct Jwk {
    jwk: jsonwebtoken::jwk::Jwk,
}

impl Jwk {
    pub fn from_value(value: serde_json::Value) -> Result<Self, Error> {
        Ok(Jwk {
            jwk: serde_json::from_value(value)?,
        })
    }
}

impl Deref for Jwk {
    type Target = jsonwebtoken::jwk::Jwk;

    fn deref(&self) -> &Self::Target {
        &self.jwk
    }
}

impl DerefMut for Jwk {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.jwk
    }
}
