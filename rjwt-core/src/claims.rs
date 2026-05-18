use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Error;

/// The [`Claims`] of a [`SignedToken`]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Claims<H, A, C> {
    pub(crate) exp: u64,
    host: H,
    actor_id: A,
    claims: C,
    inherit: Option<Box<Claims<H, A, C>>>,
}

impl<H, A, C> Claims<H, A, C> {
    pub(crate) fn new(exp: u64, host: H, actor_id: A, claims: C) -> Self {
        Self {
            exp,
            host,
            actor_id,
            claims,
            inherit: None,
        }
    }

    pub(crate) fn consume(self, host: H, actor_id: A, claims: C) -> Result<Self, Error> {
        let exp = self.expires().duration_since(UNIX_EPOCH)?;

        Ok(Self {
            exp: exp.as_secs(),
            host,
            actor_id,
            claims,
            inherit: Some(Box::new(self)),
        })
    }

    pub(crate) fn expires(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.exp)
    }
}

/// An iterator over the chain of [`Claims`] in a [`SignedToken`]
pub struct Iter<'a, H, A, C> {
    claims: Option<&'a Claims<H, A, C>>,
}

impl<'a, H: 'a, A: 'a, C: 'a> Iterator for Iter<'a, H, A, C> {
    type Item = (&'a H, &'a A, &'a C);

    fn next(&mut self) -> Option<Self::Item> {
        let claims = self.claims?;
        let item = (&claims.host, &claims.actor_id, &claims.claims);
        self.claims = claims.inherit.as_deref();
        Some(item)
    }
}

impl<H, A, C> Claims<H, A, C> {
    /// Iterate over this chain of claims from newest to oldest.
    pub fn iter(&self) -> Iter<'_, H, A, C> {
        Iter { claims: Some(self) }
    }
}

impl<H: PartialEq, A: PartialEq, C> Claims<H, A, C> {
    /// Get the most recent claim made with the given `actor_id` on the given `host`, if any.
    pub fn get(&self, host: &H, actor_id: &A) -> Option<&C> {
        self.iter()
            .filter_map(|(h, a, c)| {
                if h == host && a == actor_id {
                    Some(c)
                } else {
                    None
                }
            })
            .next()
    }
}

impl<'a, H, A, C> IntoIterator for &'a Claims<H, A, C> {
    type Item = (&'a H, &'a A, &'a C);
    type IntoIter = Iter<'a, H, A, C>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
