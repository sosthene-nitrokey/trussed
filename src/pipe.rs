#![allow(clippy::transmute_ptr_to_ptr)]
// Ignore lint caused by interchange! macro
#![allow(clippy::derive_partial_eq_without_eq)]

use interchange::{Interchange, InterchangeRef, Requester, Responder};

use crate::api::{Reply, Request};
use crate::backend::BackendId;
use crate::config;
use crate::error::Error;
use crate::types::Context;

type TrussedInterchangeInner =
    Interchange<Request, Result<Reply, Error>, { config::MAX_SERVICE_CLIENTS }>;
static TRUSSED_INTERCHANGE_INNER: TrussedInterchangeInner = Interchange::new();

pub type TrussedInterchange = InterchangeRef<'static, Request, Result<Reply, Error>>;
pub static TRUSSED_INTERCHANGE: TrussedInterchange = TRUSSED_INTERCHANGE_INNER.as_interchange_ref();

pub type TrussedResponder = Responder<'static, Request, Result<Reply, Error>>;
pub type TrussedRequester = Requester<'static, Request, Result<Reply, Error>>;

// pub use interchange::TrussedInterchange;

// TODO: The request pipe should block if there is an unhandled
// previous request/reply. As a side effect, the service should always
// be able to assume that the reply pipe is "ready".

// PRIOR ART:
// https://xenomai.org/documentation/xenomai-2.4/html/api/group__native__queue.html
// https://doc.micrium.com/display/osiiidoc/Using+Message+Queues

pub struct ServiceEndpoint<I: 'static, C> {
    pub interchange: TrussedResponder,
    // service (trusted) has this, not client (untrusted)
    // used among other things to namespace cryptographic material
    pub ctx: Context<C>,
    pub backends: &'static [BackendId<I>],
}

// pub type ClientEndpoint = Requester<TrussedInterchange>;
