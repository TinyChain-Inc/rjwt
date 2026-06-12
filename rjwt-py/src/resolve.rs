use std::sync::Arc;

use pyo3::prelude::*;
use pyo3_async_runtimes::tokio::future_into_py;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pymethods};

use rjwt_core::{Actor, Error, Resolve};

use crate::actor::PyActor;
use crate::token::PySignedToken;
use crate::{A, C, H, to_py_err, unix_to_system_time};

struct InnerResolver {
    py_obj: Py<PyAny>,
}

// SAFETY: Py<PyAny> is a reference-counted pointer; it is only dereferenced
// while holding the GIL, which is enforced by the Python::attach calls below.
unsafe impl Send for InnerResolver {}
unsafe impl Sync for InnerResolver {}

impl Resolve for InnerResolver {
    type HostId = H;
    type ActorId = A;
    type Claims = C;

    fn resolve(
        &self,
        host: &H,
        actor_id: &A,
    ) -> impl std::future::Future<Output = Result<Actor<A>, Error>> + Send {
        // Convert Link/Id to strings before entering the async block so there
        // are no borrows of `self` inside the future.
        let host_str = host.to_string();
        let actor_str = actor_id.to_string();
        // clone_ref increments the CPython refcount; requires the GIL.
        let py_obj = Python::attach(|py| self.py_obj.clone_ref(py));

        async move {
            // Call Python's async resolve(host, actor_id).
            // Acquire the GIL to call the method and convert the coroutine to a
            // Rust Future, then release the GIL before awaiting.
            let future = Python::attach(|py| {
                let coro = py_obj
                    .call_method1(py, "resolve", (host_str.clone(), actor_str.clone()))
                    .map_err(|e: PyErr| Error::fetch(e.to_string()))?;
                pyo3_async_runtimes::tokio::into_future(coro.into_bound(py))
                    .map_err(|e: PyErr| Error::fetch(e.to_string()))
            })?;

            let result = future
                .await
                .map_err(|e: PyErr| Error::fetch(e.to_string()))?;

            // Extract the PyActor returned by Python.
            // Actor::clone() strips the private key, returning a public-key-only
            // actor suitable for signature verification.
            Python::attach(|py| {
                let py_actor: PyRef<'_, PyActor> = result.bind(py).extract()?;
                Ok::<_, PyErr>(py_actor.0.clone())
            })
            .map_err(|e: PyErr| Error::fetch(e.to_string()))
        }
    }
}

/// Wraps a Python object implementing ``async def resolve(host: str, actor_id: str) -> Actor``
/// and exposes a ``verify`` coroutine that decodes and validates signed JWT strings.
///
/// The Python resolver is responsible for looking up actors by host and ID and
/// returning an ``Actor`` constructed via ``Actor.with_public_key``.
#[gen_stub_pyclass]
#[pyclass(name = "Resolver")]
pub(crate) struct PyResolver {
    inner: Arc<InnerResolver>,
}

#[gen_stub_pymethods]
#[pymethods]
impl PyResolver {
    #[new]
    pub(crate) fn new(py_obj: Py<PyAny>) -> Self {
        Self {
            inner: Arc::new(InnerResolver { py_obj }),
        }
    }

    /// Decode and verify ``encoded`` as of ``now_unix`` (Unix timestamp, float seconds).
    ///
    /// Returns a coroutine that resolves to a ``SignedToken`` containing the full
    /// claim chain. Raises ``RuntimeError`` if the token is invalid or expired.
    fn verify<'py>(
        &self,
        py: Python<'py>,
        encoded: String,
        now_unix: f64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let now = unix_to_system_time(now_unix);
        // Arc::clone gives the async block an owned handle so the future is 'static.
        let inner = Arc::clone(&self.inner);

        future_into_py(py, async move {
            let signed = inner.verify(encoded, now).await.map_err(to_py_err)?;
            Ok(PySignedToken(signed))
        })
    }
}
