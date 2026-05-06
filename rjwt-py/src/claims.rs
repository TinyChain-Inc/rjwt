use std::str::FromStr;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use ::rjwt::Claims;

use crate::{A, C, H, claims_to_py};

/// The chain of claims carried by a SignedToken, from newest to oldest.
#[pyclass(name = "Claims")]
pub(crate) struct PyClaims(pub(crate) Claims<H, A, C>);

#[pymethods]
impl PyClaims {
    /// Return the most recent claim for ``(host, actor_id)``, or ``None``.
    ///
    /// The returned value is a ``dict[str, int]`` mapping path strings to mode bits.
    fn get(&self, py: Python<'_>, host: &str, actor_id: &str) -> PyResult<Option<PyObject>> {
        let h = host.to_string();
        let a = A::from_str(actor_id).map_err(|e| PyValueError::new_err(e.to_string()))?;
        match self.0.get(&h, &a) {
            Some(c) => Ok(Some(claims_to_py(py, c)?)),
            None => Ok(None),
        }
    }

    /// Return all claims as a list of ``(host_str, actor_id_str, dict[str, int])``
    /// tuples, from newest segment to oldest.
    fn iter(&self, py: Python<'_>) -> PyResult<Vec<(String, String, PyObject)>> {
        self.0
            .iter()
            .map(|(h, a, c)| {
                let py_c = claims_to_py(py, c)?;
                Ok((h.to_string(), a.to_string(), py_c))
            })
            .collect()
    }
}
