use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::types::PyString;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use yari_sys::Context as YARIContext;
use yari_sys::ContextBuilder;
use yari_sys::Module;
use yari_sys::YrValue;

// Exception type for yari python module.
create_exception!(yari, YariError, PyException);

/// Python `Context` wrapper.
#[pyclass(unsendable)]
struct Context {
    inner: YARIContext,
}

/// Helper to convert `YrValue` to a `PyObject`.
///
/// Return values are modeled similar to Python built-in `eval` function. This function converts
/// values to the Python native types. For example `Vec<YrValue>` is converted to `list[YrValue]`.
/// Same applies to structures and dictionaries.
fn yr_value_to_py_object(yr_value: &YrValue) -> PyObject {
    let gil = Python::acquire_gil();
    let py = gil.python();

    match yr_value {
        YrValue::Integer(i) => i.into_py(py),
        YrValue::Float(f) => f.into_py(py),
        YrValue::String(s) => s.into_py(py),
        YrValue::Dictionary(d) => d
            .iter()
            .map(|(k, v)| (k, yr_value_to_py_object(v)))
            .collect::<HashMap<_, _>>()
            .into_py(py),
        YrValue::Array(a) => a
            .iter()
            .map(yr_value_to_py_object)
            .collect::<Vec<_>>()
            .into_py(py),
        YrValue::Structure(s) => s
            .iter()
            .map(|(k, v)| (k, yr_value_to_py_object(v)))
            .collect::<HashMap<_, _>>()
            .into_py(py),
    }
}

#[pymethods]
impl Context {
    /// Context constructor.
    ///
    /// Call without arguments will initialize default context matching /dev/null, without rule or
    /// any module data. `sample` and `rule` are expected to be valid paths. `module_data` is a
    /// python dictionary where key is a module name and data is a path to a file.
    #[new]
    fn new(
        sample: Option<&PyString>,
        rule: Option<&PyString>,
        module_data: Option<&PyDict>,
    ) -> PyResult<Self> {
        let mut builder = ContextBuilder::default();

        if let Some(sample) = sample {
            builder = builder.with_sample(Some(sample.to_string()));
        }

        if let Some(rule) = rule {
            builder = builder.with_rule_file(Some(rule.to_string()));
        }

        if let Some(module_data) = module_data {
            for (module, data) in module_data {
                if let (Ok(module), Ok(data)) =
                    (module.downcast::<PyString>(), data.downcast::<PyString>())
                {
                    let module = Module::from_str(module.to_str().unwrap())
                        .map_err(|e| YariError::new_err(e.to_string()))?;
                    builder =
                        builder.with_module_data(module, PathBuf::from(data.to_str().unwrap()))
                }
            }
        }

        Ok(Context {
            inner: builder
                .build()
                .map_err(|e| YariError::new_err(e.to_string()))?,
        })
    }

    /// Evaluate YARA expression.
    ///
    /// This function behaves like python build-in `eval` function and returns dynamic type based
    /// on the evaluation result.
    pub fn eval(&mut self, expr: &str) -> PyResult<PyObject> {
        self.inner
            .eval(expr)
            .as_ref()
            .map(yr_value_to_py_object)
            .map_err(|e| YariError::new_err(e.to_string()))
    }

    /// Evaluate YARA expression returning `bool` using YARA conversion rules.
    pub fn eval_bool(&mut self, expr: &str) -> PyResult<bool> {
        self.inner
            .eval(expr)
            .and_then(|res| res.try_into())
            .map_err(|e| YariError::new_err(e.to_string()))
    }
}

#[pymodule]
fn yari(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Context>()?;

    m.add("YariError", py.get_type::<YariError>())?;

    Ok(())
}
