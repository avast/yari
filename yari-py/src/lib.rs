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
fn yr_value_to_py_object(py: Python<'_>, yr_value: &YrValue) -> PyObject {
    match yr_value {
        YrValue::Integer(i) => i.into_py(py),
        YrValue::Float(f) => f.into_py(py),
        YrValue::String(s) => s.as_ref().into_py(py),
        YrValue::Dictionary(d) => d
            .iter()
            .map(|(k, v)| (k, yr_value_to_py_object(py, v)))
            .collect::<HashMap<_, _>>()
            .into_py(py),
        YrValue::Array(a) => a
            .iter()
            .map(|val| yr_value_to_py_object(py, val))
            .collect::<Vec<_>>()
            .into_py(py),
        YrValue::Structure(s) => s
            .as_ref()
            .map(|map| {
                map.iter()
                    .map(|(k, v)| (k, yr_value_to_py_object(py, v)))
                    .collect::<HashMap<_, _>>()
            })
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
        rule_string: Option<&PyString>,
        rule_path: Option<&PyString>,
        module_data: Option<&PyDict>,
    ) -> PyResult<Self> {
        let mut builder = ContextBuilder::default();

        if let Some(sample) = sample {
            builder = builder.with_sample(Some(sample.to_string()));
        }

        // Use either `rule_string` or `rule_path`. Invalid configuration of arguments raises
        // exception.
        match (rule_string, rule_path) {
            (Some(rule_string), None) => {
                builder = builder.with_rule_string(Some(rule_string.to_string()))
            }
            (None, Some(rule_path)) => {
                builder = builder.with_rule_file(Some(rule_path.to_string()))
            }
            (Some(_), Some(_)) => {
                return Err(YariError::new_err(
                    "detected Context with both `rule_string` and `rule_path`, specify only one of the sources".to_string(),
                ))
            }
            // Create empty context if no source was specified
            (_, _) => {},
        }

        // Add the module data
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
    pub fn eval(&mut self, py: Python<'_>, expr: &str) -> PyResult<PyObject> {
        self.inner
            .eval(expr)
            .as_ref()
            .map(|val| yr_value_to_py_object(py, val))
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

    m.add("LICENSES", yari_sys::LICENSES)?;

    Ok(())
}
