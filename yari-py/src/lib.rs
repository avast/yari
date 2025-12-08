use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
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

/// Helper to convert `YrValue` to a `Bound<PyAny>`.
///
/// Return values are modeled similar to Python built-in `eval` function. This function converts
/// values to the Python native types. For example `Vec<YrValue>` is converted to `list[YrValue]`.
/// Same applies to structures and dictionaries.
fn yr_value_to_py_object<'py>(py: Python<'py>, yr_value: &YrValue) -> Bound<'py, PyAny> {
    match yr_value {
        YrValue::Integer(i) => (*i).into_pyobject(py).unwrap().into_any(),
        YrValue::Float(f) => (*f).into_pyobject(py).unwrap().into_any(),
        YrValue::String(s) => s.as_ref().into_pyobject(py).unwrap().into_any(),
        YrValue::Dictionary(d) => {
            let dict = PyDict::new(py);
            for (k, v) in d.iter() {
                let val = yr_value_to_py_object(py, v);
                dict.set_item(k, val).unwrap();
            }
            dict.into_any()
        }
        YrValue::Array(a) => {
            let list = PyList::empty(py);
            for val in a.iter() {
                let py_val = yr_value_to_py_object(py, val);
                list.append(py_val).unwrap();
            }
            list.into_any()
        }
        YrValue::Structure(s) => match s.as_ref() {
            Some(map) => {
                let dict = PyDict::new(py);
                for (k, v) in map.iter() {
                    let val = yr_value_to_py_object(py, v);
                    dict.set_item(k, val).unwrap();
                }
                dict.into_any()
            }
            None => py.None().into_bound(py),
        },
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
    #[pyo3(signature = (sample=None, rule_string=None, rule_path=None, module_data=None))]
    fn new(
        sample: Option<String>,
        rule_string: Option<String>,
        rule_path: Option<String>,
        module_data: Option<HashMap<String, String>>,
    ) -> PyResult<Self> {
        let mut builder = ContextBuilder::default();

        if let Some(sample) = sample {
            builder = builder.with_sample(Some(sample));
        }

        // Use either `rule_string` or `rule_path`. Invalid configuration of arguments raises
        // exception.
        match (rule_string, rule_path) {
            (Some(rule_string), None) => {
                builder = builder.with_rule_string(Some(rule_string));
            }
            (None, Some(rule_path)) => {
                builder = builder.with_rule_file(Some(rule_path));
            }
            (Some(_), Some(_)) => {
                return Err(YariError::new_err(
                    "detected Context with both `rule_string` and `rule_path`, specify only one"
                ))
            }
            (None, None) => {}
        }

        // Add the module data
        if let Some(module_data) = module_data {
            for (module_name, data_path) in module_data {
                let module = Module::from_str(&module_name)
                    .map_err(|e| YariError::new_err(e.to_string()))?;
                builder = builder.with_module_data(module, PathBuf::from(data_path));
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
    pub fn eval<'py>(&mut self, py: Python<'py>, expr: &str) -> PyResult<Bound<'py, PyAny>> {
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
fn yari(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Context>()?;

    // Add exception type
    m.add("YariError", m.py().get_type::<YariError>())?;

    m.add("LICENSES", yari_sys::LICENSES)?;

    Ok(())
}
