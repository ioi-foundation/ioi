//! Assertion utilities for testing

/// Assert that two byte arrays are equal
#[macro_export]
macro_rules! assert_bytes_eq {
    ($left:expr, $right:expr) => {
        assert_eq!($left.as_ref(), $right.as_ref());
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        assert_eq!($left.as_ref(), $right.as_ref(), $($arg)+);
    };
}

/// Assert that a result is OK and unwrap it
#[macro_export]
macro_rules! assert_ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => panic!("Expected Ok, got Err: {:?}", err),
        }
    };
    ($expr:expr, $($arg:tt)+) => {
        match $expr {
            Ok(val) => val,
            Err(err) => panic!("Expected Ok, got Err: {:?} ({})", err, format!($($arg)+)),
        }
    };
}

/// Assert that a result is Err and unwrap the error
#[macro_export]
macro_rules! assert_err {
    ($expr:expr) => {
        match $expr {
            Ok(val) => panic!("Expected Err, got Ok: {:?}", val),
            Err(err) => err,
        }
    };
    ($expr:expr, $($arg:tt)+) => {
        match $expr {
            Ok(val) => panic!("Expected Err, got Ok: {:?} ({})", val, format!($($arg)+)),
            Err(err) => err,
        }
    };
}

/// Assert that a value is within a specific range
#[macro_export]
macro_rules! assert_in_range {
    ($value:expr, $min:expr, $max:expr) => {
        assert!($value >= $min && $value <= $max, "{} not in range [{}, {}]", $value, $min, $max);
    };
    ($value:expr, $min:expr, $max:expr, $($arg:tt)+) => {
        assert!($value >= $min && $value <= $max, "{} not in range [{}, {}]: {}", $value, $min, $max, format!($($arg)+));
    };
}
