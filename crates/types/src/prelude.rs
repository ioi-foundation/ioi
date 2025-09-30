// Path: crates/types/src/prelude.rs

//! A curated set of commonly used traits and types.

/// An extension trait for `Option` that provides a convenient `required` method
/// to convert an `Option` to a `Result` with a specific error.
pub trait OptionExt<T> {
    /// Converts an `Option<T>` to a `Result<T, E>`, returning the provided
    /// error if the option is `None`.
    fn required<E>(self, err: E) -> Result<T, E>;
}

impl<T> OptionExt<T> for Option<T> {
    fn required<E>(self, err: E) -> Result<T, E> {
        self.ok_or(err)
    }
}
