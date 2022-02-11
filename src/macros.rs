//! Helper macros.

/// Declare a [newtype] wrapper for the given array type alias.
///
/// # Trait implementations
///
/// - [`From`] to wrap an array
/// - [`AsRef`] to reference the wrapped array
///
/// [newtype]: https://rust-unofficial.github.io/patterns/patterns/behavioural/newtype.html
macro_rules! type_wrapper {
    ($newtype_name:ident, $array_type_name:ty) => {
        #[derive(Clone)]
        #[repr(transparent)]
        pub struct $newtype_name($array_type_name);

        impl From<$array_type_name> for $newtype_name {
            fn from(array: $array_type_name) -> Self {
                $newtype_name(array)
            }
        }

        impl AsRef<$array_type_name> for $newtype_name {
            fn as_ref(&self) -> &$array_type_name {
                &self.0
            }
        }
    };
}

pub(crate) use type_wrapper;
