// Path: crates/api/src/component/classification.rs
//! Traits and enums for the Fixed/Adaptable/Extensible classification system.

/// Defines the modification and extension capabilities of a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentClassification {
    /// The component's implementation is fixed and cannot be modified.
    Fixed,

    /// The component can be parameterized within defined bounds but not replaced.
    Adaptable,

    /// The component's implementation can be fully customized or replaced.
    Extensible,
}

/// A trait for components that have a defined classification.
pub trait ClassifiedComponent {
    /// Gets the component's classification.
    fn classification(&self) -> ComponentClassification;

    /// Checks if the component's parameters can be modified.
    fn can_modify(&self) -> bool {
        match self.classification() {
            ComponentClassification::Fixed => false,
            ComponentClassification::Adaptable | ComponentClassification::Extensible => true,
        }
    }

    /// Checks if the component's implementation can be extended or replaced.
    fn can_extend(&self) -> bool {
        match self.classification() {
            ComponentClassification::Fixed | ComponentClassification::Adaptable => false,
            ComponentClassification::Extensible => true,
        }
    }
}

/// A marker trait for fixed components.
pub trait Fixed {}

/// A marker trait for adaptable components.
pub trait Adaptable {}

/// A marker trait for extensible components.
pub trait Extensible {}
