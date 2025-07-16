//! Fixed/Adaptable/Extensible classification definitions

/// Component classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentClassification {
    /// Fixed component - cannot be modified
    Fixed,
    
    /// Adaptable component - can be parameterized within defined bounds
    Adaptable,
    
    /// Extensible component - can be fully customized
    Extensible,
}

/// Component with classification
pub trait ClassifiedComponent {
    /// Get the component classification
    fn classification(&self) -> ComponentClassification;
    
    /// Check if the component can be modified
    fn can_modify(&self) -> bool {
        match self.classification() {
            ComponentClassification::Fixed => false,
            ComponentClassification::Adaptable | ComponentClassification::Extensible => true,
        }
    }
    
    /// Check if the component can be extended
    fn can_extend(&self) -> bool {
        match self.classification() {
            ComponentClassification::Fixed | ComponentClassification::Adaptable => false,
            ComponentClassification::Extensible => true,
        }
    }
}

/// Marker trait for fixed components
pub trait Fixed {}

/// Marker trait for adaptable components
pub trait Adaptable {}

/// Marker trait for extensible components
pub trait Extensible {}

// Instead of blanket implementations, we'll provide implementation helpers

/// Helper struct for fixed components
pub struct FixedComponent;

impl ClassifiedComponent for FixedComponent {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Fixed
    }
}

/// Helper struct for adaptable components
pub struct AdaptableComponent;

impl ClassifiedComponent for AdaptableComponent {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Adaptable
    }
}

/// Helper struct for extensible components
pub struct ExtensibleComponent;

impl ClassifiedComponent for ExtensibleComponent {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Extensible
    }
}
