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

/// Mark a component as fixed
pub trait Fixed: ClassifiedComponent {}

/// Mark a component as adaptable
pub trait Adaptable: ClassifiedComponent {}

/// Mark a component as extensible
pub trait Extensible: ClassifiedComponent {}

impl<T: Fixed> ClassifiedComponent for T {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Fixed
    }
}

impl<T: Adaptable> ClassifiedComponent for T {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Adaptable
    }
}

impl<T: Extensible> ClassifiedComponent for T {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Extensible
    }
}
