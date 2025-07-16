//! Tests for the component classification system

// Change module definition to avoid "tests::tests" inception
#[cfg(test)]
mod component_tests {
    use crate::component::{
        Adaptable, AdaptableComponent, ClassifiedComponent, ComponentClassification, Extensible,
        ExtensibleComponent, Fixed, FixedComponent,
    };

    // Test struct implementing Fixed trait
    struct TestFixedComponent;
    impl Fixed for TestFixedComponent {}

    // Test struct implementing Adaptable trait
    struct TestAdaptableComponent;
    impl Adaptable for TestAdaptableComponent {}

    // Test struct implementing Extensible trait
    struct TestExtensibleComponent;
    impl Extensible for TestExtensibleComponent {}

    #[test]
    fn test_fixed_component() {
        let component = FixedComponent;
        assert_eq!(component.classification(), ComponentClassification::Fixed);
        assert!(!component.can_modify());
        assert!(!component.can_extend());
    }

    #[test]
    fn test_adaptable_component() {
        let component = AdaptableComponent;
        assert_eq!(
            component.classification(),
            ComponentClassification::Adaptable
        );
        assert!(component.can_modify());
        assert!(!component.can_extend());
    }

    #[test]
    fn test_extensible_component() {
        let component = ExtensibleComponent;
        assert_eq!(
            component.classification(),
            ComponentClassification::Extensible
        );
        assert!(component.can_modify());
        assert!(component.can_extend());
    }

    // TODO: Add more comprehensive tests covering:
    // - Custom components with the classification system
    // - Component compatibility checks
    // - Classification inheritance
    // - Component composition with mixed classifications
}
