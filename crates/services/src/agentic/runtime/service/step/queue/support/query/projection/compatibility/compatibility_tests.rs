use super::*;

fn projection_for_query(query: &str) -> QueryConstraintProjection {
    build_query_constraint_projection(query, 2, &[])
}

#[test]
fn grounded_briefing_rejects_off_topic_authority_neighbor_fill() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let projection = projection_for_query(query);
    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2",
        "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM",
        "IBM explains the NIST Cybersecurity Framework 2.0 and broader cyber risk management.",
    );

    assert!(
        !compatibility_passes_projection(&projection, &compatibility),
        "off-topic authority-neighbor fill should not satisfy grounded briefing compatibility: {:?}",
        compatibility
    );
}

#[test]
fn grounded_briefing_keeps_on_topic_secondary_sources_compatible() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let projection = projection_for_query(query);
    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        "https://www.ibm.com/think/insights/post-quantum-cryptography-transition",
        "Post-quantum cryptography transition guidance",
        "March 2026 - IBM explains recent NIST post-quantum cryptography transition planning for enterprises.",
    );

    assert!(
        compatibility_passes_projection(&projection, &compatibility),
        "on-topic secondary coverage should remain compatible: {:?}",
        compatibility
    );
}

#[test]
fn grounded_briefing_contract_rejects_off_topic_authority_neighbor_with_execution_suffix() {
    let query_contract =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let projection = projection_for_query(query_contract);
    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2",
        "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM",
        "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos.",
    );

    assert!(
        !compatibility_passes_projection(&projection, &compatibility),
        "execution-contract suffix must not weaken subject grounding for off-topic authority-neighbor fill: {:?}",
        compatibility
    );
}
