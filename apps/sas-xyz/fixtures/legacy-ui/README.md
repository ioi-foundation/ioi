# Legacy visual fixture — never product authority

`v2/` is the retired sas.xyz interaction prototype. It persisted operational
contracts to `localStorage`, generated receipt material in the browser, and
mutated provider and settlement-looking state without domain owners.

The production entry point does not import or serve it. It remains solely as
visual-design evidence. Functional work belongs in `src/`, with state changes
admitted through the domain API and its runtime, settlement, authority, and
storage owner adapters.

