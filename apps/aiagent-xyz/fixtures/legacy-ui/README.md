# Legacy visual fixture — never product authority

These components are the retired, disconnected aiagent.xyz visual prototype.
They contain hard-coded listings, financial values, runtime telemetry, wallet
success, audit success, and timer-driven console output.

They are retained only as design-history evidence. Nothing in `src/` imports
this directory, Vite does not include it in the production graph, and no route
serves it. Do not reconnect these components to a product path. New work must
use the domain client under `src/product/` and the canonical owner adapters.

