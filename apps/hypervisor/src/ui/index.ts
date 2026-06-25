// Hypervisor UX kit — barrel. Importing from "../ui" pulls the design-system stylesheet + all
// primitives and composition primitives. Surfaces consume ONLY this (no bespoke inline styling).
import "./kit.css";
export * from "./primitives";
export * from "./patterns";
