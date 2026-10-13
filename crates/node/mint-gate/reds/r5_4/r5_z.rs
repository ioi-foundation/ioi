// Codex batch-3 r5 MINOR fixture: a function including an expression fragment with the spelling `include !`.
pub fn harmless() -> u8 {
    include ! ("r5_a.rs")
}
