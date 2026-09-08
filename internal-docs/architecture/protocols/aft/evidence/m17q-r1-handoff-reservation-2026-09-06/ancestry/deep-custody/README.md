# Complete distinct custody ancestry follow-up

Scoped campaign passed: 84 core and 21 runtime tests, CLI, format/syntax,
record/anchor/continuation/lifetime proof and model gates, both record and handoff
syscall checks. started.json and completed.json bind unchanged selected sources.

The handoff trace fixture uses handoff/state.scale and custody/nested/state.anchor.
The writer syncs the complete distinct state and custody ancestries before live
admission. Removing only the intermediate custody directory sync fails the
checker while the active anchor's immediate directory sync remains. Missing
state and anchor file syncs are separately rejected. Syscalls do not prove actual
power-loss behavior or worst-case timing. Ten anchor-ordering and ten continuation
proof obligations remain conditional on filesystem/nonrollback/live-Q premises.

The parent ancestry collector failure is retained: its last command contained
an extra script argument. This corrected collector passed all its declared gates;
no deadline, assertion or production requirement was weakened. The preceding
parent handoff-reservation source predates the ancestry repair.

No whole R1 finding, full R2, independent review or M18Q claim is closed. Separate
consequence-store changes postdate this campaign and require their own evidence.
