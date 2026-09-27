//! Named time zones for schedules (`America/New_York`, `Europe/Berlin`), read from the host's IANA
//! time-zone database: the TZif files under `$TZDIR` or `/usr/share/zoneinfo`. A named zone follows its
//! daylight-saving rules — the transition table for the years it covers, then the POSIX rule in the
//! file's footer — so a schedule at 09:00 New York stays at 09:00 New York across the change of
//! season. A zone the host does not have is refused by name; nothing falls back to a fixed offset.

/// One zone's offsets: transition instants (UTC seconds) with the UTC offset in force from each, the
/// offset before the first transition, and the footer rule for instants past the table.
pub(crate) struct Zone {
    transitions: Vec<(i64, i32)>,
    initial: i32,
    rule: Option<PosixRule>,
}

struct PosixRule {
    std: i32,
    dst: Option<(i32, RuleDate, i32, RuleDate, i32)>, // (dst offset, start, start time, end, end time)
}

#[derive(Clone, Copy)]
struct RuleDate {
    month: u8,
    week: u8,
    weekday: u8,
}

fn zone_path(name: &str) -> Result<std::path::PathBuf, String> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('/')
        && !name
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'));
    if !valid {
        return Err(format!("'{name}' is not a time zone name"));
    }
    let dir = std::env::var("TZDIR").unwrap_or_else(|_| "/usr/share/zoneinfo".to_string());
    Ok(std::path::Path::new(&dir).join(name))
}

pub(crate) fn load(name: &str) -> Result<Zone, String> {
    let path = zone_path(name)?;
    let bytes = std::fs::read(&path)
        .map_err(|_| format!("time zone '{name}' is not in this host's time-zone database"))?;
    parse(&bytes).map_err(|why| format!("time zone '{name}': {why}"))
}

fn be_u32(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "truncated TZif data".to_string())
}

fn be_i64(b: &[u8], at: usize) -> Result<i64, String> {
    b.get(at..at + 8)
        .map(|s| i64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
        .ok_or_else(|| "truncated TZif data".to_string())
}

fn parse(b: &[u8]) -> Result<Zone, String> {
    if b.get(0..4) != Some(&b"TZif"[..]) {
        return Err("not a TZif file".into());
    }
    let version = b.get(4).copied().unwrap_or(0);
    let counts = |at: usize| -> Result<[usize; 6], String> {
        let mut c = [0usize; 6];
        for (i, slot) in c.iter_mut().enumerate() {
            *slot = be_u32(b, at + 20 + i * 4)? as usize;
        }
        Ok(c)
    };
    // [isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt]
    let v1 = counts(0)?;
    let v1_len = v1[3] * 5 + v1[4] * 6 + v1[5] + v1[2] * 8 + v1[1] + v1[0];
    let (base, c, time_size) = if version >= b'2' {
        let at = 44 + v1_len;
        (at, counts(at)?, 8usize)
    } else {
        (0, v1, 4usize)
    };
    let (_, _, leapcnt, timecnt, typecnt, charcnt) = (c[0], c[1], c[2], c[3], c[4], c[5]);
    let data = base + 44;
    let times_at = data;
    let idx_at = times_at + timecnt * time_size;
    let types_at = idx_at + timecnt;
    let mut types = Vec::with_capacity(typecnt);
    for i in 0..typecnt {
        types.push(be_u32(b, types_at + i * 6)? as i32);
    }
    if types.is_empty() {
        return Err("no local time types".into());
    }
    let mut transitions = Vec::with_capacity(timecnt);
    for i in 0..timecnt {
        let t = if time_size == 8 {
            be_i64(b, times_at + i * 8)?
        } else {
            i64::from(be_u32(b, times_at + i * 4)? as i32)
        };
        let ty = *b.get(idx_at + i).ok_or("truncated TZif data")? as usize;
        transitions.push((t, *types.get(ty).ok_or("bad local time type index")?));
    }
    let rule = if version >= b'2' {
        let footer_at = types_at + typecnt * 6 + charcnt + leapcnt * 12 + c[1] + c[0];
        let footer = b.get(footer_at..).unwrap_or(&[]);
        let text = String::from_utf8_lossy(footer);
        let rule = text.trim_matches('\n');
        if rule.is_empty() {
            None
        } else {
            Some(parse_posix(rule)?)
        }
    } else {
        None
    };
    Ok(Zone {
        initial: types[0],
        transitions,
        rule,
    })
}

/// "EST5EDT,M3.2.0,M11.1.0", "CET-1CEST,M3.5.0,M10.5.0/3", "<+0330>-3:30", "AEST-10AEDT,M10.1.0,M4.1.0/3".
fn parse_posix(s: &str) -> Result<PosixRule, String> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let name = |i: &mut usize| -> Result<(), String> {
        if bytes.get(*i) == Some(&b'<') {
            while *i < bytes.len() && bytes[*i] != b'>' {
                *i += 1;
            }
            *i += 1;
        } else {
            while *i < bytes.len() && bytes[*i].is_ascii_alphabetic() {
                *i += 1;
            }
        }
        Ok(())
    };
    // A POSIX offset is hours WEST of UTC: "5" means UTC-5.
    let offset = |i: &mut usize| -> Result<i32, String> {
        let mut sign = 1;
        if matches!(bytes.get(*i), Some(b'+') | Some(b'-')) {
            if bytes[*i] == b'-' {
                sign = -1;
            }
            *i += 1;
        }
        let mut parts = [0i32; 3];
        for (n, part) in parts.iter_mut().enumerate() {
            let start = *i;
            while *i < bytes.len() && bytes[*i].is_ascii_digit() {
                *i += 1;
            }
            if start == *i {
                if n == 0 {
                    return Err(format!("bad POSIX offset in '{s}'"));
                }
                break;
            }
            *part = s[start..*i]
                .parse()
                .map_err(|_| format!("bad POSIX offset in '{s}'"))?;
            if bytes.get(*i) == Some(&b':') {
                *i += 1;
            } else {
                break;
            }
        }
        Ok(sign * (parts[0] * 3600 + parts[1] * 60 + parts[2]))
    };
    name(&mut i)?;
    let std = -offset(&mut i)?;
    if i >= bytes.len() {
        return Ok(PosixRule { std, dst: None });
    }
    name(&mut i)?;
    let dst_off = if i < bytes.len() && bytes[i] != b',' {
        -offset(&mut i)?
    } else {
        std + 3600
    };
    let date = |i: &mut usize| -> Result<(RuleDate, i32), String> {
        if bytes.get(*i) != Some(&b',') || bytes.get(*i + 1) != Some(&b'M') {
            return Err(format!(
                "only Mm.w.d transition rules are supported ('{s}')"
            ));
        }
        *i += 2;
        let rest = &s[*i..];
        let end = rest.find([',', '/']).unwrap_or(rest.len());
        let mut f = rest[..end].split('.');
        let mut next = || f.next().and_then(|x| x.parse::<u8>().ok());
        let d = RuleDate {
            month: next().ok_or("bad rule month")?,
            week: next().ok_or("bad rule week")?,
            weekday: next().ok_or("bad rule weekday")?,
        };
        *i += end;
        let time = if bytes.get(*i) == Some(&b'/') {
            *i += 1;
            offset(i)?
        } else {
            7200
        };
        Ok((d, time))
    };
    let (start, start_time) = date(&mut i)?;
    let (end, end_time) = date(&mut i)?;
    Ok(PosixRule {
        std,
        dst: Some((dst_off, start, start_time, end, end_time)),
    })
}

fn rule_instant(year: i32, d: RuleDate, local_secs: i32, offset: i32) -> Option<i64> {
    let month = time::Month::try_from(d.month).ok()?;
    let first = time::Date::from_calendar_date(year, month, 1).ok()?;
    let first_wd = first.weekday().number_days_from_sunday();
    let mut day = 1
        + (i32::from(d.weekday) - i32::from(first_wd)).rem_euclid(7)
        + (i32::from(d.week) - 1) * 7;
    let days_in_month = i32::from(month.length(year));
    while day > days_in_month {
        day -= 7;
    }
    let date = time::Date::from_calendar_date(year, month, day as u8).ok()?;
    let midnight_utc = date.midnight().assume_utc().unix_timestamp();
    Some(midnight_utc + i64::from(local_secs) - i64::from(offset))
}

impl PosixRule {
    fn offset_at(&self, t: i64) -> i32 {
        let Some((dst, start, start_time, end, end_time)) = self.dst else {
            return self.std;
        };
        let year = time::OffsetDateTime::from_unix_timestamp(t)
            .map(|d| d.year())
            .unwrap_or(1970);
        let (Some(on), Some(off)) = (
            rule_instant(year, start, start_time, self.std),
            rule_instant(year, end, end_time, dst),
        ) else {
            return self.std;
        };
        let in_dst = if on < off {
            t >= on && t < off
        } else {
            t >= on || t < off
        };
        if in_dst {
            dst
        } else {
            self.std
        }
    }
}

impl Zone {
    /// The UTC offset, in seconds, in force at UTC instant `t`.
    pub(crate) fn offset_at(&self, t: i64) -> i32 {
        match self.transitions.last() {
            Some(&(last, _)) if t >= last => {
                if let Some(rule) = &self.rule {
                    return rule.offset_at(t);
                }
            }
            _ => {}
        }
        match self.transitions.partition_point(|&(at, _)| at <= t) {
            0 => self.initial,
            n => self.transitions[n - 1].1,
        }
    }
}

#[cfg(test)]
mod zoneinfo_tests {
    use super::*;

    fn at(iso: &str) -> i64 {
        time::OffsetDateTime::parse(iso, &time::format_description::well_known::Rfc3339)
            .unwrap()
            .unix_timestamp()
    }

    #[test]
    fn a_named_zone_follows_daylight_saving() {
        let ny = load("America/New_York").expect("the host has tzdata");
        assert_eq!(ny.offset_at(at("2026-01-15T12:00:00Z")), -5 * 3600);
        assert_eq!(ny.offset_at(at("2026-07-15T12:00:00Z")), -4 * 3600);
        // past the fat table: the footer rule
        assert_eq!(ny.offset_at(at("2045-07-15T12:00:00Z")), -4 * 3600);
        assert_eq!(ny.offset_at(at("2045-12-15T12:00:00Z")), -5 * 3600);
        let sydney = load("Australia/Sydney").unwrap();
        assert_eq!(sydney.offset_at(at("2026-01-15T00:00:00Z")), 11 * 3600);
        assert_eq!(sydney.offset_at(at("2026-07-15T00:00:00Z")), 10 * 3600);
        assert_eq!(sydney.offset_at(at("2050-01-15T00:00:00Z")), 11 * 3600);
    }

    #[test]
    fn the_posix_footer_rule_alone_computes_the_switch() {
        let rule = parse_posix("CET-1CEST,M3.5.0,M10.5.0/3").unwrap();
        assert_eq!(rule.offset_at(at("2031-03-30T00:59:00Z")), 3600);
        assert_eq!(rule.offset_at(at("2031-03-30T01:00:00Z")), 7200);
        assert_eq!(rule.offset_at(at("2031-10-26T00:59:00Z")), 7200);
        assert_eq!(rule.offset_at(at("2031-10-26T01:00:00Z")), 3600);
        assert_eq!(
            parse_posix("<+0330>-3:30").unwrap().offset_at(0),
            3 * 3600 + 1800
        );
    }

    #[test]
    fn a_zone_name_is_a_name_never_a_path() {
        assert!(load("../../etc/passwd").is_err());
        assert!(load("/etc/passwd").is_err());
        assert!(load("America/Nowhere_Real").is_err());
    }
}
