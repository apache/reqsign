// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Time related utils.

use crate::Error;
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

/// An instant in time represented as the number of nanoseconds since the Unix epoch.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(jiff::Timestamp);

impl FromStr for Timestamp {
    type Err = Error;

    /// Parse a timestamp by the default [`DateTimeParser`].
    ///
    /// All of them are valid time:
    ///
    /// - `2022-03-13T07:20:04Z`
    /// - `2022-03-01T08:12:34+00:00`
    /// - `2022-03-01T08:12:34.00+00:00`
    /// - `2022-07-08T02:14:07+02:00[Europe/Paris]`
    ///
    /// [`DateTimeParser`]: jiff::fmt::temporal::DateTimeParser
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse() {
            Ok(t) => Ok(Timestamp(t)),
            Err(err) => Err(
                Error::unexpected(format!("parse '{s}' into timestamp failed")).with_source(err),
            ),
        }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Timestamp {
    /// Create the timestamp of now.
    pub fn now() -> Self {
        Self(jiff::Timestamp::now())
    }

    /// Format the timestamp into date: `20220301`
    pub fn format_date(self) -> String {
        self.0.strftime("%Y%m%d").to_string()
    }

    /// Format the timestamp into ISO8601: `20220313T072004Z`
    pub fn format_iso8601(self) -> String {
        self.0.strftime("%Y%m%dT%H%M%SZ").to_string()
    }

    /// Format the timestamp into http date: `Sun, 06 Nov 1994 08:49:37 GMT`
    ///
    /// ## Note
    ///
    /// HTTP date is slightly different from RFC2822.
    ///
    /// - Timezone is fixed to GMT.
    /// - Day must be 2 digit.
    pub fn format_http_date(self) -> String {
        self.0.strftime("%a, %d %b %Y %T GMT").to_string()
    }

    /// Format the timestamp into RFC3339 in Zulu: `2022-03-13T07:20:04Z`
    pub fn format_rfc3339_zulu(self) -> String {
        self.0.strftime("%FT%TZ").to_string()
    }

    /// Returns this timestamp as a number of seconds since the Unix epoch.
    ///
    /// This only returns the number of whole seconds. That is, if there are
    /// any fractional seconds in this timestamp, then they are truncated.
    pub fn as_second(self) -> i64 {
        self.0.as_second()
    }

    /// Returns the fractional second component of this timestamp in units of
    /// nanoseconds.
    ///
    /// It is guaranteed that this will never return a value that is greater
    /// than 1 second (or less than -1 second).
    pub fn subsec_nanosecond(self) -> i32 {
        self.0.subsec_nanosecond()
    }

    /// Convert to `SystemTime`.
    ///
    /// # Panics
    ///
    /// Panics if the timestamp is outside the range supported by `SystemTime`
    /// on the current platform.
    pub fn as_system_time(self) -> SystemTime {
        SystemTime::try_from(self.0).expect("timestamp is out of range for SystemTime")
    }

    /// Creates a new instant in time from the number of milliseconds elapsed
    /// since the Unix epoch.
    ///
    /// When `millisecond` is negative, it corresponds to an instant in time
    /// before the Unix epoch. A smaller number corresponds to an instant in
    /// time further into the past.
    pub fn from_millisecond(millis: i64) -> crate::Result<Self> {
        match jiff::Timestamp::from_millisecond(millis) {
            Ok(t) => Ok(Timestamp(t)),
            Err(err) => Err(Error::unexpected(format!(
                "convert '{millis}' milliseconds into timestamp failed"
            ))
            .with_source(err)),
        }
    }

    /// Creates a new instant in time from the number of seconds elapsed since
    /// the Unix epoch.
    ///
    /// When `second` is negative, it corresponds to an instant in time before
    /// the Unix epoch. A smaller number corresponds to an instant in time
    /// further into the past.
    pub fn from_second(second: i64) -> crate::Result<Self> {
        match jiff::Timestamp::from_second(second) {
            Ok(t) => Ok(Timestamp(t)),
            Err(err) => Err(Error::unexpected(format!(
                "convert '{second}' seconds into timestamp failed"
            ))
            .with_source(err)),
        }
    }

    /// Parse a timestamp from RFC2822.
    ///
    /// All of them are valid time:
    ///
    /// - `Sat, 13 Jul 2024 15:09:59 -0400`
    /// - `Mon, 15 Aug 2022 16:50:12 GMT`
    pub fn parse_rfc2822(s: &str) -> crate::Result<Timestamp> {
        match jiff::fmt::rfc2822::parse(s) {
            Ok(zoned) => Ok(Timestamp(zoned.timestamp())),
            Err(err) => {
                Err(Error::unexpected(format!("parse '{s}' into rfc2822 failed")).with_source(err))
            }
        }
    }

    /// Parse the string format "2023-10-31 21:59:10.000000".
    pub fn parse_datetime_utc(s: &str) -> crate::Result<Timestamp> {
        let dt = s.parse::<jiff::civil::DateTime>().map_err(|err| {
            Error::unexpected(format!("parse '{s}' into datetime failed")).with_source(err)
        })?;

        let ts = jiff::tz::TimeZone::UTC.to_timestamp(dt).map_err(|err| {
            Error::unexpected(format!("convert '{s}' into timestamp failed")).with_source(err)
        })?;

        Ok(Timestamp(ts))
    }

    /// Add a duration, saturating at the maximum representable timestamp on overflow.
    ///
    /// The `Add<Duration>` implementation panics when the sum is out of range.
    /// Use this method for caller-supplied durations, such as a signing
    /// `expires_in`, where an arbitrarily large value must produce the strictest
    /// representable deadline instead of a panic. Saturating upward cannot make a
    /// credential that fails to cover the requested lifetime appear valid, and
    /// representable results keep their exact nanosecond value.
    pub fn saturating_add(self, rhs: Duration) -> Self {
        match self.0.saturating_add(rhs) {
            Ok(ts) => Self(ts),
            // `std::time::Duration` has no calendar units, so jiff rejects the
            // input only when it cannot be represented at all.
            Err(_) => Self(jiff::Timestamp::MAX),
        }
    }

    /// Add a duration, returning `None` if the result is out of range.
    ///
    /// Use this instead of [`Timestamp::saturating_add`] when an unrepresentable
    /// result must be rejected, such as a server-provided token lifetime.
    pub fn checked_add(self, rhs: Duration) -> Option<Self> {
        self.0.checked_add(rhs).ok().map(Self)
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, rhs: Duration) -> Timestamp {
        let ts = self
            .0
            .checked_add(rhs)
            .expect("adding unsigned duration to timestamp overflowed");

        Timestamp(ts)
    }
}

impl AddAssign<Duration> for Timestamp {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Timestamp;

    fn sub(self, rhs: Duration) -> Timestamp {
        let ts = self
            .0
            .checked_sub(rhs)
            .expect("subtracting unsigned duration from timestamp overflowed");

        Timestamp(ts)
    }
}

impl SubAssign<Duration> for Timestamp {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_time() -> Timestamp {
        Timestamp("2022-03-01T08:12:34Z".parse().unwrap())
    }

    #[test]
    fn test_format_date() {
        let t = test_time();
        assert_eq!("20220301", t.format_date())
    }

    #[test]
    fn test_format_ios8601() {
        let t = test_time();
        assert_eq!("20220301T081234Z", t.format_iso8601())
    }

    #[test]
    fn test_format_http_date() {
        let t = test_time();
        assert_eq!("Tue, 01 Mar 2022 08:12:34 GMT", t.format_http_date())
    }

    #[test]
    fn test_format_rfc3339() {
        let t = test_time();
        assert_eq!("2022-03-01T08:12:34Z", t.format_rfc3339_zulu())
    }

    #[test]
    fn test_parse_rfc3339() {
        let t = test_time();

        for v in [
            "2022-03-01T08:12:34Z",
            "2022-03-01T08:12:34+00:00",
            "2022-03-01T08:12:34.00+00:00",
        ] {
            assert_eq!(t, v.parse().expect("must be valid time"));
        }
    }

    #[test]
    fn test_as_system_time_around_unix_epoch() {
        let epoch = SystemTime::UNIX_EPOCH;
        for (value, expected) in [
            ("1970-01-01T00:00:00Z", epoch),
            (
                "1970-01-01T00:00:00.123456789Z",
                epoch + Duration::from_nanos(123_456_789),
            ),
            (
                "1969-12-31T23:59:59.123456789Z",
                epoch - Duration::from_nanos(876_543_211),
            ),
        ] {
            let timestamp: Timestamp = value.parse().expect("must be valid time");
            assert_eq!(timestamp.as_system_time(), expected);
        }
    }

    #[test]
    fn test_parse_timestamp_below_minimum() {
        // Jiff 1.0.0 could parse this into a timestamp below its supported range.
        // https://github.com/BurntSushi/jiff/issues/714
        assert!("-009999-01-02T01:59:58.5Z".parse::<Timestamp>().is_err());
    }

    #[test]
    fn saturating_add_matches_add_for_representable_durations() {
        let base = test_time();

        for duration in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(1_500),
            Duration::from_secs(86_400),
        ] {
            assert_eq!(base.saturating_add(duration), base + duration);
        }
    }

    #[test]
    fn saturating_add_saturates_at_the_maximum_timestamp() {
        let base = test_time();
        let max: Timestamp = jiff::Timestamp::MAX
            .to_string()
            .parse()
            .expect("jiff maximum timestamp must parse");

        assert_eq!(base.saturating_add(Duration::MAX), max);
        assert_eq!(base.saturating_add(Duration::from_secs(u64::MAX)), max);
    }

    #[test]
    fn checked_add_reports_overflow() {
        let base = test_time();
        let duration = Duration::from_millis(1_500);

        assert_eq!(base.checked_add(duration), Some(base + duration));
        assert_eq!(base.checked_add(Duration::MAX), None);
    }
}
