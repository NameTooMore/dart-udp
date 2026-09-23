use std::{
    collections::{BTreeMap, VecDeque},
    ops::Range,
};

use udp_protocol::StreamId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiveStream {
    stream_id: StreamId,
    next_offset: u64,
    final_offset: Option<u64>,
    max_offset: u64,
    segments: BTreeMap<u64, Vec<u8>>,
    ready: VecDeque<u8>,
}

impl ReceiveStream {
    pub(crate) fn new(stream_id: StreamId, max_offset: u64) -> Self {
        Self {
            stream_id,
            next_offset: 0,
            final_offset: None,
            max_offset,
            segments: BTreeMap::new(),
            ready: VecDeque::new(),
        }
    }

    pub(crate) const fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub(crate) const fn max_offset(&self) -> u64 {
        self.max_offset
    }

    pub(crate) fn set_max_offset(&mut self, max_offset: u64) {
        self.max_offset = max_offset;
    }

    pub(crate) fn insert(
        &mut self,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, crate::CoreError> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(crate::CoreError::InvalidOffset)?;
        if end > self.max_offset {
            return Err(crate::CoreError::FlowControlViolation {
                stream_id: Some(self.stream_id),
            });
        }
        if fin {
            if self.final_offset.is_some_and(|existing| existing != end) {
                return Err(crate::CoreError::InvalidOffset);
            }
            self.final_offset = Some(end);
        } else if self
            .final_offset
            .is_some_and(|final_offset| end > final_offset)
        {
            return Err(crate::CoreError::InvalidOffset);
        }

        let mut new_bytes: usize = 0;
        for Range { start, end } in self.uncovered_ranges(offset, end) {
            let start_index =
                usize::try_from(start - offset).map_err(|_| crate::CoreError::InvalidOffset)?;
            let end_index =
                usize::try_from(end - offset).map_err(|_| crate::CoreError::InvalidOffset)?;
            let chunk = data
                .get(start_index..end_index)
                .ok_or(crate::CoreError::InvalidOffset)?
                .to_vec();
            new_bytes = new_bytes.saturating_add(chunk.len());
            self.segments.insert(start, chunk);
        }
        self.deliver_contiguous()?;
        Ok(new_bytes)
    }

    pub(crate) fn new_bytes(&self, offset: u64, data: &[u8]) -> Result<usize, crate::CoreError> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(crate::CoreError::InvalidOffset)?;
        if end > self.max_offset {
            return Err(crate::CoreError::FlowControlViolation {
                stream_id: Some(self.stream_id),
            });
        }
        self.uncovered_ranges(offset, end)
            .into_iter()
            .try_fold(0_usize, |total, range| {
                let length = usize::try_from(range.end - range.start)
                    .map_err(|_| crate::CoreError::InvalidOffset)?;
                total
                    .checked_add(length)
                    .ok_or(crate::CoreError::InvalidOffset)
            })
    }

    pub(crate) fn read(&mut self, max_len: usize) -> Vec<u8> {
        let amount = max_len.min(self.ready.len());
        self.ready.drain(..amount).collect()
    }

    pub(crate) fn readable(&self) -> bool {
        !self.ready.is_empty()
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.final_offset
            .is_some_and(|final_offset| self.next_offset == final_offset && self.ready.is_empty())
    }

    pub(crate) fn buffered_len(&self) -> usize {
        self.ready.len() + self.segments.values().map(Vec::len).sum::<usize>()
    }

    fn uncovered_ranges(&self, offset: u64, end: u64) -> Vec<Range<u64>> {
        if offset == end {
            return Vec::new();
        }
        let mut cursor = offset.max(self.next_offset);
        let mut ranges = Vec::new();
        for (&existing_start, existing_data) in self.segments.range(..end) {
            let existing_end = existing_start.saturating_add(existing_data.len() as u64);
            if existing_end <= cursor {
                continue;
            }
            if existing_start > cursor {
                ranges.push(cursor..existing_start.min(end));
            }
            cursor = cursor.max(existing_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            ranges.push(cursor..end);
        }
        ranges
    }

    fn deliver_contiguous(&mut self) -> Result<(), crate::CoreError> {
        while let Some(data) = self.segments.remove(&self.next_offset) {
            self.next_offset = self
                .next_offset
                .checked_add(data.len() as u64)
                .ok_or(crate::CoreError::InvalidOffset)?;
            self.ready.extend(data);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use udp_protocol::StreamId;

    use super::ReceiveStream;

    #[test]
    fn reorders_and_deduplicates_segments_before_delivery() {
        let mut stream = ReceiveStream::new(StreamId::new(0), 100);
        assert_eq!(stream.insert(5, b" world", false).unwrap(), 6);
        assert!(!stream.readable());
        assert_eq!(stream.insert(0, b"hello", false).unwrap(), 5);
        assert_eq!(stream.read(100), b"hello world");
        assert_eq!(stream.insert(3, b"lo wo", false).unwrap(), 0);
    }

    #[test]
    fn fin_is_delivered_only_after_all_bytes_are_contiguous() {
        let mut stream = ReceiveStream::new(StreamId::new(0), 100);
        stream.insert(3, b"def", true).unwrap();
        assert!(!stream.is_finished());
        stream.insert(0, b"abc", false).unwrap();
        assert_eq!(stream.read(3), b"abc");
        assert!(!stream.is_finished());
        assert_eq!(stream.read(3), b"def");
        assert!(stream.is_finished());
    }
}
