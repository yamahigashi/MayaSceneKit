#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

impl ByteSpan {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(self) -> bool {
        self.start >= self.end
    }

    pub fn slice(self, data: &[u8]) -> &[u8] {
        &data[self.start..self.end]
    }

    pub fn checked_subspan(self, offset: usize, len: usize) -> Option<Self> {
        let start = self.start.checked_add(offset)?;
        let end = start.checked_add(len)?;
        if end > self.end {
            return None;
        }
        Some(Self { start, end })
    }

    pub fn offset(self, base: usize) -> Self {
        Self {
            start: self.start + base,
            end: self.end + base,
        }
    }
}
