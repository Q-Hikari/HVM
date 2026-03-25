use super::*;

impl WindowsProcessEnvironment {
    pub(super) fn walk_loader_list(
        &self,
        head: u64,
        entry_link_offset: u64,
    ) -> Result<Vec<u64>, MemoryError> {
        let mut entries = Vec::new();
        let mut cursor = self.read_pointer(head)?;
        let mut remaining = (LDR_REGION_SIZE as usize / self.pointer_size()).max(1);

        while cursor != head && remaining > 0 {
            if cursor < entry_link_offset {
                return Err(MemoryError::MissingRegion {
                    address: cursor,
                    size: self.pointer_size() as u64,
                });
            }
            let entry_base = cursor - entry_link_offset;
            entries.push(entry_base);
            cursor = self.read_pointer(cursor)?;
            remaining -= 1;
        }

        Ok(entries)
    }

    pub(super) fn link_loader_list(&mut self, head: u64, nodes: &[u64]) {
        let ptr_size = self.pointer_size() as u64;
        let first = nodes.first().copied().unwrap_or(head);
        let last = nodes.last().copied().unwrap_or(head);
        self.write_pointer(head, first);
        self.write_pointer(head + ptr_size, last);

        for (index, node) in nodes.iter().copied().enumerate() {
            let previous = if index == 0 { head } else { nodes[index - 1] };
            let next = if index + 1 == nodes.len() {
                head
            } else {
                nodes[index + 1]
            };
            self.write_pointer(node, next);
            self.write_pointer(node + ptr_size, previous);
        }
    }
}
