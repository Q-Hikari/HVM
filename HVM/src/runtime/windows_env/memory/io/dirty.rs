use super::*;

impl WindowsProcessEnvironment {
    pub(in crate::runtime::windows_env) fn mark_dirty_pages(&mut self, address: u64, size: usize) {
        if size == 0 {
            return;
        }
        let mut page = address & !(PAGE_SIZE - 1);
        let last_address = address.saturating_add(size.saturating_sub(1) as u64);
        let last_page = last_address & !(PAGE_SIZE - 1);
        loop {
            self.dirty_pages.insert(page);
            if page >= last_page {
                break;
            }
            let next_page = page.saturating_add(PAGE_SIZE);
            if next_page <= page {
                break;
            }
            page = next_page;
        }
    }
}
