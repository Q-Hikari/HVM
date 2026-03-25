use super::*;

impl VirtualExecutionEngine {
    pub(super) fn initialize_msvcrt_onexit_table(&mut self, table: u64) -> Result<(), VmError> {
        if table == 0 {
            return Ok(());
        }
        self.write_pointer_value(table, 0)?;
        self.write_pointer_value(table + self.arch.pointer_size as u64, 0)?;
        self.write_pointer_value(table + (self.arch.pointer_size as u64 * 2), 0)?;
        self.msvcrt_onexit_tables
            .insert(table, MsvcrtOnExitTable::default());
        Ok(())
    }

    pub(super) fn register_msvcrt_onexit_function(
        &mut self,
        table: u64,
        function: u64,
    ) -> Result<u64, VmError> {
        if table == 0 {
            return Ok(u64::MAX);
        }
        if !self.msvcrt_onexit_tables.contains_key(&table) {
            self.initialize_msvcrt_onexit_table(table)?;
        }
        let pointer_size = self.arch.pointer_size as u64;
        let needs_storage = self
            .msvcrt_onexit_tables
            .get(&table)
            .map(|entry| entry.storage.is_none())
            .unwrap_or(true);
        if needs_storage {
            let storage =
                self.modules
                    .memory_mut()
                    .reserve(PAGE_SIZE, None, "msvcrt:onexit", true)?;
            let capacity = (PAGE_SIZE / pointer_size.max(1)) as usize;
            let entry = self
                .msvcrt_onexit_tables
                .get_mut(&table)
                .ok_or(VmError::RuntimeInvariant("missing onexit table after init"))?;
            entry.storage = Some(storage);
            entry.capacity = capacity.max(1);
        }
        let entry = self
            .msvcrt_onexit_tables
            .get_mut(&table)
            .ok_or(VmError::RuntimeInvariant("missing onexit table state"))?;
        if entry.functions.len() >= entry.capacity {
            return Ok(u64::MAX);
        }
        if function != 0 {
            entry.functions.push(function);
        }
        let storage = entry.storage.unwrap_or(0);
        let functions = entry.functions.clone();
        let capacity = entry.capacity;
        let end = storage + functions.len() as u64 * pointer_size;
        let capacity_end = storage + capacity as u64 * pointer_size;
        let _ = entry;
        for (index, value) in functions.iter().copied().enumerate() {
            self.write_pointer_value(storage + index as u64 * pointer_size, value)?;
        }
        self.write_pointer_value(table, storage)?;
        self.write_pointer_value(table + pointer_size, end)?;
        self.write_pointer_value(table + pointer_size * 2, capacity_end)?;
        Ok(0)
    }

    pub(super) fn execute_msvcrt_onexit_table(&mut self, table: u64) -> Result<u64, VmError> {
        if table == 0 {
            return Ok(0);
        }
        let functions = self
            .msvcrt_onexit_tables
            .remove(&table)
            .map(|mut entry| {
                entry.functions.reverse();
                entry.functions
            })
            .unwrap_or_default();
        self.initialize_msvcrt_onexit_table(table)?;
        for function in functions {
            if function == 0 {
                continue;
            }
            let _ = self.call_native_with_entry_frame(function, &[]);
        }
        Ok(0)
    }
}
