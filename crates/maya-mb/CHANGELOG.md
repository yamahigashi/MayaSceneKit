# Changelog

## 0.4.0

- Section rescans can retain the original parse budget with the existing explicit-budget parser; callers must inspect ParsedSection::state before using its chunks as a complete inventory.

Incompatible section-scan API changes:

- ParsedSection::into_chunks(self) -> Vec<SectionChunk> is replaced by into_parts(self) -> (Vec<SectionChunk>, MbSectionScanState).
- walk_group_chunks_with_layout(data, hints) returns MbWalkResult instead of Vec<SectionChunk>.
- walk_group_chunks_with_layout_with_budget(data, hints, starting_depth, budget) returns Result<MbWalkResult, MayaBinaryParseError> instead of Result<Vec<SectionChunk>, MayaBinaryParseError>.
- visit_group_chunks_with_layout(data, hints, visitor) returns MbSectionScanState instead of ().
- visit_group_chunks_with_layout_with_budget(data, hints, starting_depth, budget, visitor) returns Result<MbSectionScanState, MayaBinaryParseError> instead of Result<(), MayaBinaryParseError>.

New public API:

- MbSectionScanState exposes Complete and Stopped, and merge(&mut self, other).
- MbWalkResult exposes chunks: Vec<SectionChunk> and state: MbSectionScanState.
- ParsedSection::state(&self) -> MbSectionScanState reports unconsumed tail bytes.
- parse_section_chunks_with_hints_with_budget(data, hints, budget) -> ParsedSection accepts an explicit allocation budget.
- Chunk::section_budget(&self) -> Option<&MbParseBudget> exposes the original parse budget for groups; leaves have no section budget.
- Chunk::scan_root_sections(&self, data, budget) -> Result<MbSectionScanState, MayaBinaryParseError> checks group children and caches the original root-buffer result for the original parse budget. Cloned files share this cache; other buffers and budgets are scanned independently. A complete tree with matching raw-walk layouts supplies the completion result during parsing. Mixed layouts and partial trees require a raw scan.

MbSectionScanState and MbWalkResult are must_use. Callers must inspect completion before accepting a prefix, including when no chunks were returned. Missing layout hints with nonempty input yield Stopped.

The formerly unbounded parse_section_chunks_with_hints, walk_group_chunks_with_layout, and visit_group_chunks_with_layout now use MbParseBudget::default(). The default limits are 100,000 children per group, 1,000,000 total chunks, depth 128 for recursive walks, and 2 GiB of input. These wrappers return a retained prefix and Stopped when their applicable limits are reached. Section allocation is checked before retention. Budgeted raw walks retain hard errors, now also enforcing max_parse_bytes; a budget error takes precedence over an earlier section stop. Use the budgeted APIs when a larger explicitly chosen budget is required.

All four-byte chunk tags are accepted, including non-printable tags. Group recognition and root-tag restrictions are unchanged. Partial headers, payload overruns, and incomplete padding retain the unconsumed tail. Padding may be omitted for the last child only when its payload ends exactly at the input boundary. Root leaf children are not scanned as sections.

Related maya-scene-kit-formats migration in this workspace:

- MbRewriteError changes from a struct with a completeness field to an enum with IncompleteTree(MbCompleteness), SectionScanStopped, and Parse(MayaBinaryParseError). require_complete_mb_sections(data, root) -> Result<(), MbRewriteError> is new. Rewrite entrypoints retain their signatures and use the parsed group's original budget.
- HeadMetadata gains section_state: MbSectionScanState. extract_head_metadata_with_budget(mb, budget) -> HeadMetadata is new.
- scan_raw_script_nodes_in_mb(data, root) changes from Vec<String> to MbSectionScan<Vec<String>>.
- extract_raw_script_entries_from_mb(mb) changes from Vec<(String, String)> to MbSectionScan<Vec<(String, String)>>.
- extract_raw_scene_paths_from_mb(mb) changes from Vec<MbScenePathEntry> to MbSectionScan<Vec<MbScenePathEntry>>.
- collect_rtft_owner_traces_from_mb(mb) changes from Vec<MbRtftOwnerTrace> to MbSectionScan<Vec<MbRtftOwnerTrace>>.
- Each of those four extraction functions gains a corresponding _with_budget entrypoint with a final &MbParseBudget argument and the same state-bearing return type.
- locate_raw_script_node_forms_in_mb_by_name(data, root, selection) changes from (Vec<(String, usize)>, Vec<String>) to MbSectionScan<MbScriptNodeFormSelection>, where MbScriptNodeFormSelection aliases the original tuple.
- extract_mb_script_node_name_with_layout(payload, child_alignment, child_header_size, budget) and extract_mb_form_node_name_with_layout(payload, child_alignment, child_header_size, budget) gain the final &MbParseBudget argument and return MbSectionScan<Option<String>> instead of Option<String>.
- MbSectionScan<T> is new, with public value: T and state: MbSectionScanState fields. Public default extraction entrypoints that receive a parsed file or root use its original group budget.
