use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use maya_scene_kit_observe::scene::{
    forensics::{NodeRecoveryIssue, RecoveryForensics},
    model::{RecoveredHeader, RecoveredScene},
    recovery::AngularAttrKind,
};

use crate::scene::{
    DecodeQuality, RawChunkDump, emit::ma::document, public::map::map_decode_quality,
};

#[derive(Debug, Clone)]
pub(crate) struct BestEffortBuildResult {
    pub(in crate::scene) maya_ascii: String,
    pub(in crate::scene) issues: Vec<NodeRecoveryIssue>,
    pub(in crate::scene) raw_chunks: Vec<RawChunkDump>,
    pub(in crate::scene) raw_chunk_count: usize,
    pub(in crate::scene) raw_payload_size_total: usize,
    pub(in crate::scene) decode_quality_distribution: Vec<DecodeQualityDistributionEntry>,
}

#[derive(Debug, Clone)]
pub(in crate::scene) struct DecodeQualityDistributionEntry {
    pub(in crate::scene) quality: DecodeQuality,
    pub(in crate::scene) form: String,
    pub(in crate::scene) tag: String,
    pub(in crate::scene) count: usize,
}

pub(in crate::scene) struct BestEffortRenderData<'a> {
    pub(in crate::scene) metadata: RecoveredHeader,
    pub(in crate::scene) scene_model: RecoveredScene,
    pub(in crate::scene) forensics: RecoveryForensics,
    pub(in crate::scene) issues: Vec<NodeRecoveryIssue>,
    pub(in crate::scene) source_path: &'a Path,
    pub(in crate::scene) output_name: &'a str,
    pub(in crate::scene) angular_attrs_by_node: HashMap<String, HashMap<String, AngularAttrKind>>,
    pub(in crate::scene) embed_metadata: bool,
}

pub(in crate::scene) fn render_best_effort_ma(
    data: BestEffortRenderData<'_>,
) -> BestEffortBuildResult {
    let BestEffortRenderData {
        metadata,
        scene_model,
        forensics,
        issues,
        source_path,
        output_name,
        angular_attrs_by_node,
        embed_metadata,
    } = data;
    let raw_chunk_count = forensics.raw_chunks.len();
    let raw_payload_size_total = forensics
        .raw_chunks
        .iter()
        .map(|chunk| chunk.payload.len())
        .sum::<usize>();
    let raw_chunks = forensics
        .raw_chunks
        .iter()
        .map(|raw| RawChunkDump {
            trace_form: raw.chunk_ref.form.clone(),
            trace_tag: raw.chunk_ref.tag.clone(),
            trace_node_offset: raw.chunk_ref.node_offset,
            trace_chunk_aux: raw.chunk_ref.chunk_aux,
            trace_child_alignment: raw.chunk_ref.child_alignment,
            trace_child_header_size: raw.chunk_ref.child_header_size,
            payload: raw.payload.clone(),
        })
        .collect();
    let decode_quality_distribution = build_decode_quality_distribution(&forensics);

    BestEffortBuildResult {
        maya_ascii: document::render_best_effort_maya_ascii(
            &metadata,
            &scene_model,
            source_path,
            output_name,
            &angular_attrs_by_node,
            embed_metadata,
        ),
        issues,
        raw_chunks,
        raw_chunk_count,
        raw_payload_size_total,
        decode_quality_distribution,
    }
}

fn build_decode_quality_distribution(
    forensics: &RecoveryForensics,
) -> Vec<DecodeQualityDistributionEntry> {
    let mut grouped: BTreeMap<(DecodeQuality, String, String), usize> = BTreeMap::new();
    for record in &forensics.decode_qualities {
        *grouped
            .entry((
                map_decode_quality(record.quality.clone()),
                record.chunk_ref.form.clone(),
                record.chunk_ref.tag.clone(),
            ))
            .or_insert(0) += 1;
    }

    grouped
        .into_iter()
        .map(
            |((quality, form, tag), count)| DecodeQualityDistributionEntry {
                quality,
                form,
                tag,
                count,
            },
        )
        .collect()
}
