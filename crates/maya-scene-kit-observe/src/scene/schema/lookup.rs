use std::sync::Arc;

use super::{
    ChunkSchema, SchemaLookupContext, SchemaRegistry, builtin::lookup_builtin_schema,
    default_schema_registry, external::lookup_external_schema,
};

pub(in crate::scene) fn schema_matches_context(
    schema: impl AsRef<ChunkSchema>,
    context: SchemaLookupContext<'_>,
) -> bool {
    let schema = schema.as_ref();
    let Some(ref when) = schema.when else {
        return true;
    };

    if let Some(min) = when.payload_min {
        let Some(size) = context.payload_size else {
            return false;
        };
        if size < min {
            return false;
        }
    }
    if let Some(max) = when.payload_max {
        let Some(size) = context.payload_size else {
            return false;
        };
        if size > max {
            return false;
        }
    }
    if let Some(modulo) = when.payload_mod {
        let Some(size) = context.payload_size else {
            return false;
        };
        if modulo == 0 || size % modulo != 0 {
            return false;
        }
    }
    if let Some(parent_form) = &when.parent_form {
        if context.parent_form != Some(parent_form.as_ref()) {
            return false;
        }
    }
    if let Some(parent_tag) = &when.parent_tag {
        if context.parent_tag != Some(parent_tag.as_ref()) {
            return false;
        }
    }
    if let Some(mask) = when.aux_mask {
        let Some(aux) = context.aux else {
            return false;
        };
        let expected = when.aux_equals.unwrap_or(aux);
        if (aux & mask) != (expected & mask) {
            return false;
        }
    } else if let Some(aux_equals) = when.aux_equals {
        if context.aux != Some(aux_equals) {
            return false;
        }
    }

    true
}

#[allow(dead_code)]
pub(in crate::scene) fn lookup_chunk_schema_with_context(
    form: &str,
    tag: &str,
    context: SchemaLookupContext<'_>,
) -> Option<Arc<ChunkSchema>> {
    lookup_chunk_schema_with_context_and_registry(default_schema_registry(), form, tag, context)
}

pub(in crate::scene) fn lookup_chunk_schema_with_context_and_registry(
    registry: &SchemaRegistry,
    form: &str,
    tag: &str,
    context: SchemaLookupContext<'_>,
) -> Option<Arc<ChunkSchema>> {
    let external = lookup_external_schema(registry, form, tag)
        .filter(|schema| schema_matches_context(schema, context));
    let builtin =
        lookup_builtin_schema(form, tag).filter(|schema| schema_matches_context(schema, context));

    match (external, builtin) {
        (Some(ext), Some(builtin)) => {
            if ext.priority >= builtin.priority {
                Some(ext)
            } else {
                Some(builtin)
            }
        }
        (Some(ext), None) => Some(ext),
        (None, Some(builtin)) => Some(builtin),
        (None, None) => None,
    }
}

#[cfg(test)]
pub(in crate::scene) fn lookup_chunk_schema(form: &str, tag: &str) -> Option<Arc<ChunkSchema>> {
    lookup_chunk_schema_with_context_and_registry(
        default_schema_registry(),
        form,
        tag,
        SchemaLookupContext::default(),
    )
}
