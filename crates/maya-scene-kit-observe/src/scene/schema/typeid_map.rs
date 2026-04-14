use std::collections::HashMap;

use super::{SchemaRegistry, default_schema_registry};

#[derive(Debug, Clone, Default)]
pub(crate) struct TypeIdTypeNameResolver {
    map: HashMap<u32, String>,
}

impl TypeIdTypeNameResolver {
    pub(crate) fn lookup(&self, type_id: u32) -> Option<String> {
        self.map.get(&type_id).cloned()
    }
}

#[allow(dead_code)]
pub(in crate::scene) fn build_typeid_typename_resolver() -> Result<TypeIdTypeNameResolver, String> {
    build_typeid_typename_resolver_with_registry(default_schema_registry())
}

pub(in crate::scene) fn build_typeid_typename_resolver_with_registry(
    registry: &SchemaRegistry,
) -> Result<TypeIdTypeNameResolver, String> {
    let map = super::node_semantics::load_typeid_typename_map_with_registry(registry)?;
    Ok(TypeIdTypeNameResolver { map })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{build_typeid_typename_resolver, build_typeid_typename_resolver_with_registry};
    use crate::scene::schema::{SchemaRegistry, locator::SchemaPaths};

    #[test]
    fn default_typeid_map_path_points_to_node_info_schema_file() {
        let registry = SchemaRegistry::new(SchemaPaths::from_defaults());
        let path = &registry.paths().node_info_schema_file;
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("node_info.yaml")
        );
        assert_eq!(
            path.parent()
                .and_then(|value| value.file_name())
                .and_then(|value| value.to_str()),
            Some("schemas")
        );
    }

    #[test]
    fn build_typeid_typename_resolver_reads_typeids_from_node_info() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("node_info_{unique}.yaml"));
        let yaml = r#"---
version: 1
nodes:
  twistSpline:
    typeid: 0x001226F7
    attrs: {}
  demoNode:
    typeid: "1234"
    attrs: {}
  twistTangent:
    typeid: 0x001226FA
    attrs: {}
"#;
        std::fs::write(&path, yaml).expect("write");
        let mut paths = SchemaPaths::from_defaults();
        paths.node_info_schema_file = path.clone();
        let map = build_typeid_typename_resolver_with_registry(&SchemaRegistry::new(paths))
            .expect("resolver");
        assert_eq!(map.lookup(0x0012_26F7).as_deref(), Some("twistSpline"));
        assert_eq!(map.lookup(1234).as_deref(), Some("demoNode"));
        assert_eq!(map.lookup(0x0012_26FA).as_deref(), Some("twistTangent"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolver_merges_additional_node_info_without_global_mutation() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("node_info_extra_{unique}.yaml"));
        std::fs::write(
            &path,
            "version: 1\nnodes:\n  customNode:\n    typeid: 0x00123456\n    attrs: {}\n",
        )
        .expect("write");
        let mut paths = SchemaPaths::from_defaults();
        paths.additional_node_info_files = vec![path.clone()];

        let resolver = build_typeid_typename_resolver_with_registry(&SchemaRegistry::new(paths))
            .expect("resolver");
        assert_eq!(resolver.lookup(0x0012_3456).as_deref(), Some("customNode"));

        let default_resolver = build_typeid_typename_resolver().expect("default resolver");
        assert_eq!(default_resolver.lookup(0x0012_3456), None);
        let _ = std::fs::remove_file(&path);
    }
}
