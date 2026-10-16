fn main() {
    let source = "vendor/tree-sitter-verus/src";
    let mut compiler = cc::Build::new();
    compiler.std("c11").include(source);

    if std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|value| value == "msvc") {
        compiler.flag("-utf-8");
    }

    for file in ["parser.c", "scanner.c"] {
        let path = format!("{source}/{file}");
        compiler.file(&path);
        println!("cargo:rerun-if-changed={path}");
    }
    for header in ["alloc.h", "array.h", "parser.h"] {
        println!("cargo:rerun-if-changed={source}/tree_sitter/{header}");
    }

    compiler.compile("tree-sitter-verus");
}
