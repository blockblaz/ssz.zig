const std = @import("std");
const Builder = @import("std").Build;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("ssz.zig", Builder.Module.CreateOptions{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "ssz",
        .root_source_file = .{ .cwd_relative = "src/lib.zig" },
        .optimize = optimize,
        .target = target,
    });
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/lib.zig" },
        .optimize = optimize,
        .target = target,
    });
    const run_main_tests = b.addRunArtifact(main_tests);
    const tests_tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/tests.zig" },
        .optimize = optimize,
        .target = target,
    });
    tests_tests.root_module.addImport("ssz.zig", mod);
    const run_tests_tests = b.addRunArtifact(tests_tests);

    // Poseidon hasher build options
    const poseidon_enabled = b.option(bool, "poseidon", "Enable Poseidon2 hash support") orelse false;
    if (poseidon_enabled) {
        std.log.info("Poseidon2 enabled (koalabear, Poseidon2-24 Plonky3)", .{});
    }

    // Create build options
    const options = b.addOptions();
    options.addOption(bool, "poseidon_enabled", poseidon_enabled);

    // Poseidon2 implementation via hash-zig dependency
    const hashzig_module = if (poseidon_enabled) blk: {
        const hashzig_dep = b.dependency("hash_zig", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk hashzig_dep.module("hash-zig");
    } else null;

    // Add build options and poseidon import to all artifacts
    mod.addOptions("build_options", options);
    if (hashzig_module) |pm| mod.addImport("hash_zig", pm);

    lib.root_module.addOptions("build_options", options);
    if (hashzig_module) |pm| lib.root_module.addImport("hash_zig", pm);

    main_tests.root_module.addOptions("build_options", options);
    if (hashzig_module) |pm| main_tests.root_module.addImport("hash_zig", pm);

    tests_tests.root_module.addOptions("build_options", options);
    if (hashzig_module) |pm| tests_tests.root_module.addImport("hash_zig", pm);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_tests_tests.step);
    // Optional Poseidon validation suite (only when Poseidon is enabled)
    if (poseidon_enabled) {
        const plonky3_validation_tests = b.addTest(.{
            .root_source_file = .{ .cwd_relative = "src/poseidon_plonky3_validation.zig" },
            .optimize = optimize,
            .target = target,
        });
        plonky3_validation_tests.root_module.addOptions("build_options", options);
        if (hashzig_module) |pm| plonky3_validation_tests.root_module.addImport("hash_zig", pm);
        const run_plonky3_validation_tests = b.addRunArtifact(plonky3_validation_tests);
        test_step.dependOn(&run_plonky3_validation_tests.step);
    }
}
