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

    // Use ReleaseSafe for tests to avoid "object file too large" errors
    const test_optimize = if (optimize == .Debug) .ReleaseSafe else optimize;

    const main_tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/lib.zig" },
        .optimize = test_optimize,
        .target = target,
    });
    const run_main_tests = b.addRunArtifact(main_tests);
    const tests_tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/tests.zig" },
        .optimize = test_optimize,
        .target = target,
    });
    tests_tests.root_module.addImport("ssz.zig", mod);
    const run_tests_tests = b.addRunArtifact(tests_tests);

    const list_tests = b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/list_tests.zig" },
        .optimize = test_optimize,
        .target = target,
    });
    list_tests.root_module.addImport("ssz.zig", mod);
    const run_list_tests = b.addRunArtifact(list_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_tests_tests.step);
    test_step.dependOn(&run_list_tests.step);
}
