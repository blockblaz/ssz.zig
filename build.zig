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

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_tests_tests.step);

    // Poseidon hasher build options
    const poseidon_enabled = b.option(bool, "poseidon", "Enable Poseidon2 hash support") orelse false;
    const poseidon_field = b.option([]const u8, "poseidon-field", "Poseidon2 field variant (babybear|koalabear)") orelse "koalabear";

    // Validate poseidon fields
    if (poseidon_enabled) {
        const valid_fields = [_][]const u8{ "babybear", "koalabear" };
        var field_valid = false;
        for (valid_fields) |valid_field| {
            if (std.mem.eql(u8, poseidon_field, valid_field)) {
                field_valid = true;
                break;
            }
        }
        if (!field_valid) {
            std.log.err("Invalid Poseidon2 field configuration: '{s}'", .{poseidon_field});
            std.log.err("Valid field options are:\n1) 'koalabear'\n2) 'babybear'", .{});
            std.log.err("Usage examples:", .{});
            std.log.err("zig build -Dposeidon=true -Dposeidon-field=koalabear", .{});
            std.log.err("zig build -Dposeidon=true -Dposeidon-field=koalabear", .{});
            std.log.err("If no field is specified 'koalabear' will be used as the default.", .{});
        }

        std.log.info("Poseidon2 enabled with field: '{s}'", .{poseidon_field});
    }

    // Create build options
    const options = b.addOptions();
    options.addOption(bool, "poseidon_enabled", poseidon_enabled);
    options.addOption([]const u8, "poseidon_field", poseidon_field);

    // Get poseidon dependency once if enabled
    const poseidon_module = if (poseidon_enabled) blk: {
        const poseidon_dep = b.dependency("poseidon", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk poseidon_dep.module("poseidon");
    } else null;

    // Add build options and poseidon import to all artifacts
    mod.addOptions("build_options", options);
    if (poseidon_module) |pm| mod.addImport("poseidon", pm);

    lib.root_module.addOptions("build_options", options);
    if (poseidon_module) |pm| lib.root_module.addImport("poseidon", pm);

    main_tests.root_module.addOptions("build_options", options);
    if (poseidon_module) |pm| main_tests.root_module.addImport("poseidon", pm);

    tests_tests.root_module.addOptions("build_options", options);
    if (poseidon_module) |pm| tests_tests.root_module.addImport("poseidon", pm);
}
