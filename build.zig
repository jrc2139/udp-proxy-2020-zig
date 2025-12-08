const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target and optimization options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // -------------------------------------------------------------------------
    // UDP Proxy 2020 Executable
    // -------------------------------------------------------------------------
    const exe = b.addExecutable(.{
        .name = "udp-proxy-2020",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.linkSystemLibrary("pcap");

    b.installArtifact(exe);

    // -------------------------------------------------------------------------
    // Run Command
    // -------------------------------------------------------------------------
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run udp-proxy-2020");
    run_step.dependOn(&run_cmd.step);

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    tests.linkSystemLibrary("pcap");

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_tests.step);

    // -------------------------------------------------------------------------
    // Check (for ZLS build-on-save)
    // -------------------------------------------------------------------------
    const check_exe = b.addExecutable(.{
        .name = "udp-proxy-2020-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    check_exe.linkSystemLibrary("pcap");

    const check_step = b.step("check", "Check for compilation errors (used by ZLS)");
    check_step.dependOn(&check_exe.step);
}
