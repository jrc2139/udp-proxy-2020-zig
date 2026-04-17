const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const version = b.option([]const u8, "version", "Version string injected into the binary") orelse "2.0.0-dev";
    const commit = b.option([]const u8, "commit", "Git commit SHA injected into the binary") orelse "unknown";
    const libpcap_path = b.option(
        []const u8,
        "libpcap-path",
        "Directory containing libpcap (expects lib/ and include/ subdirectories)",
    );

    // Generate build_info.zig with injected version/commit values
    const build_info_wf = b.addWriteFiles();
    const build_info_src = b.fmt(
        \\pub const version = "{s}";
        \\pub const commit = "{s}";
        \\
    , .{ version, commit });
    const build_info_file = build_info_wf.add("build_info.zig", build_info_src);
    const build_info_mod = b.createModule(.{ .root_source_file = build_info_file });

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
    exe.root_module.addImport("build_info", build_info_mod);
    linkPcap(exe.root_module, target, libpcap_path, b);

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
    tests.root_module.addImport("build_info", build_info_mod);
    linkPcap(tests.root_module, target, libpcap_path, b);

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
    check_exe.root_module.addImport("build_info", build_info_mod);
    linkPcap(check_exe.root_module, target, libpcap_path, b);

    const check_step = b.step("check", "Check for compilation errors (used by ZLS)");
    check_step.dependOn(&check_exe.step);
}

/// Wire libpcap into the given module. Uses the explicit `libpcap-path` if
/// provided (expects a `lib/` and `include/` layout, which is what libpcap's
/// configure `--prefix=DIR` produces); otherwise auto-adds FreeBSD's
/// `/usr/local` paths where `pkg` installs libpcap.
fn linkPcap(
    mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    libpcap_path: ?[]const u8,
    b: *std.Build,
) void {
    if (libpcap_path) |p| {
        mod.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ p, "lib" }) });
        mod.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ p, "include" }) });
    } else if (target.result.os.tag == .freebsd) {
        mod.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
        mod.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
    }
    mod.linkSystemLibrary("pcap", .{});
}
