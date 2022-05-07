const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const tinyaes = b.addStaticLibrary("tinyaes", "lib/tiny-AES-c/aes.c");

    const exe = b.addExecutable("cryptopals", "src/main.zig");
    exe.addPackagePath("utils", "src/utils.zig");
    exe.addIncludeDir("lib/tiny-AES-c");
    exe.linkLibrary(tinyaes);
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const utils_tests = b.addTest("src/utils.zig");
    utils_tests.setTarget(target);
    utils_tests.setBuildMode(mode);

    const set1_tests = b.addTest("src/crypto/set1.zig");
    set1_tests.addPackagePath("utils", "src/utils.zig");

    set1_tests.addIncludeDir("lib/tiny-AES-c");
    set1_tests.linkLibrary(tinyaes);
    set1_tests.setTarget(target);
    set1_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&utils_tests.step);
    test_step.dependOn(&set1_tests.step);
}
