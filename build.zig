const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const with_boringssl = b.option([]const u8, "with-boringssl", "Path to BoringSSL install") orelse "";

    const lib_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    if (with_boringssl.len > 0) {
        var buf_include: [std.posix.PATH_MAX]u8 = undefined;
        var buf_include_alloc = std.heap.FixedBufferAllocator.init(&buf_include);
        const path_include = try std.fs.path.join(buf_include_alloc.allocator(), &.{ with_boringssl, "include" });

        var buf_lib: [std.posix.PATH_MAX]u8 = undefined;
        var buf_lib_alloc = std.heap.FixedBufferAllocator.init(&buf_lib);
        const path_lib = try std.fs.path.join(buf_lib_alloc.allocator(), &.{ with_boringssl, "lib" });

        lib_module.addIncludePath(b.path(path_include));
        lib_module.addLibraryPath(b.path(path_lib));
    } else {
        lib_module.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        lib_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
    }
    lib_module.linkSystemLibrary("crypto", .{});

    lib_module.addCSourceFiles(.{ .files = &.{"src/partially_blind_rsa.c"} });

    const lib = b.addLibrary(.{
        .name = "pbrsa",
        .root_module = lib_module,
    });
    b.installArtifact(lib);

    const exe_module = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    if (with_boringssl.len > 0) {
        var buf_include: [std.posix.PATH_MAX]u8 = undefined;
        var buf_include_alloc = std.heap.FixedBufferAllocator.init(&buf_include);
        const path_include = try std.fs.path.join(buf_include_alloc.allocator(), &.{ with_boringssl, "include" });

        var buf_lib: [std.posix.PATH_MAX]u8 = undefined;
        var buf_lib_alloc = std.heap.FixedBufferAllocator.init(&buf_lib);
        const path_lib = try std.fs.path.join(buf_lib_alloc.allocator(), &.{ with_boringssl, "lib" });

        exe_module.addIncludePath(b.path(path_include));
        exe_module.addLibraryPath(b.path(path_lib));
    } else {
        exe_module.addIncludePath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/include" });
        exe_module.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/opt/openssl@3/lib" });
    }

    exe_module.addCSourceFiles(.{ .files = &.{"src/test_partially_blind_rsa.c"} });
    exe_module.linkLibrary(lib);

    const exe = b.addExecutable(.{
        .name = "c-partially-blind-rsa-signatures",
        .root_module = exe_module,
    });

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_exe_unit_tests = b.addRunArtifact(exe);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
