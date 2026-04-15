const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    // WASM target (wasm32-freestanding)
    const wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
    });

    // Resolve webauthn dependency for WASM
    const wasm_webauthn_dep = b.dependency("webauthn", .{
        .target = wasm_target,
        .optimize = optimize,
    });

    const wasm = b.addExecutable(.{
        .name = "zig-auth",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = wasm_target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{
                .{ .name = "webauthn", .module = wasm_webauthn_dep.module("webauthn") },
            },
        }),
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    b.installArtifact(wasm);

    // Native test target
    const native_target = b.standardTargetOptions(.{});

    // Resolve webauthn dependency for native tests
    const native_webauthn_dep = b.dependency("webauthn", .{
        .target = native_target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run unit tests");
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = native_target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "webauthn", .module = native_webauthn_dep.module("webauthn") },
            },
        }),
    });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);
}
