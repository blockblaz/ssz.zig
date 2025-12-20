//! Provides a SHA256-compatible API wrapper for Poseidon2 hash function.
//! This allows Poseidon2 to be used as a drop-in replacement for SHA256
//! in merkleization and hash tree root operations.
//!
//! IMPORTANT: This is a specialized wrapper for SSZ merkleization, which always
//! provides exactly 64 bytes (two 32-byte nodes). It is NOT a general-purpose
//! hash function: it enforces the fixed 64-byte input length and intentionally
//! does not implement any padding scheme.

const std = @import("std");

/// Creates a hasher type that wraps a Poseidon2 instance with SHA256-like API
pub fn PoseidonHasher(comptime Poseidon2Type: type) type {
    // SSZ compression in this codebase is always:
    //   H: {0,1}^512 -> {0,1}^256
    // i.e. exactly 64 bytes in, 32 bytes out.
    const BUFFER_SIZE = 64;

    // Poseidon2-24 state width.
    const WIDTH = 24;

    // Compile-time safety: verify Poseidon2Type has the required interface
    comptime {
        if (!@hasDecl(Poseidon2Type, "Field")) {
            @compileError("Poseidon2Type must have a 'Field' declaration");
        }
        if (!@hasDecl(Poseidon2Type, "permutation")) {
            @compileError("Poseidon2Type must have a 'permutation' function");
        }
        if (!@hasDecl(Poseidon2Type, "WIDTH")) {
            @compileError("Poseidon2Type must expose a WIDTH constant");
        }
        if (Poseidon2Type.WIDTH != WIDTH) {
            @compileError(std.fmt.comptimePrint(
                "PoseidonHasher requires width-{d} Poseidon2, got width-{d}",
                .{ WIDTH, Poseidon2Type.WIDTH },
            ));
        }
    }

    // We encode 64 bytes as 22 limbs of 24 bits each (little-endian within each limb),
    // which are always < 2^24 < p (KoalaBear prime), avoiding lossy modular reduction:
    // 64 bytes = 21*3 + 1  => 22 limbs, fits in a single width-24 permutation.
    const LIMBS = 22;

    const FIELD_ELEM_SIZE = 4; // u32 = 4 bytes
    const OUTPUT_FIELD_ELEMS = 8; // 8 u32s = 32 bytes

    return struct {
        const Self = @This();

        // Accumulated input bytes
        buffer: [BUFFER_SIZE]u8,
        buffer_len: usize,

        /// Options struct for compatibility with std.crypto.hash API
        pub const Options = struct {};

        /// Initialize a new hasher instance
        pub fn init(_: Options) Self {
            return .{
                .buffer = undefined,
                .buffer_len = 0,
            };
        }

        /// Update the hasher with new data
        /// Note: This accumulates data. SSZ compression requires exactly 64 bytes,
        /// so we buffer until we have enough data.
        pub fn update(self: *Self, data: []const u8) void {
            // Enforce the 64-byte limit explicitly
            std.debug.assert(self.buffer_len + data.len <= BUFFER_SIZE);

            // Copy data into buffer
            @memcpy(self.buffer[self.buffer_len..][0..data.len], data);
            self.buffer_len += data.len;
        }

        /// Finalize the hash and write the result to out
        pub fn final(self: *Self, out: []u8) void {
            std.debug.assert(out.len == 32);
            // Enforce exact length: SSZ internal nodes and mix-in-length always pass 64 bytes.
            std.debug.assert(self.buffer_len == BUFFER_SIZE);

            // Byte -> 24-bit limb packing (injective for fixed 64-byte inputs).
            var limbs: [LIMBS]u32 = undefined;
            for (0..(LIMBS - 1)) |i| {
                const j = i * 3;
                limbs[i] = @as(u32, self.buffer[j]) |
                    (@as(u32, self.buffer[j + 1]) << 8) |
                    (@as(u32, self.buffer[j + 2]) << 16);
            }
            limbs[LIMBS - 1] = @as(u32, self.buffer[63]);

            // Build Poseidon2 state: 22 limbs + 2 zero lanes.
            var state: [WIDTH]Poseidon2Type.Field = undefined;
            for (0..LIMBS) |i| {
                state[i] = Poseidon2Type.Field.fromU32(limbs[i]);
            }
            state[22] = Poseidon2Type.Field.zero;
            state[23] = Poseidon2Type.Field.zero;

            // TruncatedPermutation semantics (no feed-forward): permute, then squeeze.
            Poseidon2Type.permutation(state[0..]);

            // Squeeze first 8 lanes as 32 bytes, little-endian u32 per lane.
            for (0..OUTPUT_FIELD_ELEMS) |i| {
                const v = state[i].toU32();
                std.mem.writeInt(u32, out[i * FIELD_ELEM_SIZE ..][0..FIELD_ELEM_SIZE], v, .little);
            }

            // Reset buffer for potential reuse.
            self.buffer_len = 0;
        }

        /// Convenience helper used by some generic code (e.g. zero-hash builders).
        pub fn finalResult(self: *Self) [32]u8 {
            var out: [32]u8 = undefined;
            self.final(out[0..]);
            return out;
        }
    };
}

test "PoseidonHasher basic API" {
    // This test just verifies the API compiles and runs.
    const hash_zig = @import("hash_zig");
    const Hasher = PoseidonHasher(hash_zig.poseidon2.Poseidon2KoalaBear24Plonky3);

    var hasher = Hasher.init(.{});
    const data = [_]u8{0x01} ** 64;
    hasher.update(data[0..]);

    var output: [32]u8 = undefined;
    hasher.final(output[0..]);

    // Just verify we got some output (not all zeros)
    var has_nonzero = false;
    for (output) |byte| {
        if (byte != 0) {
            has_nonzero = true;
            break;
        }
    }
    try std.testing.expect(has_nonzero);
}

test "PoseidonHasher deterministic" {
    // Verify same input produces same output
    const hash_zig = @import("hash_zig");
    const Hasher = PoseidonHasher(hash_zig.poseidon2.Poseidon2KoalaBear24Plonky3);

    var hasher1 = Hasher.init(.{});
    var hasher2 = Hasher.init(.{});

    const data = [_]u8{0x42} ** 64;
    hasher1.update(data[0..]);
    hasher2.update(data[0..]);

    var output1: [32]u8 = undefined;
    var output2: [32]u8 = undefined;
    hasher1.final(output1[0..]);
    hasher2.final(output2[0..]);

    try std.testing.expectEqualSlices(u8, &output1, &output2);
}

test "PoseidonHasher different inputs produce different outputs" {
    // Verify different inputs produce different outputs
    const hash_zig = @import("hash_zig");
    const Hasher = PoseidonHasher(hash_zig.poseidon2.Poseidon2KoalaBear24Plonky3);

    var hasher1 = Hasher.init(.{});
    var hasher2 = Hasher.init(.{});

    const data1 = [_]u8{0x01} ** 64;
    const data2 = [_]u8{0x02} ** 64;

    hasher1.update(data1[0..]);
    hasher2.update(data2[0..]);

    var output1: [32]u8 = undefined;
    var output2: [32]u8 = undefined;
    hasher1.final(output1[0..]);
    hasher2.final(output2[0..]);

    // Verify outputs are different
    const are_equal = std.mem.eql(u8, &output1, &output2);
    try std.testing.expect(!are_equal);
}
