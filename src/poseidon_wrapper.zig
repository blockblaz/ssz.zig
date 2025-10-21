//! Provides a SHA256-compatible API wrapper for Poseidon2 hash function.
//! This allows Poseidon2 to be used as a drop-in replacement for SHA256
//! in merkleization and hash tree root operations.
//!
//! IMPORTANT: This is a specialized wrapper for SSZ merkleization, which always
//! provides exactly 64 bytes (two 32-byte hashes). It is NOT a general-purpose
//! hash function and will produce collisions for variable-length inputs due to
//! simple zero-padding (e.g., "abc" and "abc\x00" would hash identically).

const std = @import("std");

/// Creates a hasher type that wraps a Poseidon2 instance with SHA256-like API
pub fn PoseidonHasher(comptime Poseidon2Type: type) type {
    const WIDTH = 16; // Poseidon2 width (16 field elements)
    const FIELD_ELEM_SIZE = 4; // u32 = 4 bytes
    const BUFFER_SIZE = WIDTH * FIELD_ELEM_SIZE; // 64 bytes
    const OUTPUT_FIELD_ELEMS = 8; // 8 u32s = 32 bytes output

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
        /// Note: This accumulates data. Poseidon2 requires exactly 64 bytes,
        /// so we buffer until we have enough data.
        pub fn update(self: *Self, data: []const u8) void {
            // Enforce the 64-byte limit explicitly
            std.debug.assert(self.buffer_len + data.len <= BUFFER_SIZE);

            // Copy data into buffer
            const space_left = BUFFER_SIZE - self.buffer_len;
            const copy_len = @min(data.len, space_left);

            @memcpy(self.buffer[self.buffer_len..][0..copy_len], data[0..copy_len]);
            self.buffer_len += copy_len;
        }

        /// Finalize the hash and write the result to out
        pub fn final(self: *Self, out: *[32]u8) void {
            // Pad buffer to 64 bytes if needed
            if (self.buffer_len < BUFFER_SIZE) {
                @memset(self.buffer[self.buffer_len..BUFFER_SIZE], 0);
            }

            // Convert bytes to field elements (u32s) using little-endian encoding
            var input: [WIDTH]u32 = undefined;
            for (0..WIDTH) |i| {
                input[i] = std.mem.readInt(u32, self.buffer[i * FIELD_ELEM_SIZE ..][0..FIELD_ELEM_SIZE], .little) % Poseidon2Type.Field.MODULUS;
            }

            // Hash with Poseidon2 compress function
            // Output 8 field elements (32 bytes total)
            const output = Poseidon2Type.compress(OUTPUT_FIELD_ELEMS, input);

            // Convert field elements back to bytes using little-endian encoding
            for (0..OUTPUT_FIELD_ELEMS) |i| {
                std.mem.writeInt(u32, out[i * FIELD_ELEM_SIZE ..][0..FIELD_ELEM_SIZE], output[i], .little);
            }

            // Reset buffer for potential reuse
            self.buffer_len = 0;
        }
    };
}

test "PoseidonHasher basic API" {
    // This test just verifies the API compiles and runs
    // Actual hash correctness should be verified against known test vectors
    const poseidon = @import("poseidon");
    const Hasher = PoseidonHasher(poseidon.Poseidon2KoalaBear16);

    var hasher = Hasher.init(.{});
    const data = "test data for hashing";
    hasher.update(data);

    var output: [32]u8 = undefined;
    hasher.final(&output);

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
    const poseidon = @import("poseidon");
    const Hasher = PoseidonHasher(poseidon.Poseidon2KoalaBear16);

    var hasher1 = Hasher.init(.{});
    var hasher2 = Hasher.init(.{});

    const data = "deterministic test data";
    hasher1.update(data);
    hasher2.update(data);

    var output1: [32]u8 = undefined;
    var output2: [32]u8 = undefined;
    hasher1.final(&output1);
    hasher2.final(&output2);

    try std.testing.expectEqualSlices(u8, &output1, &output2);
}

test "PoseidonHasher different inputs produce different outputs" {
    // Verify different inputs produce different outputs
    const poseidon = @import("poseidon");
    const Hasher = PoseidonHasher(poseidon.Poseidon2KoalaBear16);

    var hasher1 = Hasher.init(.{});
    var hasher2 = Hasher.init(.{});

    const data1 = "first test data";
    const data2 = "second test data";

    hasher1.update(data1);
    hasher2.update(data2);

    var output1: [32]u8 = undefined;
    var output2: [32]u8 = undefined;
    hasher1.final(&output1);
    hasher2.final(&output2);

    // Verify outputs are different
    const are_equal = std.mem.eql(u8, &output1, &output2);
    try std.testing.expect(!are_equal);
}
