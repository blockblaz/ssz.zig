const libssz = @import("ssz.zig");
const utils = libssz.utils;
const serialize = libssz.serialize;
const deserialize = libssz.deserialize;
const chunkCount = libssz.chunkCount;
const hashTreeRoot = libssz.hashTreeRoot;
const isFixedSizeObject = libssz.isFixedSizeObject;
const std = @import("std");
const ArrayList = std.ArrayList;
const expect = std.testing.expect;
const sha256 = std.crypto.hash.sha2.Sha256;

test "serializes uint8" {
    const data: u8 = 0x55;
    const serialized_data = [_]u8{0x55};

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u8, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "serializes uint16" {
    const data: u16 = 0x5566;
    const serialized_data = [_]u8{ 0x66, 0x55 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u16, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "serializes uint32" {
    const data: u32 = 0x55667788;
    const serialized_data = [_]u8{ 0x88, 0x77, 0x66, 0x55 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(u32, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "serializes a int32" {
    const data: i32 = -(0x11223344);
    const serialized_data = [_]u8{ 0xbc, 0xcc, 0xdd, 0xee };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(i32, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "non-byte aligned int serialization fails" {
    const data: u10 = 0x03ff;
    var list = ArrayList(u8).init(std.testing.allocator);
    try std.testing.expectError(error.InvalidSerializedIntLengthType, serialize(u10, data, &list));
}

test "serializes bool" {
    var data = false;
    var serialized_data = [_]u8{0x00};

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(bool, data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));

    data = true;
    serialized_data = [_]u8{0x01};

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();
    try serialize(bool, data, &list2);
    try expect(std.mem.eql(u8, list2.items, serialized_data[0..]));
}

test "serializes Bitvector[N] == [N]bool" {
    const data7 = [_]bool{ true, false, true, true, false, false, false };
    var serialized_data = [_]u8{0b00001101};
    var exp = serialized_data[0..serialized_data.len];

    var list7 = ArrayList(u8).init(std.testing.allocator);
    defer list7.deinit();
    try serialize([7]bool, data7, &list7);
    try expect(std.mem.eql(u8, list7.items, exp));

    const data8 = [_]bool{ true, false, true, true, false, false, false, true };
    serialized_data = [_]u8{0b10001101};
    exp = serialized_data[0..serialized_data.len];

    var list8 = ArrayList(u8).init(std.testing.allocator);
    defer list8.deinit();
    try serialize([8]bool, data8, &list8);
    try expect(std.mem.eql(u8, list8.items, exp));

    const data12 = [_]bool{ true, false, true, true, false, false, false, true, false, true, false, true };

    var list12 = ArrayList(u8).init(std.testing.allocator);
    defer list12.deinit();
    try serialize([12]bool, data12, &list12);
    try expect(list12.items.len == 2);
    try expect(list12.items[0] == 141);
    try expect(list12.items[1] == 10);
}

test "serializes string" {
    const data = "zig zag";

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([]const u8, data, &list);
    try expect(std.mem.eql(u8, list.items, data));
}

test "serializes an array of shorts" {
    const data = [_]u16{ 0xabcd, 0xef01 };
    const serialized = [_]u8{ 0xcd, 0xab, 0x01, 0xef };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([]const u16, data[0..data.len], &list);
    try expect(std.mem.eql(u8, list.items, serialized[0..]));
}

test "serializes an array of structures" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const exp = [_]u8{ 8, 0, 0, 0, 23, 0, 0, 0, 6, 0, 0, 0, 20, 0, 99, 114, 111, 105, 115, 115, 97, 110, 116, 6, 0, 0, 0, 244, 1, 72, 101, 114, 114, 101, 110, 116, 111, 114, 116, 101 };

    try serialize(@TypeOf(pastries), pastries, &list);
    try expect(std.mem.eql(u8, list.items, exp[0..]));
}

test "serializes a structure without variable fields" {
    const data = .{
        .uint8 = @as(u8, 1),
        .uint32 = @as(u32, 3),
        .boolean = true,
    };
    const serialized_data = [_]u8{ 1, 3, 0, 0, 0, 1 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(data), data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
}

test "(de)serializes a structure with variable fields" {
    // Taken from ssz.cr
    const Person = struct {
        name: []const u8,
        age: u8,
        company: []const u8,
    };
    var data = Person{
        .name = "James",
        .age = 32,
        .company = "DEV Inc.",
    };
    const serialized_data = [_]u8{ 9, 0, 0, 0, 32, 14, 0, 0, 0, 74, 97, 109, 101, 115, 68, 69, 86, 32, 73, 110, 99, 46 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    // Note the `&data` - this is so that `data` is not considered const.
    try serialize(@TypeOf(&data), &data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));
    var out: @TypeOf(data) = undefined;
    try deserialize(@TypeOf(data), list.items, &out, null);
}

test "serializes a structure with optional fields" {
    const Employee = struct {
        name: ?[]const u8,
        age: u8,
        company: ?[]const u8,
    };
    const data: Employee = .{
        .name = "James",
        .age = @as(u8, 32),
        .company = null,
    };

    const serialized_data = [_]u8{ 9, 0, 0, 0, 32, 15, 0, 0, 0, 1, 74, 97, 109, 101, 115, 0 };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(data), data, &list);
    try expect(std.mem.eql(u8, list.items, serialized_data[0..]));

    var deserialized: Employee = undefined;
    try deserialize(Employee, list.items, &deserialized, null);
    // only available in >=0.11
    // try std.testing.expectEqualDeep(data, deserialized);
    try expect(std.mem.eql(u8, data.name.?, deserialized.name.?));
    try std.testing.expectEqual(data.age, deserialized.age);
    try std.testing.expectEqual(deserialized.company, null);
}

test "serializes an optional object" {
    const null_or_string: ?[]const u8 = null;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(null_or_string), null_or_string, &list);
    try expect(list.items.len == 1);
}

test "serializes a union" {
    const Payload = union(enum) {
        int: u64,
        boolean: bool,
    };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const exp = [_]u8{ 0, 210, 4, 0, 0, 0, 0, 0, 0 };
    try serialize(Payload, Payload{ .int = 1234 }, &list);
    try expect(std.mem.eql(u8, list.items, exp[0..]));

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();
    const exp2 = [_]u8{ 1, 1 };
    try serialize(Payload, Payload{ .boolean = true }, &list2);
    try expect(std.mem.eql(u8, list2.items, exp2[0..]));

    // Make sure that the code won't try to serialize untagged
    // payloads.
    const UnTaggedPayload = union {
        int: u64,
        boolean: bool,
    };

    var list3 = ArrayList(u8).init(std.testing.allocator);
    defer list3.deinit();
    if (serialize(UnTaggedPayload, UnTaggedPayload{ .boolean = false }, &list3)) {
        @panic("didn't catch error");
    } else |err| switch (err) {
        error.UnionIsNotTagged => {},
    }
}

test "(de)serializes a type with a custom serialization method" {
    const MyCustomSerializingType = struct {
        len: usize,
        buffer: [100]u8,

        const Self = @This();

        pub fn sszEncode(self: *const Self, list: *ArrayList(u8)) !void {
            try list.append(@truncate(self.len));
            try list.appendSlice(self.buffer[0..self.len]);
        }

        pub fn sszDecode(serialized: []const u8, out: *Self, _: ?std.mem.Allocator) !void {
            if (serialized.len == 0) {
                return error.IndexOutOfBounds;
            }

            out.len = @intCast(serialized[0]);
            if (out.len > serialized.len - 1) {
                return error.IndexOutOfBounds;
            }

            std.mem.copyForwards(u8, out.buffer[0..], serialized[1..]);
        }
    };

    var before: MyCustomSerializingType = .{ .len = 10, .buffer = [_]u8{0} ** 100 };
    before.buffer[0] = 1;
    before.buffer[9] = 100;

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(MyCustomSerializingType, before, &list);

    try expect(list.items.len == 11);

    var after: MyCustomSerializingType = undefined;
    try deserialize(MyCustomSerializingType, list.items, &after, null);

    try expect(before.len == after.len);
    try expect(std.mem.eql(u8, before.buffer[0..before.len], after.buffer[0..after.len]));
}

test "deserializes an u8" {
    const payload = [_]u8{0x55};
    var i: u8 = 0;
    try deserialize(u8, payload[0..payload.len], &i, null);
    try expect(i == 0x55);
}

test "deserializes an u32" {
    const payload = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    var i: u32 = 0;
    try deserialize(u32, payload[0..payload.len], &i, null);
    try expect(i == 0x88776655);
}

test "deserializes a boolean" {
    const payload_false = [_]u8{0};
    var b = true;
    try deserialize(bool, payload_false[0..1], &b, null);
    try expect(b == false);

    const payload_true = [_]u8{1};
    try deserialize(bool, payload_true[0..1], &b, null);
    try expect(b == true);
}

test "deserializes a Bitvector[N]" {
    const exp = [_]bool{ true, false, true, true, false, false, false };
    var out = [_]bool{ false, false, false, false, false, false, false };
    const serialized_data = [_]u8{0b00001101};
    try deserialize([7]bool, serialized_data[0..1], &out, null);
    comptime var i = 0;
    inline while (i < 7) : (i += 1) {
        try expect(out[i] == exp[i]);
    }
}

test "deserializes an Optional" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    var out: ?u32 = undefined;
    const exp: ?u32 = 10;
    try serialize(?u32, exp, &list);
    try deserialize(?u32, list.items, &out, null);
    try expect(out.? == exp.?);

    var list2 = ArrayList(u8).init(std.testing.allocator);
    defer list2.deinit();

    try serialize(?u32, null, &list2);
    try deserialize(?u32, list2.items, &out, null);
    try expect(out == null);
}

test "deserializes a string" {
    const exp = "croissants";

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize([]const u8, exp, &list);

    var got: []const u8 = undefined;

    // Deserialize without allocator. The variable
    // must be of type const.
    try deserialize([]const u8, list.items, &got, null);
    try expect(std.mem.eql(u8, exp, got));

    // deserialize with allocator
    var got_var: []u8 = undefined;
    try deserialize([]u8, list.items, &got_var, std.testing.allocator);
    defer std.testing.allocator.free(got_var);
    try expect(std.mem.eql(u8, exp, got));
}

const Pastry = struct {
    name: []const u8,
    weight: u16,
};

const pastries = [_]Pastry{
    Pastry{
        .name = "croissant",
        .weight = 20,
    },
    Pastry{
        .name = "Herrentorte",
        .weight = 500,
    },
};

test "deserializes a structure" {
    var out = Pastry{ .name = "", .weight = 0 };
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try serialize(Pastry, pastries[0], &list);
    try deserialize(Pastry, list.items, &out, null);

    try expect(pastries[0].weight == out.weight);
    try expect(std.mem.eql(u8, pastries[0].name, out.name));
}

test "deserializes a Vector[N]" {
    var out: [2]Pastry = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try serialize([2]Pastry, pastries, &list);
    try deserialize(@TypeOf(pastries), list.items, &out, null);
    comptime var i = 0;
    inline while (i < pastries.len) : (i += 1) {
        try expect(out[i].weight == pastries[i].weight);
        try expect(std.mem.eql(u8, pastries[i].name, out[i].name));
    }
}

test "deserializes an invalid Vector[N] payload" {
    var out: [2]Pastry = undefined;
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    try serialize([2]Pastry, pastries, &list);
    if (deserialize(@TypeOf(pastries), list.items[0 .. list.items.len / 2], &out, null)) {
        @panic("missed error");
    } else |err| switch (err) {
        error.IndexOutOfBounds => {},
        error.NoSerializedFixedSizeAvailable => {},
        // NOTE: this is to be uncommented if slices start using allocators
        // else => @panic(try std.fmt.allocPrint(std.testing.allocator, "wrong type of error found, err={any}", .{err})),
    }
}

test "deserializes an union" {
    const Payload = union {
        int: u32,
        boolean: bool,
    };

    var p: Payload = undefined;
    try deserialize(Payload, ([_]u8{ 1, 1 })[0..], &p, null);
    try expect(p.boolean == true);

    try deserialize(Payload, ([_]u8{ 1, 0 })[0..], &p, null);
    try expect(p.boolean == false);

    try deserialize(Payload, ([_]u8{ 0, 1, 2, 3, 4 })[0..], &p, null);
    try expect(p.int == 0x04030201);
}

test "serialize/deserialize a u256" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    const data = [_]u8{0xAA} ** 32;
    var output: [32]u8 = undefined;

    try serialize([32]u8, data, &list);
    try deserialize([32]u8, list.items, &output, null);

    try expect(std.mem.eql(u8, data[0..], output[0..]));
}

test "(de)serialize a .One pointer in a struct" {
    var a: u32 = 1;
    const b = .{
        .a = &a,
    };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(b), b, &list);
    var c_val: u32 = undefined;
    var c: @TypeOf(b) = .{ .a = &c_val };
    try deserialize(@TypeOf(b), list.items, &c, std.testing.allocator);
    std.testing.allocator.destroy(c.a);
}

test "(de)serialize a slice of structs" {
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();

    // force runtime evaluation of the slice using a
    // runtime start and end.
    var start: usize = 0;
    var end: usize = pastries.len;
    _ = .{ &start, &end };

    try serialize([]Pastry, @constCast(pastries[start..end]), &list);

    // pre-allocated deserialization
    var deser_const_pastries: [pastries.len]Pastry = undefined;
    try deserialize([]Pastry, list.items, @constCast(&deser_const_pastries[start..end]), null);

    // allocating deserialization
    var deser_var_pastries: []Pastry = undefined;
    try deserialize([]Pastry, list.items, @constCast(&deser_var_pastries), std.testing.allocator);
    std.testing.allocator.free(deser_var_pastries);
}

test "chunk count of basic types" {
    try expect(chunkCount(bool) == 1);
    try expect(chunkCount(u8) == 1);
    try expect(chunkCount(u16) == 1);
    try expect(chunkCount(u32) == 1);
    try expect(chunkCount(u64) == 1);
}

test "chunk count of Bitvector[N]" {
    try expect(chunkCount([7]bool) == 1);
    try expect(chunkCount([12]bool) == 1);
    try expect(chunkCount([384]bool) == 2);
}

test "chunk count of Vector[B, N]" {
    try expect(chunkCount([17]u32) == 3);
}

test "chunk count of a struct" {
    try expect(chunkCount(Pastry) == 2);
}

test "chunk count of a Vector[C, N]" {
    try expect(chunkCount([2]Pastry) == 2);
}

// used at comptime to generate a bitvector from a byte vector
fn bytesToBits(comptime N: usize, src: [N]u8) [N * 8]bool {
    var bitvector: [N * 8]bool = undefined;
    for (src, 0..) |byte, idx| {
        var i = 0;
        while (i < 8) : (i += 1) {
            bitvector[i + idx * 8] = ((byte >> (7 - i)) & 1) == 1;
        }
    }
    return bitvector;
}

const a_bytes = [_]u8{0xaa} ** 16;
const b_bytes = [_]u8{0xbb} ** 16;
const c_bytes = [_]u8{0xcc} ** 16;
const d_bytes = [_]u8{0xdd} ** 16;
const e_bytes = [_]u8{0xee} ** 16;
const empty_bytes = [_]u8{0} ** 16;

const a_bits = bytesToBits(16, a_bytes);
const b_bits = bytesToBits(16, b_bytes);
const c_bits = bytesToBits(16, c_bytes);
const d_bits = bytesToBits(16, d_bytes);
const e_bits = bytesToBits(16, e_bytes);

test "calculate the root hash of a boolean" {
    var expected = [_]u8{1} ++ [_]u8{0} ** 31;
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(bool, true, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));

    expected = [_]u8{0} ** 32;
    try hashTreeRoot(bool, false, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate root hash of an array of two Bitvector[128]" {
    const deserialized: [2][128]bool = [2][128]bool{ a_bits, b_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(@TypeOf(deserialized), deserialized, &hashed, std.testing.allocator);

    var expected: [32]u8 = undefined;
    const expected_preimage = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    sha256.hash(expected_preimage[0..], &expected, sha256.Options{});

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an array of integers" {
    var expected = [_]u8{ 0xef, 0xbe, 0xad, 0xde, 0xfe, 0xca, 0xfe, 0xca } ++ [_]u8{0} ** 24;
    var hashed: [32]u8 = undefined;
    try hashTreeRoot([2]u32, [_]u32{ 0xdeadbeef, 0xcafecafe }, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate root hash of an array of three Bitvector[128]" {
    const deserialized: [3][128]bool = [3][128]bool{ a_bits, b_bits, c_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(@TypeOf(deserialized), deserialized, &hashed, std.testing.allocator);

    var left: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    const preimg1 = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    const preimg2 = c_bytes ++ empty_bytes ** 3;
    sha256.hash(preimg1[0..], &left, sha256.Options{});
    sha256.hash(preimg2[0..], &expected, sha256.Options{});
    var digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(expected[0..]);
    digest.final(&expected);

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an array of five Bitvector[128]" {
    const deserialized = [5][128]bool{ a_bits, b_bits, c_bits, d_bits, e_bits };
    var hashed: [32]u8 = undefined;
    try hashTreeRoot(@TypeOf(deserialized), deserialized, &hashed, std.testing.allocator);

    var internal_nodes: [64]u8 = undefined;
    var left: [32]u8 = undefined;
    var expected: [32]u8 = undefined;
    const preimg1 = a_bytes ++ empty_bytes ++ b_bytes ++ empty_bytes;
    const preimg2 = c_bytes ++ empty_bytes ++ d_bytes ++ empty_bytes;
    const preimg3 = e_bytes ++ empty_bytes ** 3;
    const preimg4 = empty_bytes ** 4;

    sha256.hash(preimg1[0..], &left, sha256.Options{});
    sha256.hash(preimg2[0..], internal_nodes[0..32], sha256.Options{});
    var digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(internal_nodes[0..32]);
    digest.final(internal_nodes[0..32]);

    sha256.hash(preimg3[0..], &left, sha256.Options{});
    sha256.hash(preimg4[0..], internal_nodes[32..], sha256.Options{});
    digest = sha256.init(sha256.Options{});
    digest.update(left[0..]);
    digest.update(internal_nodes[32..]);
    digest.final(internal_nodes[32..]);

    sha256.hash(internal_nodes[0..], &expected, sha256.Options{});

    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

const Fork = struct {
    previous_version: [4]u8,
    current_version: [4]u8,
    epoch: u64,
};

test "calculate the root hash of a structure" {
    var hashed: [32]u8 = undefined;
    const fork = Fork{
        .previous_version = [_]u8{ 0x9c, 0xe2, 0x5d, 0x26 },
        .current_version = [_]u8{ 0x36, 0x90, 0x55, 0x93 },
        .epoch = 3,
    };
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected[0..], "58316a908701d3660123f0b8cb7839abdd961f71d92993d34e4f480fbec687d9");
    try hashTreeRoot(Fork, fork, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an Optional" {
    var hashed: [32]u8 = undefined;
    var payload: [64]u8 = undefined;
    const v: ?u32 = null;
    const u: ?u32 = 0xdeadbeef;
    var expected: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(payload[0..], "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], expected[0..], sha256.Options{});
    try hashTreeRoot(?u32, v, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));

    _ = try std.fmt.hexToBytes(payload[0..], "efbeadde000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], expected[0..], sha256.Options{});
    try hashTreeRoot(?u32, u, &hashed, std.testing.allocator);
    try expect(std.mem.eql(u8, hashed[0..], expected[0..]));
}

test "calculate the root hash of an union" {
    const Payload = union(enum) {
        int: u64,
        boolean: bool,
    };
    var out: [32]u8 = undefined;
    var payload: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(payload[0..], "d2040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    var exp1: [32]u8 = undefined;
    sha256.hash(payload[0..], exp1[0..], sha256.Options{});
    try hashTreeRoot(Payload, Payload{ .int = 1234 }, &out, std.testing.allocator);
    try expect(std.mem.eql(u8, out[0..], exp1[0..]));

    var exp2: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(payload[0..], "01000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000");
    sha256.hash(payload[0..], exp2[0..], sha256.Options{});
    try hashTreeRoot(Payload, Payload{ .boolean = true }, &out, std.testing.allocator);
    try expect(std.mem.eql(u8, out[0..], exp2[0..]));
}

test "(de)serialize List[N] of fixed-length objects" {
    const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
    const ListValidatorIndex = utils.List(u64, MAX_VALIDATORS_PER_COMMITTEE);
    var attesting_indices = try ListValidatorIndex.init(0);
    for (0..10) |i| {
        try attesting_indices.append(i * 100);
    }
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(ListValidatorIndex, attesting_indices, &list);
    var attesting_indices_deser = try ListValidatorIndex.init(0);
    try deserialize(ListValidatorIndex, list.items, &attesting_indices_deser, null);
    try expect(attesting_indices.eql(&attesting_indices_deser));
}

test "(de)serialize List[N] of variable-length objects" {
    const ListOfStrings = utils.List([]const u8, 16);
    var string_list = try ListOfStrings.init(0);
    for (0..10) |i| {
        try string_list.append(try std.fmt.allocPrint(std.testing.allocator, "count={}", .{i}));
    }
    defer for (0..string_list.len()) |i| {
        std.testing.allocator.free(string_list.get(i));
    };
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(ListOfStrings, string_list, &list);
    var string_list_deser = try ListOfStrings.init(0);
    try deserialize(ListOfStrings, list.items, &string_list_deser, null);
    try expect(string_list.len() == string_list_deser.len());
    for (0..string_list.len()) |i| {
        try expect(std.mem.eql(u8, string_list.get(i), string_list_deser.get(i)));
    }
}

test "List[N].fromSlice of structs" {
    const PastryList = utils.List(Pastry, 100);
    var start: usize = 0;
    var end: usize = pastries.len;
    _ = .{ &start, &end };
    const pastry_list = try PastryList.fromSlice(pastries[start..end]);
    for (pastries, 0..) |pastry, i| {
        try expect(std.mem.eql(u8, pastry_list.get(i).name, pastry.name));
        try expect(pastry_list.get(i).weight == pastry.weight);
    }
}

test "(de)serialization of Bitlist[N]" {
    var bitlist = try utils.Bitlist(10).init(0);
    try bitlist.append(true);
    try bitlist.append(false);
    try bitlist.append(true);
    try expect(bitlist.get(1) == false);
    try expect(bitlist.get(2) == true);

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(bitlist), bitlist, &list);
    var bitlist_deser: @TypeOf(bitlist) = undefined;
    try deserialize(@TypeOf(bitlist), list.items, &bitlist_deser, null);
}

test "(de)serialization of Bitlist[N] when N % 8 != 0" {
    var bitlist = try utils.Bitlist(3).init(0);
    try bitlist.append(true);
    try bitlist.append(false);
    try bitlist.append(true);
    try expect(bitlist.get(1) == false);
    try expect(bitlist.get(2) == true);

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(@TypeOf(bitlist), bitlist, &list);
    var bitlist_deser: @TypeOf(bitlist) = undefined;
    try deserialize(@TypeOf(bitlist), list.items, &bitlist_deser, null);
    try expect(bitlist.len() == bitlist_deser.len());
    try expect(bitlist.eql(&bitlist_deser));
}

test "structs with nested fixed/variable size u8 array" {
    const Bytes32 = [32]u8;
    var isFixedSizeType = try isFixedSizeObject(Bytes32);
    try expect(isFixedSizeType == true);

    const BytesVar = []u8;
    isFixedSizeType = try isFixedSizeObject(BytesVar);
    try expect(isFixedSizeType == false);

    // 1.1 test for nested but fixed structures
    const FixedBlockBody = struct {
        slot: u64,
        data: [4]u8,
    };
    const FixedBlock = struct {
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body: FixedBlockBody,
    };
    const FixedSignedBlock = struct {
        message: FixedBlock,
        signature: [48]u8,
    };
    isFixedSizeType = try isFixedSizeObject(FixedSignedBlock);
    try expect(isFixedSizeType == true);
    const fixed_signed_block = FixedSignedBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .slot = 9, .data = [_]u8{ 1, 2, 3, 4 } },
        },
        .signature = [_]u8{2} ** 48,
    };
    var serialized_fixed_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_fixed_block.deinit();
    try serialize(FixedSignedBlock, fixed_signed_block, &serialized_fixed_block);
    // 1.2 verified on an equivalent nodejs container implementation
    const expected_serialized_fixed_block = [_]u8{ 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60, 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231, 9, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2 };
    try expect(std.mem.eql(u8, serialized_fixed_block.items, expected_serialized_fixed_block[0..]));

    var deserialized_fixed_block: FixedSignedBlock = undefined;
    try deserialize(FixedSignedBlock, serialized_fixed_block.items[0..], &deserialized_fixed_block, std.testing.allocator);

    // 1.3 match the individual fields
    try expect(std.mem.eql(u8, fixed_signed_block.signature[0..], deserialized_fixed_block.signature[0..]));
    try expect(fixed_signed_block.message.slot == deserialized_fixed_block.message.slot);
    try expect(fixed_signed_block.message.proposer_index == deserialized_fixed_block.message.proposer_index);
    try expect(std.mem.eql(u8, fixed_signed_block.message.parent_root[0..], deserialized_fixed_block.message.parent_root[0..]));
    try expect(std.mem.eql(u8, fixed_signed_block.message.state_root[0..], deserialized_fixed_block.message.state_root[0..]));
    try expect(fixed_signed_block.message.body.slot == deserialized_fixed_block.message.body.slot);
    try expect(std.mem.eql(u8, fixed_signed_block.message.body.data[0..], deserialized_fixed_block.message.body.data[0..]));

    // 2.1 test for nested variable structures
    const VarBlockBody = struct {
        slot: u64,
        data: []u8,
    };
    const VarBlock = struct {
        slot: u64,
        proposer_index: u64,
        parent_root: Bytes32,
        state_root: Bytes32,
        body: VarBlockBody,
    };
    const VarSignedBlock = struct {
        message: VarBlock,
        signature: [48]u8,
    };
    isFixedSizeType = try isFixedSizeObject(VarSignedBlock);
    try expect(isFixedSizeType == false);

    var varData = [_]u8{ 1, 2, 3, 4 };
    const var_signed_block = VarSignedBlock{
        .message = .{
            .slot = 9,
            .proposer_index = 3,
            .parent_root = [_]u8{ 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60 },
            .state_root = [_]u8{ 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231 },
            .body = .{ .slot = 9, .data = &varData },
        },
        .signature = [_]u8{2} ** 48,
    };

    var serialized_var_block = std.ArrayList(u8).init(std.testing.allocator);
    defer serialized_var_block.deinit();
    try serialize(VarSignedBlock, var_signed_block, &serialized_var_block);
    // 2.2 verified on an equivalent nodejs container implementation
    const expected_serialized_var_block = [_]u8{ 52, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 199, 128, 9, 253, 240, 127, 197, 106, 17, 241, 34, 55, 6, 88, 163, 83, 170, 165, 66, 237, 99, 228, 76, 75, 193, 95, 244, 205, 16, 90, 179, 60, 81, 12, 244, 147, 45, 160, 28, 192, 208, 78, 159, 151, 165, 43, 244, 44, 103, 197, 231, 128, 122, 15, 182, 90, 109, 10, 229, 68, 229, 60, 50, 231, 84, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 1, 2, 3, 4 };
    try expect(std.mem.eql(u8, serialized_var_block.items, expected_serialized_var_block[0..]));

    var deserialized_var_block: VarSignedBlock = undefined;
    try deserialize(VarSignedBlock, serialized_var_block.items[0..], &deserialized_var_block, std.testing.allocator);
    // how should the things to be de-inited accumulated?
    defer std.testing.allocator.free(deserialized_var_block.message.body.data);

    // 2.3 match the individual fields
    try expect(std.mem.eql(u8, var_signed_block.signature[0..], deserialized_var_block.signature[0..]));
    try expect(var_signed_block.message.slot == deserialized_var_block.message.slot);
    try expect(var_signed_block.message.proposer_index == deserialized_var_block.message.proposer_index);
    try expect(std.mem.eql(u8, var_signed_block.message.parent_root[0..], deserialized_var_block.message.parent_root[0..]));
    try expect(std.mem.eql(u8, var_signed_block.message.state_root[0..], deserialized_var_block.message.state_root[0..]));
    try expect(var_signed_block.message.body.slot == deserialized_var_block.message.body.slot);
    try expect(std.mem.eql(u8, var_signed_block.message.body.data[0..], deserialized_var_block.message.body.data[0..]));
}
