// List of root hashes of zero-subtrees, up to depth 255.
const std = @import("std");

pub const hashes_of_zero: [256][32]u8 = calc: {
    @setEvalBranchQuota(10000000);
    var ret: [256][32]u8 = undefined;
    
    var current = [_]u8{0} ** 32;
    
    ret[0] = current;
    
    var i: usize = 1;
    while (i < 256) : (i += 1) {
        // Hash the current level twice (left and right child are the same)
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&current);
        hasher.update(&current);
        current = hasher.finalResult();
        ret[i] = current;
    }
    
    break :calc ret;
};