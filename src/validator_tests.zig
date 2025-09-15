const libssz = @import("lib.zig");
const utils = libssz.utils;
const serialize = libssz.serialize;
const deserialize = libssz.deserialize;
const hashTreeRoot = libssz.hashTreeRoot;
const std = @import("std");
const ArrayList = std.ArrayList;
const expect = std.testing.expect;

// Beacon chain Validator struct for compatibility testing
const Validator = struct {
    pubkey: [48]u8,
    withdrawal_credentials: [32]u8,
    effective_balance: u64,
    slashed: bool,
    activation_eligibility_epoch: u64,
    activation_epoch: u64,
    exit_epoch: u64,
    withdrawable_epoch: u64,
};

test "Validator struct serialization" {
    const validator = Validator{
        .pubkey = [_]u8{0xAA} ** 48,
        .withdrawal_credentials = [_]u8{0xBB} ** 32,
        .effective_balance = 32000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 18446744073709551615, // Max u64
        .withdrawable_epoch = 18446744073709551615, // Max u64
    };

    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(Validator, validator, &list);

    // Verify expected size: 48 + 32 + 8 + 1 + 8 + 8 + 8 + 8 = 121 bytes
    try expect(list.items.len == 121);

    // Test round-trip serialization
    var deserialized: Validator = undefined;
    try deserialize(Validator, list.items, &deserialized, null);

    try expect(std.mem.eql(u8, &validator.pubkey, &deserialized.pubkey));
    try expect(std.mem.eql(u8, &validator.withdrawal_credentials, &deserialized.withdrawal_credentials));
    try expect(validator.effective_balance == deserialized.effective_balance);
    try expect(validator.slashed == deserialized.slashed);
    try expect(validator.activation_eligibility_epoch == deserialized.activation_eligibility_epoch);
    try expect(validator.activation_epoch == deserialized.activation_epoch);
    try expect(validator.exit_epoch == deserialized.exit_epoch);
    try expect(validator.withdrawable_epoch == deserialized.withdrawable_epoch);
}

test "Validator struct hash tree root" {
    const validator = Validator{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x02} ** 32,
        .effective_balance = 32000000000,
        .slashed = true,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 2,
        .exit_epoch = 100,
        .withdrawable_epoch = 200,
    };

    var hash: [32]u8 = undefined;
    try hashTreeRoot(Validator, validator, &hash, std.testing.allocator);

    // Hash should be deterministic for the same validator
    var hash2: [32]u8 = undefined;
    try hashTreeRoot(Validator, validator, &hash2, std.testing.allocator);
    try expect(std.mem.eql(u8, &hash, &hash2));

    // Different validator should produce different hash
    const validator2 = Validator{
        .pubkey = [_]u8{0xFF} ** 48,
        .withdrawal_credentials = [_]u8{0x02} ** 32,
        .effective_balance = 32000000000,
        .slashed = true,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 2,
        .exit_epoch = 100,
        .withdrawable_epoch = 200,
    };

    var hash3: [32]u8 = undefined;
    try hashTreeRoot(Validator, validator2, &hash3, std.testing.allocator);
    try expect(!std.mem.eql(u8, &hash, &hash3));
}

test "List[Validator] serialization and hash tree root" {
    const MAX_VALIDATORS = 100;
    const ValidatorList = utils.List(Validator, MAX_VALIDATORS);

    var validator_list = try ValidatorList.init(0);

    // Add test validators
    const validator1 = Validator{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x11} ** 32,
        .effective_balance = 32000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 18446744073709551615,
        .withdrawable_epoch = 18446744073709551615,
    };

    const validator2 = Validator{
        .pubkey = [_]u8{0x02} ** 48,
        .withdrawal_credentials = [_]u8{0x22} ** 32,
        .effective_balance = 31000000000,
        .slashed = false,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 1,
        .exit_epoch = 18446744073709551615,
        .withdrawable_epoch = 18446744073709551615,
    };

    try validator_list.append(validator1);
    try validator_list.append(validator2);

    // Test serialization
    var list = ArrayList(u8).init(std.testing.allocator);
    defer list.deinit();
    try serialize(ValidatorList, validator_list, &list);

    // Validate against expected bytes
    const expected_validator_list_bytes = [_]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x40, 0x59, 0x73, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x76, 0xBE, 0x37, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try expect(std.mem.eql(u8, list.items, &expected_validator_list_bytes));

    // Test deserialization
    var deserialized_list = try ValidatorList.init(0);
    try deserialize(ValidatorList, list.items, &deserialized_list, null);

    try expect(validator_list.len() == deserialized_list.len());
    try expect(validator_list.len() == 2);

    // Verify each validator was deserialized correctly
    for (0..validator_list.len()) |i| {
        const orig = validator_list.get(i);
        const deser = deserialized_list.get(i);

        try expect(std.mem.eql(u8, &orig.pubkey, &deser.pubkey));
        try expect(std.mem.eql(u8, &orig.withdrawal_credentials, &deser.withdrawal_credentials));
        try expect(orig.effective_balance == deser.effective_balance);
        try expect(orig.slashed == deser.slashed);
        try expect(orig.activation_eligibility_epoch == deser.activation_eligibility_epoch);
        try expect(orig.activation_epoch == deser.activation_epoch);
        try expect(orig.exit_epoch == deser.exit_epoch);
        try expect(orig.withdrawable_epoch == deser.withdrawable_epoch);
    }

    // Test hash tree root
    var hash1: [32]u8 = undefined;
    try hashTreeRoot(ValidatorList, validator_list, &hash1, std.testing.allocator);

    // Validate against expected hash
    const expected_validator_list_hash = [_]u8{ 0x54, 0x80, 0xF8, 0x35, 0xD7, 0x52, 0xF7, 0x27, 0xC8, 0xF1, 0xE9, 0xCC, 0x0F, 0x84, 0x2B, 0x25, 0x76, 0xA5, 0x1A, 0xD2, 0xB7, 0xB5, 0x10, 0xF1, 0xA5, 0x39, 0xF7, 0xD8, 0xD0, 0x87, 0xC3, 0xC2 };
    try expect(std.mem.eql(u8, &hash1, &expected_validator_list_hash));

    var hash2: [32]u8 = undefined;
    try hashTreeRoot(ValidatorList, deserialized_list, &hash2, std.testing.allocator);

    // Hash should be the same for original and deserialized lists
    try expect(std.mem.eql(u8, &hash1, &hash2));
}

// BeamBlockBody types for testing
const MAX_VALIDATORS_IN_BLOCK = 50;
const ValidatorArray = utils.List(Validator, MAX_VALIDATORS_IN_BLOCK);
const BeamBlockBody = struct {
    validators: ValidatorArray,
};

test "BeamBlockBody with validator array - full cycle" {
    // Create test validators
    const validator1 = Validator{
        .pubkey = [_]u8{0x01} ** 48,
        .withdrawal_credentials = [_]u8{0x11} ** 32,
        .effective_balance = 32000000000,
        .slashed = false,
        .activation_eligibility_epoch = 0,
        .activation_epoch = 0,
        .exit_epoch = 18446744073709551615,
        .withdrawable_epoch = 18446744073709551615,
    };

    const validator2 = Validator{
        .pubkey = [_]u8{0x02} ** 48,
        .withdrawal_credentials = [_]u8{0x22} ** 32,
        .effective_balance = 31000000000,
        .slashed = true,
        .activation_eligibility_epoch = 1,
        .activation_epoch = 2,
        .exit_epoch = 100,
        .withdrawable_epoch = 200,
    };

    // Create validator array
    var validators = try ValidatorArray.init(0);
    try validators.append(validator1);
    try validators.append(validator2);

    // Create BeamBlockBody
    const beam_block_body = BeamBlockBody{
        .validators = validators,
    };

    // Test serialization
    var serialized_data = ArrayList(u8).init(std.testing.allocator);
    defer serialized_data.deinit();
    try serialize(BeamBlockBody, beam_block_body, &serialized_data);

    // Validate against expected bytes
    const expected_beam_block_body_bytes = [_]u8{ 0x04, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x00, 0x40, 0x59, 0x73, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x00, 0x76, 0xBE, 0x37, 0x07, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try expect(std.mem.eql(u8, serialized_data.items, &expected_beam_block_body_bytes));

    // Test deserialization
    var deserialized_body: BeamBlockBody = undefined;
    deserialized_body.validators = try ValidatorArray.init(0);
    try deserialize(BeamBlockBody, serialized_data.items, &deserialized_body, null);

    // Verify deserialization correctness
    try expect(beam_block_body.validators.len() == deserialized_body.validators.len());
    try expect(beam_block_body.validators.len() == 2);

    for (0..beam_block_body.validators.len()) |i| {
        const orig = beam_block_body.validators.get(i);
        const deser = deserialized_body.validators.get(i);

        try expect(std.mem.eql(u8, &orig.pubkey, &deser.pubkey));
        try expect(std.mem.eql(u8, &orig.withdrawal_credentials, &deser.withdrawal_credentials));
        try expect(orig.effective_balance == deser.effective_balance);
        try expect(orig.slashed == deser.slashed);
        try expect(orig.activation_eligibility_epoch == deser.activation_eligibility_epoch);
        try expect(orig.activation_epoch == deser.activation_epoch);
        try expect(orig.exit_epoch == deser.exit_epoch);
        try expect(orig.withdrawable_epoch == deser.withdrawable_epoch);
    }

    // Test hash tree root consistency
    var hash_original: [32]u8 = undefined;
    try hashTreeRoot(BeamBlockBody, beam_block_body, &hash_original, std.testing.allocator);

    // Validate against expected hash
    const expected_beam_block_body_hash = [_]u8{ 0x34, 0xF2, 0xBC, 0x58, 0xA0, 0xBF, 0x20, 0x72, 0x43, 0xF8, 0xC2, 0x5E, 0x0F, 0x83, 0x5E, 0x36, 0x90, 0x73, 0xD5, 0xAC, 0x97, 0x1E, 0x9A, 0x53, 0x71, 0x14, 0xA0, 0xFD, 0x1C, 0xC8, 0xD8, 0xE4 };
    try expect(std.mem.eql(u8, &hash_original, &expected_beam_block_body_hash));

    var hash_deserialized: [32]u8 = undefined;
    try hashTreeRoot(BeamBlockBody, deserialized_body, &hash_deserialized, std.testing.allocator);

    // Hashes should be identical for original and deserialized data
    try expect(std.mem.eql(u8, &hash_original, &hash_deserialized));

    // Test hash determinism
    var hash_duplicate: [32]u8 = undefined;
    try hashTreeRoot(BeamBlockBody, beam_block_body, &hash_duplicate, std.testing.allocator);
    try expect(std.mem.eql(u8, &hash_original, &hash_duplicate));
}
