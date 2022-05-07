const std = @import("std");

const utils = @import("utils");

const tinyaes = @cImport({
    @cInclude("aes.h");
});

pub fn aes_ecb_enc(data: utils.BinaryData, key: []const u8) !void {
    if (key.len != tinyaes.AES_BLOCKLEN) {
        return error.LengthError;
    }
    var ctx = try data.allocator.create(tinyaes.AES_ctx);
    tinyaes.AES_init_ctx(ctx, &key[0]);

    var idx: u32 = 0;

    while (idx + tinyaes.AES_BLOCKLEN <= data.bytes.len) : (idx += tinyaes.AES_BLOCKLEN) {
        tinyaes.AES_ECB_decrypt(ctx, &data.bytes[idx]);
    }
}

pub fn aes_cbc_enc(data: utils.BinaryData, key: []const u8, iv: []const u8) !void {
    if (data.bytes.len % key.len != 0) {
        return error.LengthError;
    }
    if (key.len != iv.len) {
        return error.LengthError;
    }

    var ctx = try data.allocator.create(tinyaes.AES_ctx);
    tinyaes.AES_init_ctx(ctx, &key[0]);

    try utils.xor_bytes(iv, data.bytes[0..iv.len]);
    tinyaes.AES_ECB_encrypt(ctx, &data.bytes[0]);

    var idx: usize = key.len;
    while (idx < data.bytes.len) : (idx += key.len) {
        try utils.xor_bytes(data.bytes[idx - key.len .. idx], data.bytes[idx .. idx + key.len]);
        tinyaes.AES_ECB_encrypt(ctx, &data.bytes[idx]);
    }
}

pub fn aes_cbc_dec(data: utils.BinaryData, key: []const u8, iv: []const u8) !void {
    if (data.bytes.len % key.len != 0) {
        return error.LengthError;
    }
    if (key.len != iv.len) {
        return error.LengthError;
    }
    var ctx = try data.allocator.create(tinyaes.AES_ctx);
    tinyaes.AES_init_ctx(ctx, &key[0]);

    var idx: usize = data.bytes.len - key.len;
    while (idx >= key.len) : (idx -= key.len) {
        tinyaes.AES_ECB_decrypt(ctx, &data.bytes[idx]);
        try utils.xor_bytes(data.bytes[idx - key.len .. idx], data.bytes[idx .. idx + key.len]);
    }

    tinyaes.AES_ECB_decrypt(ctx, &data.bytes[0]);
    try utils.xor_bytes(iv, data.bytes[0..iv.len]);
}

pub fn detect_ecb(data: utils.BinaryData, block_size: usize) bool {
    var idx: usize = 0;
    var detected_ecb: bool = false;

    while (idx + (block_size * 2) < data.bytes.len) : (idx += block_size) {
        var inner_idx: usize = idx + block_size;
        while (inner_idx + block_size < data.bytes.len) : (inner_idx += block_size) {
            if (std.mem.eql(u8, data.bytes[idx .. idx + block_size], data.bytes[inner_idx .. inner_idx + block_size])) {
                detected_ecb = true;
            }
        }
    }

    return detected_ecb;
}

test "Simple CBC Cycle" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "hello, world! THIS IS A TEST";
    const key = "deadbeefdeadbeef";
    const iv = [_]u8{0} ** 16;
    const data = try utils.BinaryData.from_bytes(allocator, input);
    const padded = try data.to_padded(tinyaes.AES_BLOCKLEN);

    try aes_cbc_enc(padded, key[0..], iv[0..]);

    try aes_cbc_dec(padded, key[0..], iv[0..]);

    try std.testing.expectEqualSlices(u8, padded.bytes[0..input.len], input[0..]);
}

test "CBC IV Cascade" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "hello, world! THIS IS A TEST";
    const key = "deadbeefdeadbeef";
    const iv = [_]u8{0} ** 16;
    const data = try utils.BinaryData.from_bytes(allocator, input);
    const padded = try data.to_padded(key.len);

    try aes_cbc_enc(padded, key[0..], iv[0..]);

    const data_2 = try utils.BinaryData.from_bytes(allocator, input);
    const padded_2 = try data_2.to_padded(key.len);
    const iv_2 = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    try aes_cbc_enc(padded_2, key[0..], iv_2[0..]);

    var idx: usize = 0;
    while (idx < padded.bytes.len) : (idx += 1) {
        try std.testing.expect(padded.bytes[idx] != padded_2.bytes[idx]);
    }
}

test "AES CBC Cryptopals" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const ciphertext_split = try utils.load_file(allocator, "data/10.txt");
    const key = "YELLOW SUBMARINE";
    const expected =
        \\I'm back and I'm ringin' the bell 
        \\A rockin' on the mike while the fly girls yell 
        \\In ecstasy in the back of me 
        \\Well that's my DJ Deshay cuttin' all them Z's 
        \\Hittin' hard and the girlies goin' crazy 
        \\Vanilla's on the mike, man I'm not lazy.
    ;

    const iv = [_]u8{0} ** 16;
    const raw_data = try utils.BinaryData.from_byte_arrays(allocator, ciphertext_split);
    const data = try raw_data.decode_from_base_64();
    try aes_cbc_dec(data, key[0..], iv[0..]);
    try std.testing.expectEqualSlices(u8, data.bytes[0..expected.len], expected[0..]);
}

test "Detect ECB" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var input = [_]u8{'A'} ** 64;
    var seed: u64 = std.math.absCast(std.time.milliTimestamp());

    const RndGen = std.rand.DefaultPrng;
    var rnd = RndGen.init(seed);

    const padding_len_before = 5 + rnd.random().uintAtMost(u8, 5);
    const padding_len_after = 5 + rnd.random().uintAtMost(u8, 5);

    const padded_input = try allocator.alloc(u8, (padding_len_before + padding_len_after + input.len));
    std.mem.copy(u8, padded_input[padding_len_before .. padding_len_before + input.len], &input);
    const raw_data = try utils.BinaryData.from_bytes(allocator, padded_input);

    var key = [_]u8{0} ** 16;
    rnd.random().bytes(&key);

    const ecb_mode: bool = rnd.random().uintAtMost(u8, 255) > 128;
    const padded_data = try raw_data.to_padded(key.len);

    if (ecb_mode) {
        try aes_ecb_enc(padded_data, &key);
    } else {
        try aes_cbc_enc(padded_data, &key, &[_]u8{0} ** 16);
    }

    const detected_ecb = detect_ecb(padded_data, key.len);

    try std.testing.expectEqual(ecb_mode, detected_ecb);
}
