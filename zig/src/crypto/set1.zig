const std = @import("std");

const utils = @import("utils");

const tinyaes = @cImport({
    @cInclude("aes.h");
});

const ScoredSingleByteKey = struct {
    key: u8,
    score: f32,
};

const ScoredMultiByteKey = struct {
    key: []u8,
    score: f32,
};

pub fn search_list_for_aes_ecb_encryption(allocator: std.mem.Allocator, list: std.ArrayList([]u8)) !std.ArrayList(usize) {
    var result_list = std.ArrayList(usize).init(allocator);

    for (list.items) |item, i| {
        const raw_data = try utils.BinaryData.from_bytes(allocator, item);
        const data = try raw_data.decode_from_hex();

        var idx: u32 = 0;
        const block_size: u8 = 16;

        var match: bool = false;

        while (idx + (block_size * 2) < data.bytes.len) : (idx += block_size) {
            var inner_idx: u32 = idx + block_size;
            while (inner_idx + block_size < data.bytes.len) : (inner_idx += block_size) {
                if (std.mem.eql(u8, data.bytes[idx .. idx + block_size], data.bytes[inner_idx .. inner_idx + block_size])) {
                    match = true;
                }
            }
        }
        if (match) {
            try result_list.append(i);
        }
    }
    return result_list;
}
pub fn search_list_for_xor_single_byte(allocator: std.mem.Allocator, list: std.ArrayList([]u8)) !utils.BinaryData {
    var best_key_in_general: ScoredSingleByteKey = ScoredSingleByteKey{ .key = 0, .score = 1e5 };
    var best_item: utils.BinaryData = undefined;

    for (list.items) |item| {
        const raw_data = try utils.BinaryData.from_bytes(allocator, item);
        const data = try raw_data.decode_from_hex();
        const best_key = key_search_single_byte_xor(data);

        if (best_key.score < best_key_in_general.score) {
            best_key_in_general = best_key;
            best_item = try raw_data.decode_from_hex();
        }
    }
    best_item.apply_single_byte_key(best_key_in_general.key);

    return best_item;
}

pub fn key_search_multi_byte_xor(allocator: std.mem.Allocator, data: utils.BinaryData, max_keysize: u8) !ScoredMultiByteKey {
    const keysizes = try guess_keysizes(allocator, data, max_keysize);

    var default_key: [2]u8 = [2]u8{ 0, 0 };
    var best_key = ScoredMultiByteKey{ .key = &default_key, .score = 1e5 };

    var idx: usize = 0;

    for (keysizes) |keysize| {
        idx = 0;
        const transposed_size: usize = @divFloor(data.bytes.len, keysize) + 1;
        var transposed_chunks: [][]u8 = try allocator.alloc([]u8, keysize);

        while (idx < keysize) : (idx += 1) {
            transposed_chunks[idx] = try allocator.alloc(u8, transposed_size);
        }

        idx = 0;

        while (idx < data.bytes.len) : (idx += 1) {
            transposed_chunks[idx % keysize][@divFloor(idx, keysize)] = data.bytes[idx];
        }

        var key: []u8 = try allocator.alloc(u8, keysize);

        idx = 0;

        while (idx < keysize) : (idx += 1) {
            const chunked_data = try utils.BinaryData.from_bytes(allocator, transposed_chunks[idx]);
            const scored_key: ScoredSingleByteKey = key_search_single_byte_xor(chunked_data);
            key[idx] = scored_key.key;
        }

        data.apply_repeating_byte_key(key);
        const score: f32 = utils.score_as_english(data.bytes);
        data.reset_bytes();

        if (score < best_key.score) {
            best_key = ScoredMultiByteKey{ .key = key, .score = score };
        }
    }
    return best_key;
}

pub fn guess_keysizes(allocator: std.mem.Allocator, data: utils.BinaryData, max_guess: u8) ![]u8 {
    const iters: usize = @minimum(@divFloor(data.bytes.len, (2 * max_guess)), 4);
    var guess_scores = try allocator.alloc(f32, iters);
    for (guess_scores) |*score| {
        score.* = 1e5;
    }
    var guesses: []u8 = try allocator.alloc(u8, iters);
    var keysize: u8 = 2;
    var total_dist: f32 = undefined;

    while (keysize < max_guess) : (keysize += 1) {
        var it: u8 = 0;
        var start_a: u32 = 0;
        var end_a: u32 = keysize;
        var start_b: u32 = keysize;
        var end_b: u32 = keysize + keysize;

        while (it < iters) : (it += 1) {
            const dist = try utils.hamming_distance(data.bytes[start_a..end_a], data.bytes[start_b..end_b]);
            start_a += keysize;
            end_a += keysize;
            start_b += keysize;
            end_b += keysize;
            total_dist += @intToFloat(f32, dist) / @intToFloat(f32, keysize);
        }
        var score: f32 = total_dist / @intToFloat(f32, iters);
        total_dist = 0;

        // in lieu of a proper min heap
        var guess: u8 = keysize;
        var idx: u8 = 0;
        while (idx < guesses.len) : (idx += 1) {
            if (score < guess_scores[idx]) {
                var tmp_score: f32 = guess_scores[idx];
                var tmp_guess: u8 = guesses[idx];
                guess_scores[idx] = score;
                guesses[idx] = guess;
                score = tmp_score;
                guess = tmp_guess;
            }
        }
    }

    return guesses;
}

pub fn key_search_single_byte_xor(data: utils.BinaryData) ScoredSingleByteKey {
    var key: u8 = 0;
    var min_score: f32 = 1000000;
    var best_key: u8 = 0;

    while (key < 0xFF) {
        data.apply_single_byte_key(key);

        const score = utils.score_as_english(data.bytes);
        if (score < min_score) {
            min_score = score;
            best_key = key;
        }
        key += 1;
        data.reset_bytes();
    }

    return ScoredSingleByteKey{ .key = best_key, .score = min_score };
}

test "Single Byte XOR Cryptopals" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    const raw_data = try utils.BinaryData.from_bytes(allocator, input);

    const data = try raw_data.decode_from_hex();

    const result = key_search_single_byte_xor(data);

    try std.testing.expectEqual(result.key, 88);
}

test "Winning Line From Challenge 4" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f";

    const raw_data = try utils.BinaryData.from_bytes(allocator, input);

    const data = try raw_data.decode_from_hex();

    const result = key_search_single_byte_xor(data);

    try std.testing.expectEqual(result.key, 53);
}

test "Challenge 4 Search File" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const list = try utils.load_file(allocator, "data/4.txt");

    const winning_line_plaintext = try search_list_for_xor_single_byte(allocator, list);

    const expected = "Now that the party is jumping\n";

    try std.testing.expectEqualSlices(u8, expected[0..], winning_line_plaintext.bytes);
}

test "Challenge 6 Decrypt File" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw_data_split = try utils.load_file(allocator, "data/6.txt");

    const raw_data = try utils.BinaryData.from_byte_arrays(allocator, raw_data_split);

    const data = try raw_data.decode_from_base_64();

    const scored_key = try key_search_multi_byte_xor(allocator, data, 40);

    const expected = "Terminator X: Bring the noise";

    try std.testing.expectEqualSlices(u8, expected[0..], scored_key.key);
}

test "Encrypt Decrypt Cycle Short" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "Hello, World! A short string might not work very well.";
    const key = "hi";

    const plaintext_data = try utils.BinaryData.from_bytes(allocator, input);
    plaintext_data.apply_repeating_byte_key(key);
    const data = try utils.BinaryData.from_bytes(allocator, plaintext_data.bytes);

    const scored_key = try key_search_multi_byte_xor(allocator, data, 10);

    try std.testing.expectEqualSlices(u8, key[0..], scored_key.key);
}

test "Encrypt Decrypt Cycle A Little Longer" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "Hello, World! A short string might not work very well. I'll just add some more text here. This test will test when there is more text in the string to encrypt, and also it will add more bytes to the key to discover.";
    const key = "snowballs";

    const plaintext_data = try utils.BinaryData.from_bytes(allocator, input);
    plaintext_data.apply_repeating_byte_key(key);
    const data = try utils.BinaryData.from_bytes(allocator, plaintext_data.bytes);

    const scored_key = try key_search_multi_byte_xor(allocator, data, 10);

    try std.testing.expectEqualSlices(u8, key[0..], scored_key.key);
}

test "Decrypt AES ECB" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const expected =
        \\I'm back and I'm ringin' the bell 
        \\A rockin' on the mike while the fly girls yell 
        \\In ecstasy in the back of me 
        \\Well that's my DJ Deshay cuttin' all them Z's 
        \\Hittin' hard and the girlies goin' crazy 
        \\Vanilla's on the mike, man I'm not lazy.
    ;

    const raw_data_split = try utils.load_file(allocator, "data/7.txt");

    const raw_data = try utils.BinaryData.from_byte_arrays(allocator, raw_data_split);

    const data = try raw_data.decode_from_base_64();

    var ctx = try allocator.create(tinyaes.AES_ctx);

    tinyaes.AES_init_ctx(ctx, "YELLOW SUBMARINE");

    const block_size: u8 = 16;
    var idx: u32 = 0;

    while (idx + block_size <= data.bytes.len) : (idx += block_size) {
        tinyaes.AES_ECB_decrypt(ctx, &data.bytes[idx]);
    }

    try std.testing.expectEqualSlices(u8, data.bytes[0..expected.len], expected[0..]);
}

test "Detect AES ECB" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw_data_split = try utils.load_file(allocator, "data/8.txt");

    const result_list = try search_list_for_aes_ecb_encryption(allocator, raw_data_split);

    try std.testing.expectEqual(@intCast(usize, 1), result_list.items.len);
    try std.testing.expectEqual(result_list.items[0], 132);
}
