const std = @import("std");

const base_64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

const ScoredSingleByteKey = struct {
    key: u8,
    score: f32,
};

const ScoredMultiByteKey = struct {
    key: []u8,
    score: f32,
};

const BinaryData = struct {
    bytes: []u8 = undefined,
    _bytes: []const u8 = undefined,
    allocator: std.mem.Allocator,

    fn apply_single_byte_key(self: *const BinaryData, key: u8) void {
        for (self.bytes) |byte_val, i| {
            self.bytes[i] = byte_val ^ key;
        }
    }
    fn apply_repeating_byte_key(self: *const BinaryData, key: []const u8) void {
        for (self.bytes) |byte_val, i| {
            self.bytes[i] = byte_val ^ key[i % key.len];
        }
    }
    fn reset_bytes(self: *const BinaryData) void {
        for (self._bytes) |byte_val, i| {
            self.bytes[i] = byte_val;
        }
    }
    fn from_bytes(allocator: std.mem.Allocator, bytes: []const u8) !BinaryData {
        const bytes_var = try allocator.alloc(u8, bytes.len);
        std.mem.copy(u8, bytes_var, bytes);
        const bytes_const = try allocator.alloc(u8, bytes.len);
        std.mem.copy(u8, bytes_const, bytes);
        const result = BinaryData{ .bytes = bytes_var, ._bytes = bytes_const, .allocator = allocator };
        return result;
    }

    fn from_byte_arrays(allocator: std.mem.Allocator, arrays: std.ArrayList([]u8)) !BinaryData {
        var data_size: u32 = 0;
        for (arrays.items) |item| {
            data_size += @intCast(u32, item.len);
        }

        var bytes = try allocator.alloc(u8, data_size);
        var idx: usize = 0;
        for (arrays.items) |item| {
            std.mem.copy(u8, bytes[idx..], item);
            idx += item.len;
        }
        return BinaryData.from_bytes(allocator, bytes);
    }

    fn decode_from_base_64(self: *const BinaryData) !BinaryData {
        const bytes = try base_64_to_octets(self.allocator, self.bytes);
        return BinaryData.from_bytes(self.allocator, bytes);
    }
    fn decode_from_hex(self: *const BinaryData) !BinaryData {
        const bytes = try hex_string_to_bytes(self.allocator, self.bytes);
        return BinaryData.from_bytes(self.allocator, bytes);
    }

    fn print_hex(self: *const BinaryData) !void {
        const out = std.io.getStdOut();

        var writer = out.writer();

        for (self.bytes) |byte_val| {
            try writer.print("{x}", .{byte_val});
        }
        try writer.print("\n", .{});
    }

    fn print_ascii(self: *const BinaryData) !void {
        const out = std.io.getStdOut();

        var writer = out.writer();

        for (self.bytes) |byte_val| {
            try writer.print("{c}", .{byte_val});
        }
        try writer.print("\n", .{});
    }
};

pub fn load_file(allocator: std.mem.Allocator, path: []const u8) !std.ArrayList([]u8) {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var reader = buf_reader.reader();
    var buf: [1024]u8 = undefined;
    var list = std.ArrayList([]u8).init(allocator);

    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        const line_copy = try allocator.alloc(u8, line.len);
        std.mem.copy(u8, line_copy, line);
        try list.append(line_copy);
    }
    return list;
}

pub fn hex_string_to_bytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    var out_length: usize = @divFloor(hex_str.len, 2);

    if (hex_str.len % 2 != 0) {
        out_length += 1;
    }
    const out_buffer = try allocator.alloc(u8, out_length);

    var char_val: u8 = 0;
    var pos: u8 = 0;
    var buffer: u8 = 0;
    var out_pos: u8 = 0;

    for (hex_str) |char| {
        if (char <= '9' and char >= '0') {
            char_val = char - '0';
        } else if (char <= 'Z' and char >= 'A') {
            char_val = 10 + (char - 'A');
        } else if (char <= 'z' and char >= 'a') {
            char_val = 10 + (char - 'a');
        }

        if (pos == 0) {
            buffer = char_val << 4;
        } else if (pos == 1) {
            buffer = buffer | (char_val & 15);
            out_buffer[out_pos] = buffer;
            out_pos += 1;
        }

        pos = (pos + 1) % 2;
    }
    if (pos != 0) {
        std.log.debug("odd number of digits in hex string, left padding final digit with 0", .{});
        buffer = buffer >> 4;
        out_buffer[out_pos] = buffer;
    }
    return out_buffer;
}

pub fn octets_to_sextets(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var out_length: usize = @divFloor(bytes.len, 3);

    if (bytes.len % 3 != 0) {
        out_length += 1;
    }
    out_length *= 4;

    const out_buffer = try allocator.alloc(u8, out_length);

    var pos: u8 = 0;
    var buffer: u8 = 0;
    const rshifts = [_]u3{ 2, 4, 6 };
    const lshifts = [_]u3{ 4, 2, 0 };
    const masks = [_]u8{ 3, 15, 63 };
    var sextet_val: u8 = 0;
    var out_pos: usize = 0;

    for (bytes) |byte_val| {
        sextet_val = (buffer | (byte_val >> rshifts[pos]));
        buffer = (byte_val & masks[pos]) << lshifts[pos];
        out_buffer[out_pos] = sextet_val;

        if (pos == 2) {
            out_pos += 1;
            out_buffer[out_pos] = buffer;
            buffer = 0;
        }

        out_pos += 1;

        pos = (pos + 1) % 3;
    }

    if (pos != 0 and bytes.len != 0) {
        out_buffer[out_pos] = buffer;
        out_pos += 1;
    }

    while (pos != 0 and pos < 3) {
        out_buffer[out_pos] = 64;
        out_pos += 1;
        pos += 1;
    }
    return out_buffer;
}

pub fn base_64_to_sextets(allocator: std.mem.Allocator, base_64_string: []const u8) ![]u8 {
    var base_64_alphabet_inverse = std.AutoHashMap(u8, u8).init(allocator);
    for (base_64_alphabet) |char, i| {
        try base_64_alphabet_inverse.put(char, @intCast(u8, i));
    }
    const sextets = try allocator.alloc(u8, base_64_string.len);

    for (base_64_string) |char, i| {
        sextets[i] = base_64_alphabet_inverse.get(char).?;
    }
    return sextets;
}

pub fn base_64_to_octets(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out_length: usize = @divFloor(input.len, 4);

    out_length *= 3;

    var padding: u8 = 0;
    var rear_index: usize = input.len - 3;
    while (rear_index < input.len) : (rear_index += 1) {
        if (input[rear_index] == '=') {
            padding += 1;
        }
    }
    out_length -= padding;

    const octets = try allocator.alloc(u8, out_length);

    const sextets = try base_64_to_sextets(allocator, input);

    var pos: u8 = 0;
    var buffer: u8 = 0;
    const take_masks = [_]u8{ 0x3F, 0x30, 0x3C, 0x3F };
    const lshifts = [_]u3{ 2, 4, 6, 0 };
    const rshifts = [_]u3{ 0, 4, 2, 0 };
    const save_masks = [_]u8{ 0x0, 0x0F, 0x03, 0x0 };
    var octet_val: u8 = 0;
    var out_pos: usize = 0;

    for (sextets) |sextet_val| {
        if (pos == 0) {
            buffer = (sextet_val & take_masks[pos]) << lshifts[pos];
        } else {
            octet_val = buffer | ((sextet_val & take_masks[pos]) >> rshifts[pos]);
            buffer = (sextet_val & save_masks[pos]) << lshifts[pos];

            if (out_pos < octets.len) {
                octets[out_pos] = octet_val;
                out_pos += 1;
            }
        }

        pos = ((pos + 1) % 4);
    }

    return octets;
}

pub fn main() anyerror!void {
    std.log.info("Nothing to do!", .{});
}

pub fn search_list_for_xor_single_byte(allocator: std.mem.Allocator, list: std.ArrayList([]u8)) !BinaryData {
    var best_key_in_general: ScoredSingleByteKey = ScoredSingleByteKey{ .key = 0, .score = 1e5 };
    var best_item: BinaryData = undefined;

    for (list.items) |item| {
        const raw_data = try BinaryData.from_bytes(allocator, item);
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

pub fn hamming_distance(a: []const u8, b: []const u8) !u32 {
    if (a.len != b.len) {
        return error.LengthError;
    }
    var index: u8 = 0;
    var total: u32 = 0;

    while (index < a.len) {
        total += @popCount(u8, a[index] ^ b[index]);
        index += 1;
    }
    return total;
}

pub fn key_search_multi_byte_xor(allocator: std.mem.Allocator, data: BinaryData) !ScoredMultiByteKey {
    const keysizes = try guess_keysizes(allocator, data);

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
            const chunked_data = try BinaryData.from_bytes(allocator, transposed_chunks[idx]);
            const scored_key: ScoredSingleByteKey = key_search_single_byte_xor(chunked_data);
            key[idx] = scored_key.key;
        }

        data.apply_repeating_byte_key(key);
        const score: f32 = score_as_english(data.bytes);
        data.reset_bytes();

        if (score < best_key.score) {
            best_key = ScoredMultiByteKey{ .key = key, .score = score };
        }
    }
    return best_key;
}

pub fn guess_keysizes(allocator: std.mem.Allocator, data: BinaryData) ![]u8 {
    const num_guesses: usize = 5;
    var guess_scores = [_]f32{1e5} ** num_guesses;
    var guesses: []u8 = try allocator.alloc(u8, num_guesses);

    const max_guess: u8 = 40;
    var keysize: u8 = 2;
    const iters: u8 = 6;
    var total_dist: f32 = undefined;

    while (keysize < max_guess) : (keysize += 1) {
        var it: u8 = 0;
        var start_a: u32 = 0;
        var end_a: u32 = keysize;
        var start_b: u32 = keysize;
        var end_b: u32 = keysize + keysize;

        while (it < iters) : (it += 1) {
            const dist = try hamming_distance(data.bytes[start_a..end_a], data.bytes[start_b..end_b]);
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

pub fn key_search_single_byte_xor(data: BinaryData) ScoredSingleByteKey {
    var key: u8 = 0;
    var min_score: f32 = 1000000;
    var best_key: u8 = 0;

    while (key < 0xFF) {
        data.apply_single_byte_key(key);

        const score = score_as_english(data.bytes);
        if (score < min_score) {
            min_score = score;
            best_key = key;
        }
        key += 1;
        data.reset_bytes();
    }

    return ScoredSingleByteKey{ .key = best_key, .score = min_score };
}

pub fn score_as_english(bytes: []const u8) f32 {
    var total: i32 = 0;

    for (bytes) |char| {
        var score: i8 = switch (char) {
            'e', 'E', 't', 'T', 'a', 'A', 'o', 'O' => 2,
            'i', 'I', 'n', 'N', ' ', 's', 'S', 'h', 'H', 'r', 'R', 'd', 'D', 'l', 'L', 'u', 'U' => 1,
            else => -1,
        };
        total += score;
    }
    if (total < 0) {
        total = 0;
    }
    return 1 / @intToFloat(f32, total);
}

pub fn xor_bytes(src: []const u8, dst: []u8) !void {
    if (src.len != dst.len) {
        return error.LengthError;
    }
    var index: u8 = 0;
    while (index < src.len) {
        dst[index] = dst[index] ^ src[index];
        index += 1;
    }
}

test "Hamming Distance" {
    const a = "this is a test";
    const b = "wokka wokka!!!";

    try std.testing.expectEqual(hamming_distance(a[0..], b[0..]), 37);
}
test "Sextets to Octets 3" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const input = "TWFu";
    const expected = [_]u8{ 0x4d, 0x61, 0x6e };

    const result = try base_64_to_octets(allocator, input);

    try std.testing.expectEqualSlices(u8, expected[0..], result[0..]);
}
test "Sextets to Octets 2" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "TWE=";
    const expected = [_]u8{ 0x4d, 0x61 };

    const result = try base_64_to_octets(allocator, input);

    try std.testing.expectEqualSlices(u8, expected[0..], result[0..]);
}
test "Sextets to Octets 1" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const input = "TQ==";
    const expected = [_]u8{0x4d};

    const result = try base_64_to_octets(allocator, input);

    try std.testing.expectEqualSlices(u8, expected[0..], result[0..]);
}

test "Base64 to Sextets" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const input = "ABC/=";

    const expected = [_]u8{ 0, 1, 2, 63, 64 };

    const sextets = try base_64_to_sextets(allocator, input);

    for (sextets) |sextet_val, i| {
        try std.testing.expectEqual(expected[i], sextet_val);
    }
}

test "Cryptopals Test" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Test No Pad" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d616e";
    const expected = "TWFu";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Test One Pad" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d61";
    const expected = "TWE=";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}
test "Wikipedia Test Two Pad" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d";
    const expected = "TQ==";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Test Repeat" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d616e4d616e";
    const expected = "TWFuTWFu";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Wikipedia Test Partial Repeat" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d616e4d";
    const expected = "TWFuTQ==";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "Odd Input Length Hex" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "4d6";
    const expected = "TQY=";

    const bytes = try hex_string_to_bytes(allocator, input[0..]);

    const sextets = try octets_to_sextets(allocator, bytes);

    try std.testing.expectEqual(expected.len, sextets.len);
    for (sextets) |sextet, i| {
        try std.testing.expectEqual(base_64_alphabet[sextet], expected[i]);
    }
}

test "XOR Cryptopals" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const challenge_2_input_1 = "1c0111001f010100061a024b53535009181c";
    const challenge_2_input_2 = "686974207468652062756c6c277320657965";

    const expected_xor_string = "746865206b696420646f6e277420706c6179";

    const decoded_1 = try hex_string_to_bytes(allocator, challenge_2_input_1[0..]);
    const decoded_2 = try hex_string_to_bytes(allocator, challenge_2_input_2[0..]);

    const decoded_expected = try hex_string_to_bytes(allocator, expected_xor_string[0..]);

    try xor_bytes(decoded_1, decoded_2);

    for (decoded_2) |decoded_val, i| {
        try std.testing.expectEqual(decoded_val, decoded_expected[i]);
    }
}

test "Single Byte XOR Cryptopals" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    const raw_data = try BinaryData.from_bytes(allocator, input);

    const data = try raw_data.decode_from_hex();

    const result = key_search_single_byte_xor(data);

    try std.testing.expectEqual(result.key, 88);
}

test "Winning Line From Challenge 4" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f";

    const raw_data = try BinaryData.from_bytes(allocator, input);

    const data = try raw_data.decode_from_hex();

    const result = key_search_single_byte_xor(data);

    try std.testing.expectEqual(result.key, 53);
}

test "Challenge 4 Search File" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const list = try load_file(allocator, "4.txt");

    const winning_line_plaintext = try search_list_for_xor_single_byte(allocator, list);

    const expected = "Now that the party is jumping\n";

    try std.testing.expectEqualSlices(u8, expected[0..], winning_line_plaintext.bytes);
}

test "Challenge 6 Decrypt File" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw_data_split = try load_file(allocator, "6.txt");

    const raw_data = try BinaryData.from_byte_arrays(allocator, raw_data_split);

    const data = try raw_data.decode_from_base_64();

    const scored_key = try key_search_multi_byte_xor(allocator, data);

    const expected = "Terminator X: Bring the noise";

    try std.testing.expectEqualSlices(u8, expected[0..], scored_key.key);
}
