const std = @import("std");

const base_64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

const KeyScore = struct {
    key: u8,
    score: f32,
};

pub fn process_file_xor_single_byte() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var file = try std.fs.cwd().openFile("4.txt", .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var reader = buf_reader.reader();

    var buf: [1024]u8 = undefined;
    var best_key_in_general: KeyScore = KeyScore{ .key = 0, .score = 1000000 };
    var best_line: []u8 = undefined;

    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        const best_key = try min_score_single_byte_xor(allocator, line);

        if (best_key.score < best_key_in_general.score) {
            best_key_in_general = best_key;
            var line_copy = try allocator.alloc(u8, line.len);
            std.mem.copy(u8, line_copy, line);
            best_line = line_copy;
        }
    }

    const line_bytes = try hex_string_to_bytes(allocator, best_line);
    const decoded = try xor_byte(allocator, line_bytes, best_key_in_general.key);
    try print(decoded);
}

pub fn print(encoded_string: []const u8) !void {
    const out = std.io.getStdOut();
    var writer = out.writer();
    for (encoded_string) |byte_val| {
        try writer.print("{c}", .{byte_val});
    }
    try writer.print("\n", .{});
}

pub fn main() anyerror!void {
    // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer arena.deinit();
    // const allocator = arena.allocator();

    try process_file_xor_single_byte();
}

pub fn min_score_single_byte_xor(allocator: std.mem.Allocator, encoded_string: []const u8) !KeyScore {
    const encoded_bytes = try hex_string_to_bytes(allocator, encoded_string);

    var key: u8 = 0;
    var min_score: f32 = 1000000;
    var best_key: u8 = 0;

    while (key < 0xFF) {
        const plaintext = try xor_byte(allocator, encoded_bytes, key);
        const score = score_as_english(plaintext);
        if (score < min_score) {
            min_score = score;
            best_key = key;
        }
        key += 1;
    }

    return KeyScore{ .key = best_key, .score = min_score };
}

pub fn score_as_english(bytes: []const u8) f32 {
    var total: u32 = 0;

    for (bytes) |char| {
        var score: u8 = switch (char) {
            'e',
            'E',
            't',
            'T',
            'a',
            'A',
            'o',
            'O',
            => 2,
            'i', 'I', 'n', 'N', 's', 'S', 'h', 'H' => 1,
            else => 0,
        };
        total += score;
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

pub fn xor_byte(allocator: std.mem.Allocator, src: []u8, key: u8) ![]u8 {
    const out_buffer = try allocator.alloc(u8, src.len);

    var index: u8 = 0;
    while (index < src.len) {
        out_buffer[index] = src[index] ^ key;
        index += 1;
    }
    return out_buffer;
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

    const encoded_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    const result = try min_score_single_byte_xor(allocator, encoded_string);

    try std.testing.expectEqual(result.key, 88);
}

test "Winning Line From Challenge 4" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const input = "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f";

    const result = try min_score_single_byte_xor(allocator, input);

    try std.testing.expectEqual(result.key, 21);
}
